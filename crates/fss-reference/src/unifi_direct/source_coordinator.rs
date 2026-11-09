#![forbid(unsafe_code)]
//! Coordinate session steps with publication of separately returned sources.
//!
//! The caller owns the session guard, task authority and every returned event.
//! This owner starts one attempt per accepted source; a refused or uncertain
//! attempt is never retried without a separate caller decision.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_runtime::execution::TaskCx;

use super::{
    av_bootstrap_driver,
    av_unknown_worker_guard::{self, Advance, Guard, SessionEvent, SourceAdvance},
    av_worker, conversation,
    metered::MeteredClock,
    source_handoff, source_worker, supervisor,
};

/// One bounded session, source transfer, or archival decision.
#[must_use]
pub enum Step {
    /// A session decision which was not a separately returned source.
    Session(SessionEvent),
    /// Source transfer was attempted; any refusal retains the original event.
    SourceOffered(source_handoff::Result),
    /// The accepted source's first or explicitly authorized attempt started.
    SourceStarted,
    /// Attempt admission failed; the source remains held and retry is disarmed.
    SourceStartRefused(av_worker::StartError),
    /// Control and any source completion remain owned by the caller.
    SourceArchive(source_handoff::Drive),
    /// A source remains pending and requires an explicit retry decision.
    SourceRetryRequired,
    /// A source owner needs reconciliation before further media is read.
    SourceFenced,
    /// Source custody was unavailable for inspection.
    SourceUnavailable,
    /// The session owner, task, or clock did not match.
    Context,
    /// Cancellation drained the separate attempt; the A/V guard remains owned.
    Cancelled(Option<source_worker::Completion>),
}

/// One bootstrap, source-transfer, or archive decision.
#[must_use]
pub enum BootstrapStep {
    /// An unrelated bootstrap result is returned intact.
    Driver(av_bootstrap_driver::Step),
    /// A separate bootstrap source was offered; paired audio is retained.
    SourceOffered(source_handoff::BootstrapResult),
    /// A new or explicitly retried source attempt started.
    SourceStarted,
    /// Admission failed; the original source remains held and retry is disarmed.
    SourceStartRefused(av_worker::StartError),
    /// Control result and any source completion remain caller-owned.
    SourceArchive(source_handoff::Drive),
    /// A source remains pending and needs an explicit retry decision.
    SourceRetryRequired,
    /// Source custody requires reconciliation before media may resume.
    SourceFenced,
    /// Source custody could not be inspected.
    SourceUnavailable,
    /// The driver, task, owner, or clock did not match.
    Context,
    /// Cancellation drained the separate attempt; the driver remains owned.
    Cancelled(Option<source_worker::Completion>),
}

/// Explicit retry authorization could not be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryError {
    /// There is no idle pending source, or an attempt is already armed.
    NotPending,
}

/// The observer's decision after accepting a complete event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Continue within the bounded slice.
    Continue,
    /// Yield with the guard and any workers still owned by the caller.
    Yield,
    /// Stop; the caller must drain or retire all owned work.
    Stop,
}

/// Supplies fresh operation identities and accepts complete owned events.
pub trait Observer {
    /// Return an unused operation identity, or stop the slice.
    fn next_operation(&mut self) -> Option<OperationId>;
    /// Accept an event, or return it intact if it cannot be accepted.
    fn observe(&mut self, event: Step) -> Result<Decision, Step>;
}

/// A bounded slice stopped without relinquishing either worker owner.
#[must_use = "retain and account for the returned event and both worker owners"]
pub enum SliceStop {
    /// Invalid wait or step bounds; no work was started.
    Configuration,
    /// The bounded number of steps completed.
    Yielded,
    /// The observer accepted an event and requested a resumable yield.
    ObserverYielded,
    /// The observer accepted an event and requested a stop.
    ObserverStopped,
    /// The observer could not supply another operation identity.
    OperationUnavailable,
    /// An audio observation was withheld and remains in the guard.
    AudioWithheld,
    /// An actionable or terminal event remains owned by the caller.
    Halted(Step),
    /// The observer returned an unaccepted event intact.
    ObserverRefused(Step),
}

/// Supplies operation identities and accepts complete bootstrap outcomes.
pub trait BootstrapObserver {
    /// Return an unused operation identity, or stop the bootstrap slice.
    fn next_operation(&mut self) -> Option<OperationId>;
    /// Accept an outcome, or return it intact if it cannot be accepted.
    fn observe(&mut self, event: BootstrapStep) -> Result<Decision, BootstrapStep>;
}

/// Why a bounded bootstrap slice stopped; both owners remain caller-owned.
#[must_use = "retain and account for the returned event and worker owners"]
pub enum BootstrapStop {
    /// Invalid wait or step bounds; no work was started.
    Configuration,
    /// The bounded step count was exhausted.
    Yielded,
    /// The observer accepted an outcome and requested a resumable yield.
    ObserverYielded,
    /// The observer accepted an outcome and requested a stop.
    ObserverStopped,
    /// The observer could not supply another operation identity.
    OperationUnavailable,
    /// A ready, actionable, or terminal outcome remains with the caller.
    Halted(BootstrapStep),
    /// The observer returned an unaccepted outcome intact.
    ObserverRefused(BootstrapStep),
}

/// Resource and metered cost for one archive owner.
#[derive(Clone, Copy)]
pub struct ArchiveAdmission<'a> {
    /// Exact resource scoped by the owning task's grants.
    pub resource: &'a str,
    /// Cost to debit if this particular owner starts an attempt.
    pub cost: &'a BudgetVector,
}

/// An owner for one separate-source worker and its caller-bound source claims.
#[must_use = "drain or recover the worker and account for each returned event"]
pub struct Coordinator {
    worker: source_worker::Worker,
    key: SourceKey,
    camera_claim: ContentDigest,
    start_armed: bool,
}

impl Coordinator {
    /// Attach a worker without starting or retrying existing work.
    pub fn new(worker: source_worker::Worker, key: SourceKey, camera_claim: ContentDigest) -> Self {
        Self {
            worker,
            key,
            camera_claim,
            start_armed: false,
        }
    }

    /// Transfer an event if it contains a separate source, returning all other
    /// events and all refusals intact. Only a newly accepted source arms its
    /// first attempt.
    pub fn offer(&mut self, event: SessionEvent) -> source_handoff::Result {
        let result = source_handoff::offer(&mut self.worker, event, self.key, self.camera_claim);
        if matches!(&result, source_handoff::Result::Accepted { .. }) {
            self.start_armed = true;
        }
        result
    }

    /// Transfer an original bootstrap source and preserve its paired audio.
    pub fn offer_bootstrap(
        &mut self,
        event: av_bootstrap_driver::Step,
    ) -> source_handoff::BootstrapResult {
        let result =
            source_handoff::offer_bootstrap(&mut self.worker, event, self.key, self.camera_claim);
        if matches!(&result, source_handoff::BootstrapResult::Accepted { .. }) {
            self.start_armed = true;
        }
        result
    }

    /// Permit one further attempt at an already retained source.
    pub fn authorize_retry(&mut self) -> Result<(), RetryError> {
        if self.start_armed || self.worker.status() != source_worker::Status::Pending {
            return Err(RetryError::NotPending);
        }
        self.start_armed = true;
        Ok(())
    }

    /// Return the exact worker and its retained work to the session owner.
    pub fn into_worker(self) -> source_worker::Worker {
        self.worker
    }

    /// Advance bootstrap while retaining separately returned source records.
    ///
    /// A held source blocks further media; only controller traffic is serviced
    /// while it is being archived. The driver remains caller-owned on every
    /// outcome, including cancellation or an unhandled result.
    pub async fn bootstrap_step<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        driver: &mut av_bootstrap_driver::Driver<'scope, 'task, IO>,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        source_archive: ArchiveAdmission<'_>,
    ) -> BootstrapStep {
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !driver.matches_clock(&owner.clock)
            || !driver.matches_clock(&clock)
        {
            return BootstrapStep::Context;
        }
        if owner.cx.checkpoint().is_err() {
            self.worker.abort();
            self.start_armed = false;
            return BootstrapStep::Cancelled(self.worker.join().await);
        }
        match self.worker.status() {
            source_worker::Status::Idle => {
                match self.offer_bootstrap(driver.step(owner, operation, wait).await) {
                    source_handoff::BootstrapResult::Unhandled(event) => {
                        BootstrapStep::Driver(event)
                    }
                    result => BootstrapStep::SourceOffered(result),
                }
            }
            source_worker::Status::Running => BootstrapStep::SourceArchive(
                source_handoff::drive_control(
                    &mut self.worker,
                    driver.service_control(owner, operation, wait),
                )
                .await,
            ),
            source_worker::Status::Pending if self.start_armed => {
                self.start_armed = false;
                match self.worker.start(
                    task,
                    cx,
                    clock,
                    source_archive.resource,
                    source_archive.cost,
                ) {
                    Ok(()) => BootstrapStep::SourceStarted,
                    Err(error) => BootstrapStep::SourceStartRefused(error),
                }
            }
            source_worker::Status::Pending => BootstrapStep::SourceRetryRequired,
            source_worker::Status::Fenced => BootstrapStep::SourceFenced,
            source_worker::Status::Unavailable => BootstrapStep::SourceUnavailable,
        }
    }

    /// Run bounded bootstrap steps while transferring each complete outcome.
    ///
    /// A ready driver is returned as a halted outcome. On any stop, the caller
    /// retains this coordinator and the driver and must drain any active source
    /// worker before retiring either owner.
    pub async fn run_bootstrap_slice<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        driver: &mut av_bootstrap_driver::Driver<'scope, 'task, IO>,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        wait: Duration,
        max_steps: usize,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        source_archive: ArchiveAdmission<'_>,
        observer: &mut dyn BootstrapObserver,
    ) -> BootstrapStop {
        if wait.is_zero() || wait > Duration::from_secs(30) || !(1..=65_536).contains(&max_steps) {
            return BootstrapStop::Configuration;
        }
        for _ in 0..max_steps {
            let Some(operation) = observer.next_operation() else {
                return BootstrapStop::OperationUnavailable;
            };
            let event = Box::pin(self.bootstrap_step(
                driver,
                owner,
                &operation,
                wait,
                task,
                cx,
                clock,
                source_archive,
            ))
            .await;
            if bootstrap_is_terminal(&event) {
                return BootstrapStop::Halted(event);
            }
            match observer.observe(event) {
                Ok(Decision::Continue) => (),
                Ok(Decision::Yield) => return BootstrapStop::ObserverYielded,
                Ok(Decision::Stop) => return BootstrapStop::ObserverStopped,
                Err(event) => return BootstrapStop::ObserverRefused(event),
            }
        }
        BootstrapStop::Yielded
    }

    /// Advance one session or source-archive operation within the owning task.
    pub async fn step<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        guard: &mut Guard<'scope, 'task, IO>,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        match guard
            .advance_with_source(
                &mut self.worker,
                owner,
                operation,
                wait,
                task,
                cx,
                clock,
                av_archive.resource,
                av_archive.cost,
            )
            .await
        {
            SourceAdvance::Context => Step::Context,
            SourceAdvance::Session(advance) => match self.offer(SessionEvent::Advance(advance)) {
                source_handoff::Result::Unhandled(event) => Step::Session(event),
                result => Step::SourceOffered(result),
            },
            SourceAdvance::SourceArchive(drive) => Step::SourceArchive(drive),
            SourceAdvance::SourcePending if self.start_armed => {
                self.start_armed = false;
                match self.worker.start(
                    task,
                    cx,
                    clock,
                    source_archive.resource,
                    source_archive.cost,
                ) {
                    Ok(()) => Step::SourceStarted,
                    Err(error) => Step::SourceStartRefused(error),
                }
            }
            SourceAdvance::SourcePending => Step::SourceRetryRequired,
            SourceAdvance::SourceFenced => Step::SourceFenced,
            SourceAdvance::SourceUnavailable => Step::SourceUnavailable,
            SourceAdvance::Cancelled(completion) => {
                self.start_armed = false;
                Step::Cancelled(completion)
            }
        }
    }

    /// Run bounded session steps and transfer complete outcomes to an observer.
    ///
    /// This never discards an unaccepted event or automatically retries a
    /// failed source. On any stop or cancellation the caller still owns this
    /// coordinator and the guard, and must explicitly drain both workers
    /// before retirement; no completion is silently consumed during shutdown.
    pub async fn run_slice<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        guard: &mut Guard<'scope, 'task, IO>,
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
            let step = Box::pin(self.step(
                guard,
                owner,
                &operation,
                wait,
                task,
                cx,
                clock,
                av_archive,
                source_archive,
            ))
            .await;
            let step = match step {
                Step::Session(SessionEvent::Advance(Advance::Source(
                    av_unknown_worker_guard::Step::Supervisor(supervisor::Step::AudioPending),
                ))) => match guard.take_audio_event(owner) {
                    Some(audio) => Step::Session(SessionEvent::Audio(audio)),
                    None => return SliceStop::AudioWithheld,
                },
                event if is_terminal(&event) => return SliceStop::Halted(event),
                event => event,
            };
            match observer.observe(step) {
                Ok(Decision::Continue) => (),
                Ok(Decision::Yield) => return SliceStop::ObserverYielded,
                Ok(Decision::Stop) => return SliceStop::ObserverStopped,
                Err(event) => return SliceStop::ObserverRefused(event),
            }
        }
        SliceStop::Yielded
    }
}

fn bootstrap_is_terminal(step: &BootstrapStep) -> bool {
    match step {
        BootstrapStep::Driver(
            av_bootstrap_driver::Step::Ready
            | av_bootstrap_driver::Step::Fenced
            | av_bootstrap_driver::Step::AudioWithheld,
        )
        | BootstrapStep::SourceOffered(
            source_handoff::BootstrapResult::Refused { .. }
            | source_handoff::BootstrapResult::Unhandled(_),
        )
        | BootstrapStep::SourceStartRefused(_)
        | BootstrapStep::SourceRetryRequired
        | BootstrapStep::SourceFenced
        | BootstrapStep::SourceUnavailable
        | BootstrapStep::Context
        | BootstrapStep::Cancelled(_)
        | BootstrapStep::SourceArchive(source_handoff::Drive::NotRunning) => true,
        BootstrapStep::Driver(av_bootstrap_driver::Step::Supervisor(step))
        | BootstrapStep::SourceArchive(source_handoff::Drive::Control { step, .. }) => {
            av_unknown_worker_guard::supervisor_is_terminal(step)
        }
        BootstrapStep::Driver(
            av_bootstrap_driver::Step::Retained
            | av_bootstrap_driver::Step::Forward { .. }
            | av_bootstrap_driver::Step::Audio(_),
        )
        | BootstrapStep::SourceOffered(source_handoff::BootstrapResult::Accepted { .. })
        | BootstrapStep::SourceStarted
        | BootstrapStep::SourceArchive(source_handoff::Drive::Completed(_)) => false,
    }
}

fn is_terminal(step: &Step) -> bool {
    match step {
        Step::Session(SessionEvent::Advance(advance)) => {
            av_unknown_worker_guard::advance_is_terminal(advance)
        }
        Step::SourceOffered(
            source_handoff::Result::Refused { .. } | source_handoff::Result::Unhandled(_),
        )
        | Step::SourceStartRefused(_)
        | Step::SourceRetryRequired
        | Step::SourceFenced
        | Step::SourceUnavailable
        | Step::Context
        | Step::Cancelled(_)
        | Step::SourceArchive(source_handoff::Drive::NotRunning) => true,
        Step::SourceArchive(source_handoff::Drive::Control { step, .. }) => {
            av_unknown_worker_guard::supervisor_is_terminal(step)
        }
        Step::Session(SessionEvent::Audio(_))
        | Step::SourceOffered(source_handoff::Result::Accepted { .. })
        | Step::SourceStarted
        | Step::SourceArchive(source_handoff::Drive::Completed(_)) => false,
    }
}
