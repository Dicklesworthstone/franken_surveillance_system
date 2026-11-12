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
use fss_geometry::WorkBudget;
use fss_publication::RootLedgerReceipt;
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{
    AudioCodec, VideoChannel, archive, av_bootstrap_driver, av_owned_sink, av_recording,
    av_rollover_preflight, av_rollover_worker, av_sink, av_worker, av_worker_guard::ArchiveState,
    conversation, events, intent, management, metered::MeteredClock, motion, pipeline, receive,
    recording, source_handoff, source_worker, supervisor,
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

/// Converted A/V sink and all owners awaiting worker construction.
#[must_use = "finish construction or recover all original owners"]
pub struct PreparedBootstrap<'scope, 'task, IO> {
    /// Original controller and media owner.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Exclusive source, storage, journal and policy owners.
    pub parts: av_worker::UnknownTimeParts,
    /// Exact first segment retained until the worker accepts it.
    pub first_segment: recording::Segment,
    /// Sender-clock hypothesis, not a physical capture-time observation.
    pub origin: av_recording::SenderClockOrigin,
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
    /// A settled predecessor reached a preflight capacity limit. The caller
    /// must still stage and verify an exact successor; this grants no authority.
    RolloverRequired(av_worker::RolloverNeed),
    /// An uncertain attempt requires retirement and reconciliation.
    RecoveryRequired,
    /// Cancellation was requested and a running worker has drained.
    Cancelled(Option<av_worker::UnknownTimeCompletion>),
}

/// A scheduling decision that also accounts for separately archived source.
#[must_use]
pub enum SourceAdvance {
    /// The task, owner, or clock do not describe the same session.
    Context,
    /// No separate source was held; the normal session decision is returned.
    Session(Advance),
    /// A running separate-source attempt was driven alongside control only.
    SourceArchive(source_handoff::Drive),
    /// A separate source is held; start, retry, or retire it explicitly.
    SourcePending,
    /// A separate source requires reconciliation before media can continue.
    SourceFenced,
    /// Source custody could not be inspected; media was not polled.
    SourceUnavailable,
    /// Cancellation was observed and any separate-source attempt was drained.
    /// The guard remains owned and any A/V archive must still be drained.
    Cancelled(Option<source_worker::Completion>),
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
    rollover_need: Option<av_worker::RolloverNeed>,
}

/// A guard paused for an explicit A/V journal rollover. The controller,
/// held segment, retry state and worker resources remain exclusively owned.
#[must_use = "resume the exact guard or explicitly account for all owners"]
pub struct PausedRollover<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    held: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
    retry_required: bool,
    rollover_need: Option<av_worker::RolloverNeed>,
    resources: av_worker::UnknownTimeRolloverResources,
}

/// A controller held while a region-owned worker validates prior custody.
#[must_use = "drain preflight and account for the original archive owner"]
pub struct DeferredPause<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    held: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
    retry_required: bool,
    rollover_need: Option<av_worker::RolloverNeed>,
    worker: av_rollover_preflight::Worker,
    completion: Option<av_rollover_preflight::Completion>,
}

/// Result after custody preflight has drained.
#[must_use = "attach, restore, or reconcile every returned owner"]
pub enum DeferredPauseFinish<'scope, 'task, IO> {
    /// Verified predecessor detached without another storage read.
    Ready {
        /// Paused controller and pending A/V resources.
        paused: PausedRollover<'scope, 'task, IO>,
        /// Exact verified predecessor.
        previous: archive::journal::rollover::Previous,
    },
    /// Preflight did not qualify for the transition.
    Unresolved(DeferredPauseUnresolved<'scope, 'task, IO>),
}

/// Why a drained preflight could not be used.
pub enum DeferredPauseReason {
    /// No blocking closure ran.
    NotStarted,
    /// The runtime requested cancellation.
    Cancelled,
    /// The original lineage failed a custody or readiness check.
    Refused(av_worker::RolloverPauseError),
    /// The closure panicked; the source remains owned but needs reconciliation.
    Panicked,
    /// Ownership or verification state could not be classified.
    Indeterminate,
    /// A proof no longer matched the exact retired owner.
    ProofMismatch,
    /// The runtime failed after the closure returned a verification result.
    RuntimeFailed,
}

/// An unresolved preflight retains the original controller and archive.
#[must_use = "restore a definitely unstarted attempt or retire for reconciliation"]
pub struct DeferredPauseUnresolved<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    held: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
    retry_required: bool,
    rollover_need: Option<av_worker::RolloverNeed>,
    original: av_worker::UnknownTimeRetirement,
    /// Why the transition could not proceed.
    pub reason: DeferredPauseReason,
    /// Independent runtime outcome.
    pub runtime: Result<(), asupersync::runtime::JoinError>,
    /// A panic or inconsistent worker state requires reconciliation.
    pub fenced: bool,
}

/// Controller and original A/V owner after a failed preflight is retired.
#[must_use]
pub struct DeferredPauseRetirement {
    /// Retired controller and unconsumed media.
    pub supervisor: supervisor::Retirement,
    /// Segment retained outside the archive worker.
    pub held: Option<recording::Segment>,
    /// Original archive owner, including its pending segment and lineage.
    pub original: av_worker::UnknownTimeRetirement,
    /// Why preflight could not be used.
    pub reason: DeferredPauseReason,
    /// Runtime classification.
    pub runtime: Result<(), asupersync::runtime::JoinError>,
    /// Whether the worker needs reconciliation.
    pub fenced: bool,
    /// Original archive phase.
    pub archive: ArchiveState,
    /// Original audio fence.
    pub audio_fenced: bool,
    /// Original retry state.
    pub retry_required: bool,
    /// Original capacity signal.
    pub rollover_need: Option<av_worker::RolloverNeed>,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> DeferredPauseUnresolved<'scope, 'task, IO> {
    /// Restore only when work never started or cancellation was observed; the
    /// original guard remains caller-owned and is not implicitly restarted.
    pub fn restore(self) -> Result<Guard<'scope, 'task, IO>, Self> {
        if self.fenced
            || !matches!(
                self.reason,
                DeferredPauseReason::NotStarted | DeferredPauseReason::Cancelled
            )
        {
            return Err(self);
        }
        Ok(Guard {
            supervisor: self.supervisor,
            worker: av_worker::UnknownTimeWorker::from_retirement(self.original),
            held: self.held,
            archive: self.archive,
            audio_fenced: self.audio_fenced,
            retry_required: self.retry_required,
            rollover_need: self.rollover_need,
        })
    }
    /// Close the controller and return the exact original archive owner.
    pub fn retire(self) -> DeferredPauseRetirement {
        DeferredPauseRetirement {
            supervisor: self.supervisor.retire(),
            held: self.held,
            original: self.original,
            reason: self.reason,
            runtime: self.runtime,
            fenced: self.fenced,
            archive: self.archive,
            audio_fenced: self.audio_fenced,
            retry_required: self.retry_required,
            rollover_need: self.rollover_need,
        }
    }
}

/// A paused controller and one region-owned rollover operation.
#[must_use = "join the transition and finish or retire all owners"]
pub struct BackgroundRollover<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    held: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
    retry_required: bool,
    rollover_need: Option<av_worker::RolloverNeed>,
    worker: av_rollover_worker::Worker,
    completion: Option<av_rollover_worker::Completion>,
}

/// A refused transfer retains the paused guard and untouched inputs.
#[must_use]
pub struct BackgroundRefusal<'scope, 'task, IO> {
    /// Original paused controller and resources.
    pub paused: PausedRollover<'scope, 'task, IO>,
    /// Unconsumed transition inputs.
    pub inputs: av_rollover_worker::Inputs,
}

/// One bounded control or worker-completion decision during rollover.
#[must_use]
pub enum BackgroundDrive {
    /// No operation is running or completed.
    NotRunning,
    /// The worker has drained; its exact result remains owned by the guard.
    Completed,
    /// A controller result and whether the worker also drained.
    Control {
        /// Controller observation or effect result.
        step: supervisor::Step,
        /// Whether the worker result is now retained by the guard.
        completed: bool,
    },
}

/// A fully drained background transition.
#[must_use = "retain the resumed guard or reconcile the unresolved transition"]
pub enum BackgroundFinish<'scope, 'task, IO> {
    /// Exact matching successor replayed and attached.
    Resumed {
        /// Session guard with its pending source still held.
        guard: Guard<'scope, 'task, IO>,
        /// Actual replay receipt.
        receipt: RootLedgerReceipt,
    },
    /// Failure or uncertainty retains every recoverable owner.
    Unresolved(BackgroundUnresolved<'scope, 'task, IO>),
}

/// A transition that cannot be automatically resumed.
#[must_use = "reconcile or retire the controller and all transition owners"]
pub struct BackgroundUnresolved<'scope, 'task, IO> {
    paused: PausedRollover<'scope, 'task, IO>,
    inputs: Option<av_rollover_worker::Inputs>,
    completion: av_rollover_worker::Completion,
    fenced: bool,
}

/// All remaining owners after an unresolved transition is explicitly retired.
#[must_use]
pub struct BackgroundRetirement {
    /// Retired controller and media sources.
    pub supervisor: supervisor::Retirement,
    /// Segment held outside the archive worker, if any.
    pub held: Option<recording::Segment>,
    /// Pending media and storage resources.
    pub resources: av_worker::UnknownTimeRolloverResources,
    /// Unconsumed transition inputs, if the work did not start.
    pub inputs: Option<av_rollover_worker::Inputs>,
    /// Exact task and transition outcomes.
    pub completion: av_rollover_worker::Completion,
    /// Panic or inconsistent state requires reconciliation.
    pub fenced: bool,
    /// Original scheduler archive phase.
    pub archive: ArchiveState,
    /// Audio observations require reconciliation.
    pub audio_fenced: bool,
    /// Original retry latch.
    pub retry_required: bool,
    /// Original capacity signal.
    pub rollover_need: Option<av_worker::RolloverNeed>,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> BackgroundUnresolved<'scope, 'task, IO> {
    /// Recover the paused owner only when the worker state was not fenced.
    /// The caller must still inspect the outcome before any further operation.
    pub fn into_paused(
        self,
    ) -> Result<
        (
            PausedRollover<'scope, 'task, IO>,
            Option<av_rollover_worker::Inputs>,
            av_rollover_worker::Completion,
        ),
        Self,
    > {
        if self.fenced {
            return Err(self);
        }
        Ok((self.paused, self.inputs, self.completion))
    }

    /// Retire controller I/O and return all recoverable storage and sources.
    pub fn retire(self) -> BackgroundRetirement {
        let PausedRollover {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources,
        } = self.paused;
        BackgroundRetirement {
            supervisor: supervisor.retire(),
            held,
            resources,
            inputs: self.inputs,
            completion: self.completion,
            fenced: self.fenced,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
        }
    }
}

/// Failed reattachment preserves the paused guard and active transition.
#[must_use = "reconcile or resume both returned owners"]
pub struct PausedAttachRefusal<'scope, 'task, IO> {
    /// Paused original controller, source and archive resources.
    pub paused: PausedRollover<'scope, 'task, IO>,
    /// The transition which could not be attached.
    pub active: archive::journal::rollover::Active,
}

struct PausedPreparedAttachRefusal<'scope, 'task, IO> {
    paused: PausedRollover<'scope, 'task, IO>,
    attachment: av_worker::PreparedUnknownTimeAttachment,
}

/// Failed restoration preserves the paused guard and supplied predecessor.
#[must_use = "reconcile or restore both returned owners"]
pub struct PausedRestoreRefusal<'scope, 'task, IO> {
    /// Paused original controller, source and archive resources.
    pub paused: PausedRollover<'scope, 'task, IO>,
    /// The nonmatching predecessor.
    pub previous: archive::journal::rollover::Previous,
}

impl<'scope, 'task, IO> PausedRollover<'scope, 'task, IO> {
    /// Transfer a matching predecessor and fresh stores to a single bounded
    /// rollover worker; no storage operation starts until `start` is called.
    pub fn into_background(
        self,
        inputs: av_rollover_worker::Inputs,
    ) -> Result<BackgroundRollover<'scope, 'task, IO>, BackgroundRefusal<'scope, 'task, IO>> {
        let matches_need = self.rollover_need.is_none_or(|need| {
            inputs.previous.journal.confirmed() == Some(need.confirmed)
                && inputs.previous.journal.anchor() == need.journal
                && inputs.previous.keeper.anchor() == need.keeper
        });
        if !matches_need || !self.resources.matches_previous(&inputs.previous) {
            return Err(BackgroundRefusal {
                paused: self,
                inputs,
            });
        }
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources,
        } = self;
        Ok(BackgroundRollover {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            worker: av_rollover_worker::Worker::new(resources, inputs),
            completion: None,
        })
    }

    /// Scoped authority for staging or committing the new history.
    pub fn replay(&self) -> &ReplayCx {
        self.resources.replay()
    }

    /// The guard's pre-pause archive phase; this is not a completion receipt.
    pub fn archive_state(&self) -> ArchiveState {
        self.archive
    }

    /// A segment held outside the worker, if any.
    pub fn held_segment(&self) -> Option<&recording::Segment> {
        self.held.as_ref()
    }

    /// Whether the worker sink owns a pending segment or fence.
    pub fn worker_has_pending(&self) -> bool {
        self.resources.has_pending()
    }

    /// Capacity-triggered predecessor held across this pause, if any.
    pub fn rollover_need(&self) -> Option<av_worker::RolloverNeed> {
        self.rollover_need
    }

    /// Revalidate the exact confirmed A/V root using the held archive owner.
    pub fn replay_confirmed_av(
        &mut self,
        active: &mut archive::journal::rollover::Active,
        read: &dyn archive::ReadAuthority,
        limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
    ) -> Result<RootLedgerReceipt, archive::journal::rollover::AvReplayError> {
        self.resources
            .replay_confirmed_av(active, read, limits, work)
    }

    /// Resume with an already replayed successor. A matching capacity request
    /// is cleared only after attachment succeeds; other retry latches remain.
    /// No archive operation starts until the scheduler is advanced again.
    pub fn attach(
        self,
        active: archive::journal::rollover::Active,
    ) -> Result<Guard<'scope, 'task, IO>, PausedAttachRefusal<'scope, 'task, IO>> {
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources,
        } = self;
        let binding = active.binding();
        let satisfied = rollover_need.is_some_and(|need| rollover_matches(need, binding));
        match resources.attach(active) {
            Ok(worker) => Ok(Guard {
                supervisor,
                worker,
                held,
                archive,
                audio_fenced,
                retry_required: retry_required && !satisfied,
                rollover_need: if satisfied { None } else { rollover_need },
            }),
            Err(refusal) => Err(PausedAttachRefusal {
                paused: Self {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    resources: refusal.resources,
                },
                active: refusal.active,
            }),
        }
    }

    /// Finalize a successor whose custody was checked by the blocking worker.
    fn attach_prepared(
        self,
        attachment: av_worker::PreparedUnknownTimeAttachment,
    ) -> Result<Guard<'scope, 'task, IO>, PausedPreparedAttachRefusal<'scope, 'task, IO>> {
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources,
        } = self;
        let satisfied =
            rollover_need.is_some_and(|need| rollover_matches(need, attachment.binding()));
        match resources.attach_prepared(attachment) {
            Ok(worker) => Ok(Guard {
                supervisor,
                worker,
                held,
                archive,
                audio_fenced,
                retry_required: retry_required && !satisfied,
                rollover_need: if satisfied { None } else { rollover_need },
            }),
            Err(refusal) => Err(PausedPreparedAttachRefusal {
                paused: Self {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    resources: refusal.resources,
                },
                attachment: refusal.attachment,
            }),
        }
    }

    /// Restore the unchanged predecessor after abandoning an uncommitted stage.
    pub fn restore(
        self,
        previous: archive::journal::rollover::Previous,
    ) -> Result<Guard<'scope, 'task, IO>, PausedRestoreRefusal<'scope, 'task, IO>> {
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources,
        } = self;
        match resources.restore(previous) {
            Ok(retirement) => Ok(Guard {
                supervisor,
                worker: av_worker::UnknownTimeWorker::from_retirement(retirement),
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
            Err(refusal) => Err(PausedRestoreRefusal {
                paused: Self {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    resources: refusal.resources,
                },
                previous: refusal.previous,
            }),
        }
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> PausedRollover<'scope, 'task, IO> {
    /// Service controller traffic while archive ownership is paused, without
    /// polling or consuming camera media. Callers must retain the returned
    /// step, including any interrupted effect or terminal controller state.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.supervisor.step_control(owner, operation, wait).await
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> BackgroundRollover<'scope, 'task, IO> {
    pub(super) fn control_supervisor(&mut self) -> &mut supervisor::Supervisor<'scope, 'task, IO> {
        &mut self.supervisor
    }

    /// Start the single region-owned blocking transition.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        if !self.supervisor.matches_clock(&clock) {
            return Err(av_rollover_worker::StartError::Context);
        }
        if self.completion.is_some() {
            return Err(av_rollover_worker::StartError::Fenced);
        }
        self.worker.start(task, cx, clock, resource, cost)
    }
    /// Recover the original paused guard and inputs after a pre-start refusal.
    pub fn into_unstarted(
        self,
    ) -> Result<
        (
            PausedRollover<'scope, 'task, IO>,
            av_rollover_worker::Inputs,
        ),
        Self,
    > {
        if self.completion.is_some() {
            return Err(self);
        }
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            worker,
            completion,
        } = self;
        match worker.into_unstarted() {
            Ok((resources, inputs)) => Ok((
                PausedRollover {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    resources,
                },
                inputs,
            )),
            Err(worker) => Err(Self {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker,
                completion,
            }),
        }
    }

    /// Service controller traffic without polling media or waiting for storage.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.supervisor.step_control(owner, operation, wait).await
    }
    /// Service control while periodically checking the exact worker. A
    /// completed transition remains internally owned until `finish`.
    pub async fn drive(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> BackgroundDrive {
        if self.completion.is_some() {
            return BackgroundDrive::Completed;
        }
        if !self.worker.is_running() {
            return BackgroundDrive::NotRunning;
        }
        if self.poll_join_once().await {
            return BackgroundDrive::Completed;
        }
        let step = self.service_control(owner, operation, wait).await;
        let completed = self.poll_join_once().await;
        BackgroundDrive::Control { step, completed }
    }

    async fn poll_join_once(&mut self) -> bool {
        poll_fn(|context| {
            let mut join = pin!(self.join());
            Poll::Ready(matches!(join.as_mut().poll(context), Poll::Ready(true)))
        })
        .await
    }

    /// Request cancellation; the worker must still be joined.
    pub fn abort(&self) {
        self.worker.abort();
    }
    /// Whether the region coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.worker.cancellation_observed()
    }
    /// Join the exact operation while retaining its outcome internally.
    pub async fn join(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if let Some(completion) = self.worker.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }
    /// Attach only a matching, successfully replayed transition. All other
    /// outcomes retain the controller, pending segment and transition state.
    pub fn finish(self) -> Result<BackgroundFinish<'scope, 'task, IO>, Self> {
        if self.completion.is_none() {
            return Err(self);
        }
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            worker,
            completion,
        } = self;
        let Some(completion) = completion else {
            return Err(Self {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker,
                completion: None,
            });
        };
        let retired = match worker.retire() {
            Ok(retired) => retired,
            Err(worker) => {
                return Err(Self {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    worker,
                    completion: Some(completion),
                });
            }
        };
        let paused = PausedRollover {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            resources: retired.resources,
        };
        if !retired.fenced && retired.inputs.is_none() {
            match completion {
                av_rollover_worker::Completion {
                    runtime: Ok(()),
                    outcome:
                        av_rollover_worker::Outcome::Prepared {
                            attachment,
                            receipt,
                        },
                } if rollover_need
                    .is_none_or(|need| rollover_matches(need, attachment.binding())) =>
                {
                    return Ok(match paused.attach_prepared(attachment) {
                        Ok(guard) => BackgroundFinish::Resumed { guard, receipt },
                        Err(refusal) => BackgroundFinish::Unresolved(BackgroundUnresolved {
                            paused: refusal.paused,
                            inputs: None,
                            completion: av_rollover_worker::Completion {
                                runtime: Ok(()),
                                outcome: av_rollover_worker::Outcome::Prepared {
                                    attachment: refusal.attachment,
                                    receipt,
                                },
                            },
                            fenced: false,
                        }),
                    });
                }
                completion => {
                    return Ok(BackgroundFinish::Unresolved(BackgroundUnresolved {
                        paused,
                        inputs: retired.inputs,
                        completion,
                        fenced: retired.fenced,
                    }));
                }
            }
        }
        Ok(BackgroundFinish::Unresolved(BackgroundUnresolved {
            paused,
            inputs: retired.inputs,
            completion,
            fenced: retired.fenced,
        }))
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> DeferredPause<'scope, 'task, IO> {
    pub(super) fn control_supervisor(&mut self) -> &mut supervisor::Supervisor<'scope, 'task, IO> {
        &mut self.supervisor
    }

    /// Admit the custody check to the bounded runtime blocking pool.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        if !self.supervisor.matches_clock(&clock) {
            return Err(av_rollover_worker::StartError::Context);
        }
        if self.completion.is_some() {
            return Err(av_rollover_worker::StartError::Fenced);
        }
        self.worker
            .start(task, cx, clock, resource, cost)
            .map_err(|error| match error {
                av_rollover_preflight::StartError::Running => {
                    av_rollover_worker::StartError::Running
                }
                av_rollover_preflight::StartError::Fenced => av_rollover_worker::StartError::Fenced,
                av_rollover_preflight::StartError::Context => {
                    av_rollover_worker::StartError::Context
                }
                av_rollover_preflight::StartError::Clock => av_rollover_worker::StartError::Clock,
                av_rollover_preflight::StartError::Task(error) => {
                    av_rollover_worker::StartError::Task(error)
                }
                av_rollover_preflight::StartError::Runtime(error) => {
                    av_rollover_worker::StartError::Runtime(error)
                }
            })
    }
    /// Service control while the prior custody check is running.
    pub async fn drive(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> BackgroundDrive {
        if self.completion.is_some() {
            return BackgroundDrive::Completed;
        }
        if !self.worker.is_running() {
            return BackgroundDrive::NotRunning;
        }
        if self.poll_join_once().await {
            return BackgroundDrive::Completed;
        }
        let step = self.supervisor.step_control(owner, operation, wait).await;
        let completed = self.poll_join_once().await;
        BackgroundDrive::Control { step, completed }
    }
    async fn poll_join_once(&mut self) -> bool {
        poll_fn(|context| {
            let mut join = pin!(self.join());
            Poll::Ready(matches!(join.as_mut().poll(context), Poll::Ready(true)))
        })
        .await
    }
    /// Request cancellation; join remains required.
    pub fn abort(&self) {
        self.worker.abort();
    }
    /// Whether the runtime coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.worker.cancellation_observed()
    }
    /// Join the exact preflight without releasing its original archive owner.
    pub async fn join(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if let Some(completion) = self.worker.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }
    /// Recover the untouched guard when admission never succeeded.
    pub fn into_unstarted(self) -> Result<Guard<'scope, 'task, IO>, Self> {
        if self.worker.is_running() || self.completion.is_some() {
            return Err(self);
        }
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            worker,
            completion,
        } = self;
        match worker.retire() {
            Ok(retired) if !retired.fenced => Ok(Guard {
                supervisor,
                worker: av_worker::UnknownTimeWorker::from_retirement(retired.original),
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
            Ok(retired) => Err(Self {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker: av_rollover_preflight::Worker::from_retirement(retired),
                completion,
            }),
            Err(worker) => Err(Self {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker,
                completion,
            }),
        }
    }
    /// Complete the preflight and detach only after the exact verified proof.
    pub fn finish(self) -> Result<DeferredPauseFinish<'scope, 'task, IO>, Self> {
        if self.completion.is_none() {
            return Err(self);
        }
        let Self {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            worker,
            completion,
        } = self;
        let Some(completion) = completion else {
            return Err(Self {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker,
                completion: None,
            });
        };
        let retired = match worker.retire() {
            Ok(retired) => retired,
            Err(worker) => {
                return Err(Self {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    worker,
                    completion: Some(completion),
                });
            }
        };
        let (reason, original) = match (completion.runtime, completion.outcome) {
            (Ok(()), av_rollover_preflight::Outcome::Verified(proof)) if !retired.fenced => {
                match retired.original.into_rollover_verified(proof) {
                    Ok((resources, previous)) => {
                        return Ok(DeferredPauseFinish::Ready {
                            paused: PausedRollover {
                                supervisor,
                                held,
                                archive,
                                audio_fenced,
                                retry_required,
                                rollover_need,
                                resources,
                            },
                            previous,
                        });
                    }
                    Err(original) => (DeferredPauseReason::ProofMismatch, (original, Ok(()))),
                }
            }
            (runtime, outcome) => {
                let reason = if runtime.is_err()
                    && matches!(outcome, av_rollover_preflight::Outcome::Verified(_))
                {
                    DeferredPauseReason::RuntimeFailed
                } else {
                    match outcome {
                        av_rollover_preflight::Outcome::Verified(_) => {
                            DeferredPauseReason::Indeterminate
                        }
                        av_rollover_preflight::Outcome::Refused(error) => {
                            DeferredPauseReason::Refused(error)
                        }
                        av_rollover_preflight::Outcome::Cancelled => DeferredPauseReason::Cancelled,
                        av_rollover_preflight::Outcome::NotStarted => {
                            DeferredPauseReason::NotStarted
                        }
                        av_rollover_preflight::Outcome::Panicked => DeferredPauseReason::Panicked,
                        av_rollover_preflight::Outcome::Indeterminate => {
                            DeferredPauseReason::Indeterminate
                        }
                    }
                };
                (reason, (retired.original, runtime))
            }
        };
        Ok(DeferredPauseFinish::Unresolved(DeferredPauseUnresolved {
            supervisor,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
            original: original.0,
            reason,
            runtime: original.1,
            fenced: retired.fenced,
        }))
    }
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
    /// Exact settled predecessor requesting rollover, if retained.
    pub rollover_need: Option<av_worker::RolloverNeed>,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Guard<'scope, 'task, IO> {
    /// Transfer the drained archive to a region-owned preflight worker without
    /// reading storage on the camera-control task. The returned owner must be
    /// started, driven, and drained before the guard can resume.
    pub fn defer_rollover_pause(self) -> Result<DeferredPause<'scope, 'task, IO>, Self> {
        if matches!(self.archive, ArchiveState::Running | ArchiveState::Recovery) {
            return Err(self);
        }
        let Self {
            supervisor,
            worker,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
        } = self;
        match worker.retire() {
            Ok(retirement) => Ok(DeferredPause {
                supervisor,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
                worker: av_rollover_preflight::Worker::new(retirement),
                completion: None,
            }),
            Err(worker) => Err(Self {
                supervisor,
                worker,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
        }
    }

    /// Pause at an idle or drained-pending archive boundary. Running and
    /// indeterminate archive operations are refused with the guard intact.
    /// Later generations may synchronously revalidate retained switch custody.
    /// This does not stop or restart the camera.
    pub fn pause_rollover(
        self,
    ) -> Result<
        (
            PausedRollover<'scope, 'task, IO>,
            archive::journal::rollover::Previous,
        ),
        Self,
    > {
        if matches!(self.archive, ArchiveState::Running | ArchiveState::Recovery) {
            return Err(self);
        }
        let Self {
            supervisor,
            worker,
            held,
            archive,
            audio_fenced,
            retry_required,
            rollover_need,
        } = self;
        let retired = match worker.retire() {
            Ok(retired) => retired,
            Err(worker) => {
                return Err(Self {
                    supervisor,
                    worker,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                });
            }
        };
        match retired.into_rollover() {
            Ok((resources, previous)) => Ok((
                PausedRollover {
                    supervisor,
                    held,
                    archive,
                    audio_fenced,
                    retry_required,
                    rollover_need,
                    resources,
                },
                previous,
            )),
            Err(retired) => Err(Self {
                supervisor,
                worker: av_worker::UnknownTimeWorker::from_retirement(retired),
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
        }
    }
    pub(super) fn control_supervisor(&mut self) -> &mut supervisor::Supervisor<'scope, 'task, IO> {
        &mut self.supervisor
    }

    /// Build from a completed bootstrap without performing I/O or inventing
    /// capture bounds. All source and storage owners return on refusal.
    pub fn from_bootstrap(
        handoff: av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        resources: BootstrapResources,
    ) -> Result<BootstrapStarted<'scope, 'task, IO>, BootstrapRefusal<'scope, 'task, IO>> {
        let prepared = Self::prepare_bootstrap(Box::new(handoff), Box::new(resources))
            .map_err(|refusal| *refusal)?;
        Self::finish_bootstrap(prepared)
            .map(|started| *started)
            .map_err(|refusal| *refusal)
    }

    /// Convert a bootstrap sink, returning all owners intact on refusal.
    #[inline(never)]
    pub fn prepare_bootstrap(
        handoff: Box<av_bootstrap_driver::Handoff<'scope, 'task, IO>>,
        resources: Box<BootstrapResources>,
    ) -> Result<Box<PreparedBootstrap<'scope, 'task, IO>>, Box<BootstrapRefusal<'scope, 'task, IO>>>
    {
        if !handoff.supervisor.audio_tracking_active() || handoff.supervisor.has_pending_audio() {
            return Err(Box::new(BootstrapRefusal::Audio {
                handoff: *handoff,
                resources: *resources,
            }));
        }
        let av_bootstrap_driver::Handoff {
            supervisor,
            bootstrap,
        } = *handoff;
        let av_owned_sink::Bootstrap {
            sink,
            first_segment,
            origin,
        } = bootstrap;
        let sink = match sink.into_unknown_time() {
            Ok(sink) => sink,
            Err(sink) => {
                return Err(Box::new(BootstrapRefusal::Sink {
                    handoff: av_bootstrap_driver::Handoff {
                        supervisor,
                        bootstrap: av_owned_sink::Bootstrap {
                            sink,
                            first_segment,
                            origin,
                        },
                    },
                    resources: *resources,
                }));
            }
        };
        let resources = *resources;
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
        Ok(Box::new(PreparedBootstrap {
            supervisor,
            parts,
            first_segment,
            origin,
        }))
    }

    /// Construct a worker from a previously converted bootstrap.
    #[inline(never)]
    pub fn finish_bootstrap(
        prepared: Box<PreparedBootstrap<'scope, 'task, IO>>,
    ) -> Result<Box<BootstrapStarted<'scope, 'task, IO>>, Box<BootstrapRefusal<'scope, 'task, IO>>>
    {
        let PreparedBootstrap {
            supervisor,
            parts,
            first_segment,
            origin,
        } = *prepared;
        let worker = match av_worker::UnknownTimeWorker::new(parts) {
            Ok(worker) => worker,
            Err(parts) => {
                return Err(Box::new(BootstrapRefusal::Worker {
                    supervisor,
                    parts,
                    first_segment,
                    origin,
                }));
            }
        };
        Ok(Box::new(BootstrapStarted {
            guard: Self {
                supervisor,
                worker,
                held: Some(first_segment),
                archive: ArchiveState::Idle,
                audio_fenced: false,
                retry_required: false,
                rollover_need: None,
            },
            origin,
        }))
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
            rollover_need: None,
        })
    }

    /// Current archive phase.
    pub fn archive_state(&self) -> ArchiveState {
        self.archive
    }

    /// Exact settled predecessor requesting rollover, if any. The request is
    /// retained until explicit retry or a matching verified successor attaches.
    pub fn rollover_need(&self) -> Option<av_worker::RolloverNeed> {
        self.rollover_need
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
        match Box::pin(self.supervisor.step(owner, operation, wait)).await {
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

    /// Service control while a separately owned original source is archived.
    ///
    /// This does not poll camera media. The returned value retains both the
    /// controller result and any completed source publication attempt.
    pub async fn drive_source_control(
        &mut self,
        worker: &mut source_worker::Worker,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> source_handoff::Drive {
        source_handoff::drive_control(worker, self.service_control(owner, operation, wait)).await
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
        self.rollover_need = None;
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
        self.rollover_need = rollover_from_completion(&completion);
        Some(completion)
    }

    /// Allow a bounded scheduler to retry a definite refusal or unstarted
    /// attempt. Indeterminate outcomes cannot be rearmed here.
    pub fn authorize_retry(&mut self) -> bool {
        if self.archive == ArchiveState::Pending && self.retry_required {
            self.retry_required = false;
            self.rollover_need = None;
            true
        } else {
            false
        }
    }

    /// Authorize additional AAC observations without resetting the timing
    /// epoch or automatically retrying a retained source. A running or
    /// indeterminate archive must first drain or be reconciled.
    pub fn extend_audio_limit(
        &mut self,
        additional_frames: u64,
    ) -> Result<u64, av_worker::AudioAllowanceError> {
        if self.archive == ArchiveState::Recovery {
            return Err(av_worker::AudioAllowanceError::Fenced);
        }
        self.worker.extend_audio_limit(additional_frames)
    }

    /// `None` means an admitted archive task still owns the muxer. A caller
    /// must keep driving that task; it must not treat this as free allowance.
    pub fn remaining_audio_frames(
        &mut self,
    ) -> Result<Option<u64>, av_worker::AudioAllowanceError> {
        match self.archive {
            ArchiveState::Running => Ok(None),
            ArchiveState::Recovery => Err(av_worker::AudioAllowanceError::Fenced),
            ArchiveState::Idle | ArchiveState::Pending => {
                self.worker.remaining_audio_frames().map(Some)
            }
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
        if self.archive == ArchiveState::Pending {
            if let Some(need) = self.rollover_need {
                return Advance::RolloverRequired(need);
            }
        }
        match self.archive {
            ArchiveState::Idle => {
                Advance::Source(Box::pin(self.step(owner, operation, wait)).await)
            }
            ArchiveState::Pending if self.retry_required => Advance::RetryRequired,
            ArchiveState::Pending => match self.start_archive(task, cx, clock, resource, cost) {
                Ok(()) => Advance::ArchiveStarted,
                Err(error) => {
                    self.retry_required = true;
                    Advance::StartRefused(error)
                }
            },
            ArchiveState::Running => {
                Advance::Archive(Box::pin(self.drive_archive(owner, operation, wait)).await)
            }
            ArchiveState::Recovery => Advance::RecoveryRequired,
        }
    }

    /// Advance the session without reading media past an outstanding source.
    ///
    /// The caller owns both the worker and every returned result. A refused
    /// source remains pending until an explicit retry or retirement; this
    /// method never silently retries publication. On cancellation, it drains
    /// the separate worker and returns its exact completion, while leaving the
    /// guard and any A/V archive for the caller to drain separately.
    pub async fn advance_with_source<'a, 'b>(
        &mut self,
        worker: &mut source_worker::Worker,
        owner: &mut conversation::Owner<'_, 'a, 'b>,
        operation: &OperationId,
        wait: Duration,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> SourceAdvance {
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !self.supervisor.matches_clock(&owner.clock)
            || !self.supervisor.matches_clock(&clock)
        {
            return SourceAdvance::Context;
        }
        if owner.cx.checkpoint().is_err() {
            worker.abort();
            return SourceAdvance::Cancelled(worker.join().await);
        }
        match worker.status() {
            source_worker::Status::Idle => SourceAdvance::Session(
                Box::pin(self.advance(owner, operation, wait, task, cx, clock, resource, cost))
                    .await,
            ),
            source_worker::Status::Running => SourceAdvance::SourceArchive(
                Box::pin(self.drive_source_control(worker, owner, operation, wait)).await,
            ),
            source_worker::Status::Pending => SourceAdvance::SourcePending,
            source_worker::Status::Fenced => SourceAdvance::SourceFenced,
            source_worker::Status::Unavailable => SourceAdvance::SourceUnavailable,
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
            rollover_need,
        } = self;
        match worker.retire() {
            Ok(worker) => Ok(Retirement {
                held,
                worker,
                supervisor: supervisor.retire(),
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
            Err(worker) => Err(Self {
                supervisor,
                worker,
                held,
                archive,
                audio_fenced,
                retry_required,
                rollover_need,
            }),
        }
    }
}

fn rollover_matches(
    need: av_worker::RolloverNeed,
    binding: archive::journal::rollover::Binding,
) -> bool {
    need.confirmed == binding.confirmed
        && need.journal == binding.old_journal
        && need.keeper == binding.old_keeper
}

fn rollover_from_completion(
    completion: &av_worker::UnknownTimeCompletion,
) -> Option<av_worker::RolloverNeed> {
    match (&completion.runtime, &completion.outcome) {
        (
            Ok(()),
            av_worker::UnknownTimeOutcome::Publication(
                av_worker::UnknownTimePublication::Refused {
                    stage: av_worker::UnknownTimeFailureStage::BeforePublication,
                    reason: av_worker::FailureReason::JournalCapacity,
                    pending: None,
                    receipt: None,
                    rollover: Some(need),
                },
            ),
        ) => Some(*need),
        _ => None,
    }
}

pub(super) fn supervisor_is_terminal(step: &supervisor::Step) -> bool {
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

pub(super) fn advance_is_terminal(advance: &Advance) -> bool {
    match advance {
        Advance::Context
        | Advance::StartRefused(_)
        | Advance::RetryRequired
        | Advance::RolloverRequired(_)
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

#[cfg(test)]
mod rollover_scheduler_tests {
    use super::*;
    use asupersync::runtime::JoinError;
    use fss_core::ContentDigest;
    use fss_runtime::effect_journal::EffectJournalPin;

    fn pin(label: &[u8], sequence: u64) -> EffectJournalPin {
        EffectJournalPin {
            sequence,
            root: ContentDigest::sha256(label),
        }
    }

    fn need() -> av_worker::RolloverNeed {
        av_worker::RolloverNeed {
            confirmed: archive::UnknownTimePin {
                root: ContentDigest::sha256(b"confirmed"),
                retention: ContentDigest::sha256(b"retention"),
            },
            journal: pin(b"journal", 5),
            keeper: pin(b"keeper", 5),
        }
    }

    fn completion(
        stage: av_worker::UnknownTimeFailureStage,
        reason: av_worker::FailureReason,
        pending: Option<archive::UnknownTimePin>,
        marker: Option<av_worker::RolloverNeed>,
    ) -> av_worker::UnknownTimeCompletion {
        av_worker::UnknownTimeCompletion {
            runtime: Ok(()),
            outcome: av_worker::UnknownTimeOutcome::Publication(
                av_worker::UnknownTimePublication::Refused {
                    stage,
                    reason,
                    pending,
                    receipt: None,
                    rollover: marker,
                },
            ),
        }
    }

    #[test]
    fn rollover_signal_requires_a_successful_precandidate_capacity_refusal() {
        use av_worker::{FailureReason as R, UnknownTimeFailureStage as S};
        let expected = need();
        let make = || {
            completion(
                S::BeforePublication,
                R::JournalCapacity,
                None,
                Some(expected),
            )
        };
        assert_eq!(rollover_from_completion(&make()), Some(expected));
        assert!(advance_is_terminal(&Advance::RolloverRequired(expected)));
        assert_eq!(
            rollover_from_completion(&completion(
                S::Archive,
                R::JournalCapacity,
                None,
                Some(expected)
            )),
            None
        );
        assert_eq!(
            rollover_from_completion(&completion(
                S::BeforePublication,
                R::Storage,
                None,
                Some(expected)
            )),
            None
        );
        assert_eq!(
            rollover_from_completion(&completion(
                S::BeforePublication,
                R::JournalCapacity,
                Some(expected.confirmed),
                Some(expected)
            )),
            None
        );
        assert_eq!(
            rollover_from_completion(&completion(
                S::BeforePublication,
                R::JournalCapacity,
                None,
                None
            )),
            None
        );
        let mut failed_runtime = make();
        failed_runtime.runtime = Err(JoinError::PolledAfterCompletion);
        assert_eq!(rollover_from_completion(&failed_runtime), None);
    }

    #[test]
    fn only_the_exact_predecessor_satisfies_a_rollover_request() {
        let expected = need();
        let binding = archive::journal::rollover::Binding {
            scope: ContentDigest::sha256(b"scope"),
            confirmed: expected.confirmed,
            old_journal: expected.journal,
            old_keeper: expected.keeper,
            new_journal: pin(b"next journal", 3),
            new_keeper: pin(b"next keeper", 1),
        };
        assert!(rollover_matches(expected, binding));
        assert!(!rollover_matches(
            expected,
            archive::journal::rollover::Binding {
                old_journal: pin(b"other", 5),
                ..binding
            }
        ));
        assert!(!rollover_matches(
            expected,
            archive::journal::rollover::Binding {
                old_keeper: pin(b"other", 5),
                ..binding
            }
        ));
        assert!(!rollover_matches(
            expected,
            archive::journal::rollover::Binding {
                confirmed: archive::UnknownTimePin {
                    root: ContentDigest::sha256(b"other"),
                    ..binding.confirmed
                },
                ..binding
            }
        ));
    }
}
