#![forbid(unsafe_code)]
//! Source-aware bridge from an owned recording session to A/V rollover.
//!
//! The caller supplies fresh stores and separately retained pin custody. This
//! bridge does not create paths, discover restart state, or authenticate a
//! camera. It keeps the separate-source coordinator owned across the switch.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{BudgetVector, OperationId};
use fss_publication::RootLedgerReceipt;
use fss_runtime::execution::TaskCx;

use super::{
    av_rollover_worker,
    av_unknown_worker_guard::{self, BackgroundDrive, BackgroundFinish, BackgroundRollover},
    conversation,
    metered::MeteredClock,
    recording_session::{AudioAllowancePolicy, AudioAllowanceStep, Phase, Session},
    source_coordinator::Coordinator,
    source_worker,
};

/// Refusal preserves the complete session or the exact paused transition.
#[must_use = "recover every returned session and storage owner"]
pub enum PrepareRefusal<'scope, 'task, IO> {
    /// The source owner or recording guard is not at a safe capacity boundary.
    NotReady {
        /// Unchanged session.
        session: Session<'scope, 'task, IO>,
        /// Unconsumed fresh stores and policy.
        supplies: av_rollover_worker::Supplies,
    },
    /// The paused predecessor disagreed with its bound resources. No work ran.
    Binding {
        /// Still-owned separate-source coordinator.
        coordinator: Coordinator,
        /// Paused guard and supplied predecessor for reconciliation.
        refusal: av_unknown_worker_guard::BackgroundRefusal<'scope, 'task, IO>,
    },
}

/// Owns recording, its explicit audio budget, and staged successor supplies
/// across repeated A/V journal transitions. Store creation and restart
/// recovery remain the caller's responsibility.
#[must_use = "drain or recover the exact managed owners"]
pub struct ManagedSession<'scope, 'task, IO> {
    owner: Option<ManagedOwners<'scope, 'task, IO>>,
    audio: AudioAllowancePolicy,
    supplies: Option<av_rollover_worker::Supplies>,
}

/// Exact current recording or transition owner.
#[must_use = "account for the session or rollover owners"]
pub enum ManagedOwners<'scope, 'task, IO> {
    /// Normal session retaining source and media ownership.
    Session(Box<Session<'scope, 'task, IO>>),
    /// Region-owned preflight or rollover work.
    Rollover(Box<AutomaticRollover<'scope, 'task, IO>>),
    /// A completed transition requiring explicit reconciliation.
    Halted(Box<AutomaticOwners<'scope, 'task, IO>>),
}

/// One policy-aware recording, control, or rollover decision.
#[must_use = "account for every returned recording and control result"]
pub enum ManagedStep {
    /// Normal session or audio-allowance result.
    Recording(AudioAllowanceStep),
    /// The capacity boundary remains held and needs successor stores.
    SuppliesRequired {
        /// Exact predecessor capacity signal.
        need: super::av_worker::RolloverNeed,
        /// Complete control result while media stayed paused.
        control: super::supervisor::Step,
    },
    /// Preflight was admitted under the supplied task authority.
    PreflightStarted,
    /// No owner or supplies were lost when the boundary could not be prepared.
    PrepareRefused,
    /// Admission was refused; explicit retry or retirement is required.
    StartRefused(av_rollover_worker::StartError),
    /// A complete control or worker decision from the rollover driver.
    Rollover(AutomaticStep),
    /// A verified successor returned the original session.
    Resumed(RootLedgerReceipt),
    /// The transition halted with all owners retained for reconciliation.
    Halted,
    /// An invariant-preserving owner transfer could not be completed.
    OwnershipUnavailable,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> ManagedSession<'scope, 'task, IO> {
    /// Attach caller-owned policy and optionally pre-provisioned stores.
    pub fn new(session: Session<'scope, 'task, IO>, audio: AudioAllowancePolicy) -> Self {
        Self {
            owner: Some(ManagedOwners::Session(Box::new(session))),
            audio,
            supplies: None,
        }
    }

    /// Borrow the existing controller without transferring the recording or
    /// storage owners. Control is unavailable after a halted transition.
    pub fn control(
        &mut self,
    ) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        match self.owner.as_mut()? {
            ManagedOwners::Session(session) => session.control(),
            ManagedOwners::Rollover(rollover) => {
                let supervisor = match rollover.stage.as_mut()? {
                    AutomaticOwners::Preflight(preflight) => preflight.deferred.control_supervisor(),
                    AutomaticOwners::Rollover(rollover) => rollover.background.control_supervisor(),
                    AutomaticOwners::PreflightHalted(_) | AutomaticOwners::Finished(_) => return None,
                };
                Some(super::recording_session::Control::from_supervisor(supervisor))
            }
            ManagedOwners::Halted(_) => None,
        }
    }

    /// Check the current recording session's controller clocks without I/O.
    pub(super) fn clocks_match(
        &mut self,
        owner: &MeteredClock<'_, '_>,
        clock: &MeteredClock<'_, '_>,
    ) -> bool {
        match self.owner.as_mut() {
            Some(ManagedOwners::Session(session)) => session.clocks_match(owner, clock),
            _ => false,
        }
    }

    /// Stage one fresh successor without overwriting an existing one.
    /// The caller remains responsible for creating and authorizing the stores.
    pub fn provide(
        &mut self,
        supplies: av_rollover_worker::Supplies,
    ) -> Result<(), av_rollover_worker::Supplies> {
        if self.supplies.is_some() || matches!(self.owner, None | Some(ManagedOwners::Halted(_))) {
            return Err(supplies);
        }
        self.supplies = Some(supplies);
        Ok(())
    }

    /// Retry a previously refused worker admission under current authority.
    pub fn retry_start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        match self.owner.as_mut() {
            Some(ManagedOwners::Rollover(rollover)) => {
                rollover.start(task, cx, clock, resource, cost)
            }
            _ => Err(av_rollover_worker::StartError::Fenced),
        }
    }

    /// Advance one owned stage. The prior session result is always delivered
    /// before a later call consumes its retained capacity signal.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: super::source_coordinator::ArchiveAdmission<'_>,
        source_archive: super::source_coordinator::ArchiveAdmission<'_>,
    ) -> ManagedStep {
        let need = match self.owner.as_mut() {
            Some(ManagedOwners::Session(session))
                if owner.cx.checkpoint().is_ok()
                    && owner.clock.matches(owner.task, owner.cx)
                    && owner.clock.matches(task, cx)
                    && clock.matches(task, cx)
                    && !wait.is_zero()
                    && wait <= Duration::from_secs(30) =>
            {
                session.ready_rollover(&owner.clock, &clock)
            }
            _ => None,
        };
        if let Some(need) = need {
            if self.supplies.is_none() {
                if let Some(ManagedOwners::Session(session)) = self.owner.as_mut() {
                    return match session.rollover_control(owner, operation, wait).await {
                        Some(control) => ManagedStep::SuppliesRequired { need, control },
                        None => ManagedStep::OwnershipUnavailable,
                    };
                }
                return ManagedStep::OwnershipUnavailable;
            }
            let session = match self.owner.take() {
                Some(ManagedOwners::Session(session)) => session,
                other => {
                    self.owner = other;
                    return ManagedStep::OwnershipUnavailable;
                }
            };
            let Some(supplies) = self.supplies.take() else {
                self.owner = Some(ManagedOwners::Session(session));
                return ManagedStep::OwnershipUnavailable;
            };
            match AutomaticRollover::prepare(*session, supplies) {
                Ok(mut rollover) => {
                    let result =
                        rollover.start(task, cx, clock, av_archive.resource, av_archive.cost);
                    self.owner = Some(ManagedOwners::Rollover(Box::new(rollover)));
                    return match result {
                        Ok(()) => ManagedStep::PreflightStarted,
                        Err(error) => ManagedStep::StartRefused(error),
                    };
                }
                Err(refusal) => {
                    self.owner = Some(ManagedOwners::Session(Box::new(refusal.session)));
                    self.supplies = Some(refusal.supplies);
                    return ManagedStep::PrepareRefused;
                }
            }
        }
        match self.owner.as_mut() {
            Some(ManagedOwners::Session(session)) => ManagedStep::Recording(
                session
                    .step_with_audio_allowance(
                        &mut self.audio,
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
            ),
            Some(ManagedOwners::Rollover(rollover)) => {
                let decision = rollover
                    .step(
                        owner,
                        operation,
                        wait,
                        task,
                        cx,
                        clock,
                        av_archive.resource,
                        av_archive.cost,
                    )
                    .await;
                if !matches!(decision, AutomaticStep::Finished) {
                    return ManagedStep::Rollover(decision);
                }
                let rollover = match self.owner.take() {
                    Some(ManagedOwners::Rollover(rollover)) => rollover,
                    other => {
                        self.owner = other;
                        return ManagedStep::OwnershipUnavailable;
                    }
                };
                match rollover.into_owners() {
                    Some(AutomaticOwners::Finished(Finished::Resumed { session, receipt })) => {
                        self.owner = Some(ManagedOwners::Session(Box::new(session)));
                        ManagedStep::Resumed(receipt)
                    }
                    Some(other) => {
                        self.owner = Some(ManagedOwners::Halted(Box::new(other)));
                        ManagedStep::Halted
                    }
                    None => ManagedStep::OwnershipUnavailable,
                }
            }
            Some(ManagedOwners::Halted(_)) => ManagedStep::Halted,
            None => ManagedStep::OwnershipUnavailable,
        }
    }

    /// Request cancellation of a rollover; it must still be driven or joined.
    pub fn abort(&self) {
        if let Some(ManagedOwners::Rollover(rollover)) = self.owner.as_ref() {
            rollover.abort();
        }
    }

    /// Join an admitted rollover stage without discarding its completion.
    pub async fn join(&mut self) -> bool {
        match self.owner.as_mut() {
            Some(ManagedOwners::Rollover(rollover)) => rollover.join().await,
            _ => false,
        }
    }

    /// Recover the exact current owner, policy and any unused staged stores.
    pub fn into_parts(
        self,
    ) -> (
        Option<ManagedOwners<'scope, 'task, IO>>,
        AudioAllowancePolicy,
        Option<av_rollover_worker::Supplies>,
    ) {
        (self.owner, self.audio, self.supplies)
    }
}

/// Exact session state while a single A/V rollover is supervised.
#[must_use = "drive or cancel and drain the rollover, then account for all owners"]
pub struct RecordingRollover<'scope, 'task, IO> {
    coordinator: Coordinator,
    background: BackgroundRollover<'scope, 'task, IO>,
}

/// A recording session whose prior lineage is being checked on a worker.
#[must_use = "drain the preflight and retain the session and supplies"]
pub struct RecordingRolloverPreflight<'scope, 'task, IO> {
    coordinator: Coordinator,
    deferred: av_unknown_worker_guard::DeferredPause<'scope, 'task, IO>,
    supplies: av_rollover_worker::Supplies,
}

/// A preflight preparation refusal preserves the unchanged session and stores.
#[must_use]
pub struct PreflightPrepareRefusal<'scope, 'task, IO> {
    /// Unchanged source-aware session.
    pub session: Session<'scope, 'task, IO>,
    /// Unused successor stores and read policy.
    pub supplies: av_rollover_worker::Supplies,
}

/// Exact outcome of a drained recording-session preflight.
#[must_use = "continue the rollover or reconcile its returned owners"]
pub enum PreflightFinished<'scope, 'task, IO> {
    /// A checked predecessor is ready for the existing rollover worker.
    Ready(RecordingRollover<'scope, 'task, IO>),
    /// Prior custody failed, was cancelled, or is indeterminate.
    Unresolved {
        /// Still-owned separate-source coordinator.
        coordinator: Coordinator,
        /// Controller, original archive owner, and exact preflight reason.
        pause: av_unknown_worker_guard::DeferredPauseUnresolved<'scope, 'task, IO>,
        /// Unused successor stores and read policy.
        supplies: av_rollover_worker::Supplies,
    },
    /// The checked predecessor did not match the resources being attached.
    Binding {
        /// Still-owned separate-source coordinator.
        coordinator: Coordinator,
        /// Paused guard and transition inputs, preserved for reconciliation.
        refusal: av_unknown_worker_guard::BackgroundRefusal<'scope, 'task, IO>,
    },
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>
    RecordingRolloverPreflight<'scope, 'task, IO>
{
    /// Transfer a capacity-stopped session without reading its switch storage.
    pub fn prepare(
        session: Session<'scope, 'task, IO>,
        supplies: av_rollover_worker::Supplies,
    ) -> Result<Self, PreflightPrepareRefusal<'scope, 'task, IO>> {
        let (coordinator, phase) = session.into_parts();
        if coordinator.source_status() != source_worker::Status::Idle {
            return Err(PreflightPrepareRefusal {
                session: Session::from_parts(coordinator, phase),
                supplies,
            });
        }
        let guard = match phase {
            Phase::Recording(guard) if guard.rollover_need().is_some() => guard,
            phase => {
                return Err(PreflightPrepareRefusal {
                    session: Session::from_parts(coordinator, phase),
                    supplies,
                });
            }
        };
        match (*guard).defer_rollover_pause() {
            Ok(deferred) => Ok(Self {
                coordinator,
                deferred,
                supplies,
            }),
            Err(guard) => Err(PreflightPrepareRefusal {
                session: Session::from_recording(coordinator, Box::new(guard)),
                supplies,
            }),
        }
    }

    /// Start the region-owned custody check.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        self.deferred.start(task, cx, clock, resource, cost)
    }
    /// Service control and retain any completed preflight result.
    pub async fn drive(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> BackgroundDrive {
        self.deferred.drive(owner, operation, wait).await
    }
    /// Request cancellation; the preflight must still be joined.
    pub fn abort(&self) {
        self.deferred.abort();
    }
    /// Whether the runtime coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.deferred.cancellation_observed()
    }
    /// Join the actual preflight without releasing its owners.
    pub async fn join(&mut self) -> bool {
        self.deferred.join().await
    }
    /// Recover the original session and stores after a pre-start refusal.
    pub fn into_unstarted(
        self,
    ) -> Result<(Session<'scope, 'task, IO>, av_rollover_worker::Supplies), Self> {
        let Self {
            coordinator,
            deferred,
            supplies,
        } = self;
        match deferred.into_unstarted() {
            Ok(guard) => Ok((
                Session::from_recording(coordinator, Box::new(guard)),
                supplies,
            )),
            Err(deferred) => Err(Self {
                coordinator,
                deferred,
                supplies,
            }),
        }
    }
    /// Transfer a verified predecessor to the existing background rollover.
    pub fn finish(self) -> Result<PreflightFinished<'scope, 'task, IO>, Self> {
        let Self {
            coordinator,
            deferred,
            supplies,
        } = self;
        match deferred.finish() {
            Ok(av_unknown_worker_guard::DeferredPauseFinish::Ready { paused, previous }) => {
                match paused.into_background(supplies.bind(previous)) {
                    Ok(background) => Ok(PreflightFinished::Ready(RecordingRollover {
                        coordinator,
                        background,
                    })),
                    Err(refusal) => Ok(PreflightFinished::Binding {
                        coordinator,
                        refusal,
                    }),
                }
            }
            Ok(av_unknown_worker_guard::DeferredPauseFinish::Unresolved(pause)) => {
                Ok(PreflightFinished::Unresolved {
                    coordinator,
                    pause,
                    supplies,
                })
            }
            Err(deferred) => Err(Self {
                coordinator,
                deferred,
                supplies,
            }),
        }
    }
}

/// A completed switch either returns the session or the unresolved owners.
#[must_use = "continue the session or reconcile the unresolved transition"]
pub enum Finished<'scope, 'task, IO> {
    /// Matching successor verified and attached to the original session.
    Resumed {
        /// Session with its separate-source coordinator and pending segment.
        session: Session<'scope, 'task, IO>,
        /// Actual replay receipt.
        receipt: RootLedgerReceipt,
    },
    /// The transition did not qualify for automatic resume.
    Unresolved {
        /// Still-owned, idle separate-source coordinator.
        coordinator: Coordinator,
        /// Pending media and exact transition outcome.
        rollover: av_unknown_worker_guard::BackgroundUnresolved<'scope, 'task, IO>,
    },
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> RecordingRollover<'scope, 'task, IO> {
    /// Transfer a session only when its separate source is idle and the A/V
    /// scheduler has retained a capacity signal. Later generations may
    /// synchronously revalidate retained switch custody while pausing.
    pub fn prepare(
        session: Session<'scope, 'task, IO>,
        supplies: av_rollover_worker::Supplies,
    ) -> Result<Self, PrepareRefusal<'scope, 'task, IO>> {
        let (coordinator, phase) = session.into_parts();
        if coordinator.source_status() != source_worker::Status::Idle {
            return Err(PrepareRefusal::NotReady {
                session: Session::from_parts(coordinator, phase),
                supplies,
            });
        }
        let guard = match phase {
            Phase::Recording(guard) if guard.rollover_need().is_some() => guard,
            phase => {
                return Err(PrepareRefusal::NotReady {
                    session: Session::from_parts(coordinator, phase),
                    supplies,
                });
            }
        };
        let (paused, previous) = match (*guard).pause_rollover() {
            Ok(parts) => parts,
            Err(guard) => {
                return Err(PrepareRefusal::NotReady {
                    session: Session::from_recording(coordinator, Box::new(guard)),
                    supplies,
                });
            }
        };
        match paused.into_background(supplies.bind(previous)) {
            Ok(background) => Ok(Self {
                coordinator,
                background,
            }),
            Err(refusal) => Err(PrepareRefusal::Binding {
                coordinator,
                refusal,
            }),
        }
    }

    /// Start the bounded region-owned transition under the recording task.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        self.background.start(task, cx, clock, resource, cost)
    }

    /// Drive control messages while the blocking storage work is active.
    pub async fn drive(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> BackgroundDrive {
        self.background.drive(owner, operation, wait).await
    }

    /// Request cancellation; the operation still needs to be joined.
    pub fn abort(&self) {
        self.background.abort();
    }
    /// Whether the runtime coordinator observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.background.cancellation_observed()
    }
    /// Join without discarding the exact outcome.
    pub async fn join(&mut self) -> bool {
        self.background.join().await
    }

    /// Return the resumed session or the exact unresolved transition. A still
    /// running or unjoined worker returns this owner unchanged.
    pub fn finish(self) -> Result<Finished<'scope, 'task, IO>, Self> {
        let Self {
            coordinator,
            background,
        } = self;
        match background.finish() {
            Ok(BackgroundFinish::Resumed { guard, receipt }) => Ok(Finished::Resumed {
                session: Session::from_recording(coordinator, Box::new(guard)),
                receipt,
            }),
            Ok(BackgroundFinish::Unresolved(rollover)) => Ok(Finished::Unresolved {
                coordinator,
                rollover,
            }),
            Err(background) => Err(Self {
                coordinator,
                background,
            }),
        }
    }

    /// Recover the paused guard and unused inputs after a refused start. This
    /// method does not classify or retry a transition that entered the pool.
    pub fn into_unstarted(
        self,
    ) -> Result<
        (
            Coordinator,
            av_unknown_worker_guard::PausedRollover<'scope, 'task, IO>,
            av_rollover_worker::Inputs,
        ),
        Self,
    > {
        let Self {
            coordinator,
            background,
        } = self;
        match background.into_unstarted() {
            Ok((paused, inputs)) => Ok((coordinator, paused, inputs)),
            Err(background) => Err(Self {
                coordinator,
                background,
            }),
        }
    }
}

/// One owner for both bounded rollover workers and the source-aware session.
#[must_use = "drive or cancel and drain the active stage, then retain its outcome"]
pub struct AutomaticRollover<'scope, 'task, IO> {
    stage: Option<AutomaticOwners<'scope, 'task, IO>>,
}

/// Exact owners retained during or after the two-stage rollover.
#[must_use = "account for the returned session, workers, and any effects"]
pub enum AutomaticOwners<'scope, 'task, IO> {
    /// Prior-custody check and unconsumed successor supplies.
    Preflight(RecordingRolloverPreflight<'scope, 'task, IO>),
    /// Successor transition and original source coordinator.
    Rollover(RecordingRollover<'scope, 'task, IO>),
    /// Preflight ended without producing a usable successor.
    PreflightHalted(PreflightFinished<'scope, 'task, IO>),
    /// The transition drained and returned its full outcome.
    Finished(Finished<'scope, 'task, IO>),
}

/// One bounded decision from the automatic two-stage driver.
#[must_use = "account for control results and any refusal"]
pub enum AutomaticStep {
    /// The current stage has not been started.
    NotRunning,
    /// One complete camera-control result; the next step checks the worker.
    Control(super::supervisor::Step),
    /// The verified preflight automatically started successor work.
    RolloverStarted,
    /// Starting successor work was refused; the owner remains recoverable.
    StartRefused(av_rollover_worker::StartError),
    /// Preflight or the successor worker finished; take the retained outcome.
    Finished,
    /// An internal owner could not be transferred; retain and inspect it.
    OwnershipUnavailable,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> AutomaticRollover<'scope, 'task, IO> {
    /// Bind caller-supplied stores to a capacity-stopped source-aware session.
    /// This performs no storage I/O or camera management write.
    pub fn prepare(
        session: Session<'scope, 'task, IO>,
        supplies: av_rollover_worker::Supplies,
    ) -> Result<Self, PreflightPrepareRefusal<'scope, 'task, IO>> {
        RecordingRolloverPreflight::prepare(session, supplies).map(|preflight| Self {
            stage: Some(AutomaticOwners::Preflight(preflight)),
        })
    }

    /// Explicitly start the current stage. A failed admission is not retried
    /// by `step`; a caller may inspect the error and choose to try again.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        match self.stage.as_mut() {
            Some(AutomaticOwners::Preflight(preflight)) => {
                preflight.start(task, cx, clock, resource, cost)
            }
            Some(AutomaticOwners::Rollover(rollover)) => {
                rollover.start(task, cx, clock, resource, cost)
            }
            _ => Err(av_rollover_worker::StartError::Fenced),
        }
    }

    /// Drive one control or completion decision. After a verified preflight,
    /// this starts the successor worker under the supplied current authority.
    /// The owner remains inside `self` across the await.
    pub async fn step<'a, 'b>(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> AutomaticStep {
        let decision = match self.stage.as_mut() {
            Some(AutomaticOwners::Preflight(preflight)) => {
                preflight.drive(owner, operation, wait).await
            }
            Some(AutomaticOwners::Rollover(rollover)) => {
                rollover.drive(owner, operation, wait).await
            }
            Some(AutomaticOwners::PreflightHalted(_) | AutomaticOwners::Finished(_)) => {
                return AutomaticStep::Finished;
            }
            None => return AutomaticStep::OwnershipUnavailable,
        };
        match decision {
            BackgroundDrive::NotRunning => AutomaticStep::NotRunning,
            BackgroundDrive::Control { step, .. } => AutomaticStep::Control(step),
            BackgroundDrive::Completed => {
                let Some(stage) = self.stage.take() else {
                    return AutomaticStep::OwnershipUnavailable;
                };
                match stage {
                    AutomaticOwners::Preflight(preflight) => match preflight.finish() {
                        Ok(PreflightFinished::Ready(mut rollover)) => {
                            let result = rollover.start(task, cx, clock, resource, cost);
                            self.stage = Some(AutomaticOwners::Rollover(rollover));
                            match result {
                                Ok(()) => AutomaticStep::RolloverStarted,
                                Err(error) => AutomaticStep::StartRefused(error),
                            }
                        }
                        Ok(halted) => {
                            self.stage = Some(AutomaticOwners::PreflightHalted(halted));
                            AutomaticStep::Finished
                        }
                        Err(preflight) => {
                            self.stage = Some(AutomaticOwners::Preflight(preflight));
                            AutomaticStep::OwnershipUnavailable
                        }
                    },
                    AutomaticOwners::Rollover(rollover) => match rollover.finish() {
                        Ok(finished) => {
                            self.stage = Some(AutomaticOwners::Finished(finished));
                            AutomaticStep::Finished
                        }
                        Err(rollover) => {
                            self.stage = Some(AutomaticOwners::Rollover(rollover));
                            AutomaticStep::OwnershipUnavailable
                        }
                    },
                    other => {
                        self.stage = Some(other);
                        AutomaticStep::Finished
                    }
                }
            }
        }
    }

    /// Request cancellation of the current worker; it must still be joined.
    pub fn abort(&self) {
        match self.stage.as_ref() {
            Some(AutomaticOwners::Preflight(preflight)) => preflight.abort(),
            Some(AutomaticOwners::Rollover(rollover)) => rollover.abort(),
            _ => (),
        }
    }
    /// Whether the current worker coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        match self.stage.as_ref() {
            Some(AutomaticOwners::Preflight(preflight)) => preflight.cancellation_observed(),
            Some(AutomaticOwners::Rollover(rollover)) => rollover.cancellation_observed(),
            _ => false,
        }
    }
    /// Join the currently running worker while retaining the complete result.
    pub async fn join(&mut self) -> bool {
        match self.stage.as_mut() {
            Some(AutomaticOwners::Preflight(preflight)) => preflight.join().await,
            Some(AutomaticOwners::Rollover(rollover)) => rollover.join().await,
            _ => false,
        }
    }

    /// Recover the original session and stores before the first stage starts.
    pub fn into_unstarted(
        self,
    ) -> Result<(Session<'scope, 'task, IO>, av_rollover_worker::Supplies), Self> {
        match self.stage {
            Some(AutomaticOwners::Preflight(preflight)) => match preflight.into_unstarted() {
                Ok(parts) => Ok(parts),
                Err(preflight) => Err(Self {
                    stage: Some(AutomaticOwners::Preflight(preflight)),
                }),
            },
            stage => Err(Self { stage }),
        }
    }

    /// Transfer the exact current owner, including unfinished or failed work.
    pub fn into_owners(self) -> Option<AutomaticOwners<'scope, 'task, IO>> {
        self.stage
    }
}
