#![forbid(unsafe_code)]
//! Region-owned blocking work for a single explicit A/V history transition.
//!
//! The pending media remains in a separately retained state if the closure
//! panics. An uncertain switch or panic requires reconciliation; this worker
//! neither discovers storage nor resumes a camera by itself.

use std::sync::{Arc, Mutex};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_geometry::WorkBudget;
use fss_publication::RootLedgerReceipt;
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    effect_journal::{EffectJournalStore, PinRetainedEffectJournal},
    execution::{ExecutionError, TaskCx},
};

use super::{archive, av_worker, metered::MeteredClock};

/// Exclusive inputs for one caller-authorized transition. The stores must be
/// fresh, and the switch retainer must be supplied by the operator's policy.
pub struct Inputs {
    /// Exact settled predecessor.
    pub previous: archive::journal::rollover::Previous,
    /// Empty successor publication store.
    pub next_journal: Box<dyn EffectJournalStore>,
    /// Empty successor keeper store.
    pub next_keeper: Box<dyn EffectJournalStore>,
    /// Empty switch with separately supplied pin custody.
    pub switch: PinRetainedEffectJournal,
    /// Current read authorization, checked during replay.
    pub read: Arc<dyn archive::ReadAuthority + Send + Sync>,
    /// Limits for the exact confirmed A/V graph.
    pub object_limits: archive::StagedAvLimits,
    /// Replay work budget, bounded to 100 billion units.
    pub work_limit: u64,
}

/// Fresh stores and policy for one rollover, before the guard supplies its
/// exact predecessor. Constructing this value performs no camera operation.
pub struct Supplies {
    /// Empty successor publication store.
    pub next_journal: Box<dyn EffectJournalStore>,
    /// Empty successor keeper store.
    pub next_keeper: Box<dyn EffectJournalStore>,
    /// Empty switch with separately supplied pin custody.
    pub switch: PinRetainedEffectJournal,
    /// Current read authorization.
    pub read: Arc<dyn archive::ReadAuthority + Send + Sync>,
    /// Bounds for the confirmed A/V graph.
    pub object_limits: archive::StagedAvLimits,
    /// Replay work budget, bounded to 100 billion units.
    pub work_limit: u64,
}

impl Supplies {
    /// Bind supplies to the exact predecessor released by the paused guard.
    pub fn bind(self, previous: archive::journal::rollover::Previous) -> Inputs {
        Inputs {
            previous,
            next_journal: self.next_journal,
            next_keeper: self.next_keeper,
            switch: self.switch,
            read: self.read,
            object_limits: self.object_limits,
            work_limit: self.work_limit,
        }
    }
}
impl Inputs {
    /// Recover a predecessor and unused supplies without starting storage work.
    pub fn into_parts(self) -> (archive::journal::rollover::Previous, Supplies) {
        (
            self.previous,
            Supplies {
                next_journal: self.next_journal,
                next_keeper: self.next_keeper,
                switch: self.switch,
                read: self.read,
                object_limits: self.object_limits,
                work_limit: self.work_limit,
            },
        )
    }
}

/// Actual transition outcome after the blocking closure has drained.
#[must_use = "retain or reconcile all returned transition owners"]
pub enum Outcome {
    /// Work did not begin; inputs remain with the worker.
    NotStarted,
    /// Cancellation was observed before any transition input was taken.
    CancelledBefore,
    /// Seeding failed; candidate storage may have been partially written.
    BeginRefused(archive::journal::rollover::BeginRefusal),
    /// Cancellation occurred with a staged, uncommitted successor.
    CancelledStaged {
        /// Uncommitted successor and predecessor.
        staged: archive::journal::rollover::Staged,
        /// Unused switch.
        switch: PinRetainedEffectJournal,
    },
    /// Switch commit refused or has an indeterminate outcome.
    CommitRefused(archive::journal::rollover::CommitError),
    /// Cancellation occurred after the switch was retained, before replay.
    CancelledActive(archive::journal::rollover::Active),
    /// A switch exists, but its confirmed root was not verified.
    ReplayRefused {
        /// Transition that must remain owned for reconciliation.
        active: archive::journal::rollover::Active,
        /// Send-safe classification, preserving any actual publication receipt.
        error: ReplayFailure,
    },
    /// Exact confirmed A/V root was replayed under the successor.
    Replayed {
        /// Verified successor and retained predecessor custody.
        active: archive::journal::rollover::Active,
        /// Actual root-ledger receipt.
        receipt: RootLedgerReceipt,
    },
    /// The replay succeeded, but a later custody check refused attachment.
    AttachRefused {
        /// Transition retained for reconciliation.
        active: archive::journal::rollover::Active,
        /// Actual replay receipt.
        receipt: RootLedgerReceipt,
    },
    /// Replay and attachment custody checks completed on the worker.
    Prepared {
        /// Opaque checked successor and retained lineage.
        attachment: av_worker::PreparedUnknownTimeAttachment,
        /// Actual replay receipt.
        receipt: RootLedgerReceipt,
    },
    /// The closure panicked; transition state and disk effects are uncertain.
    Panicked,
    /// Worker or coordinator state could not be classified.
    Indeterminate,
}

/// Send-safe replay failure. Opaque storage errors are classified without
/// carrying their non-Send inner error across the blocking boundary.
#[derive(Debug)]
pub enum ReplayFailure {
    /// The switch or history could not be verified.
    History(archive::journal::Error),
    /// The existing confirmed-history preconditions failed.
    ConfirmedHistory,
    /// The confirmed graph could not be read and verified.
    Readback(ArchiveFailure),
    /// Publication candidate could not be accepted.
    Candidate,
    /// The journal refused before publication.
    BeforePublication(archive::journal::Error),
    /// Archive publication failed or is uncertain.
    Archive(ArchiveFailure),
    /// Publication produced a receipt before confirmation failed.
    AfterPublication {
        /// Actual receipt retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Journal or anchor refusal.
        source: archive::journal::Error,
    },
    /// Replay returned a receipt other than already-ledgered.
    UnexpectedReceipt(Box<RootLedgerReceipt>),
}

/// Payload-free archive error classification; opaque storage details stay local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFailure {
    /// Policy denied the operation.
    Denied,
    /// Capture bounds were unavailable.
    UnknownCapture,
    /// A configured limit was reached.
    Limit,
    /// A committed root was not found.
    NotCommitted,
    /// History requires recovery.
    RecoveryRequired,
    /// A deletion tombstone refused the operation.
    Tombstoned,
    /// The operation was cancelled.
    Cancelled,
    /// Content or scope did not match.
    Mismatch,
    /// Work accounting refused the operation.
    Work,
    /// The caller's bounded replay work allowance was exhausted.
    BudgetExhausted,
    /// Storage failed or is indeterminate; opaque details are not transferred.
    Storage,
}

impl From<archive::Error> for ArchiveFailure {
    fn from(error: archive::Error) -> Self {
        match error {
            archive::Error::Denied => Self::Denied,
            archive::Error::UnknownCapture => Self::UnknownCapture,
            archive::Error::Limit => Self::Limit,
            archive::Error::NotCommitted => Self::NotCommitted,
            archive::Error::RecoveryRequired => Self::RecoveryRequired,
            archive::Error::Tombstoned => Self::Tombstoned,
            archive::Error::Cancelled => Self::Cancelled,
            archive::Error::Mismatch => Self::Mismatch,
            archive::Error::Work(fss_geometry::GeometryError::Cancelled) => Self::Cancelled,
            archive::Error::Work(fss_geometry::GeometryError::BudgetExhausted) => Self::BudgetExhausted,
            archive::Error::Work(_) => Self::Work,
            archive::Error::Storage(_) => Self::Storage,
        }
    }
}
impl From<archive::journal::rollover::AvReplayError> for ReplayFailure {
    fn from(error: archive::journal::rollover::AvReplayError) -> Self {
        use archive::journal::rollover::AvReplayError as E;
        use archive::{ConfirmedAvReplayError as C, UnknownTimePublishError as P};
        match error {
            E::History(error) => Self::History(error),
            E::Replay(C::History) => Self::ConfirmedHistory,
            E::Replay(C::Readback(error)) => Self::Readback(error.into()),
            E::Replay(C::Publication(P::Candidate)) => Self::Candidate,
            E::Replay(C::Publication(P::BeforePublication(error))) => {
                Self::BeforePublication(error)
            }
            E::Replay(C::Publication(P::Archive(error))) => Self::Archive(error.into()),
            E::Replay(C::Publication(P::AfterPublication { receipt, source })) => {
                Self::AfterPublication { receipt, source }
            }
            E::UnexpectedReceipt(receipt) => Self::UnexpectedReceipt(receipt),
        }
    }
}

/// A drained task result, separate from the transition outcome.
pub struct Completion {
    /// Runtime result, which may differ from the storage outcome.
    pub runtime: Result<(), JoinError>,
    /// Observed transition outcome.
    pub outcome: Outcome,
}

struct State {
    resources: av_worker::UnknownTimeRolloverResources,
    inputs: Option<Inputs>,
    result: Option<Outcome>,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One bounded operation with no detached worker or inline fallback.
#[must_use = "drain the operation and recover its resources and outcome"]
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

/// Refusal before a blocking operation was started.
#[derive(Debug)]
pub enum StartError {
    /// Work is already running.
    Running,
    /// The previous result needs retirement or reconciliation.
    Fenced,
    /// No transition inputs remain.
    Empty,
    /// Work bound is invalid.
    WorkLimit,
    /// The clock is not bound to this task and context.
    Context,
    /// The task clock could not be read.
    Clock,
    /// Task or budget admission failed.
    Task(ExecutionError),
    /// Runtime-owned blocking admission failed.
    Runtime(StartFailure),
}

/// Exclusive resources returned after a drained attempt.
#[must_use = "account for the pending media and all transition owners"]
pub struct Retirement {
    /// Pending media and archive resources, retained even after a panic.
    pub resources: av_worker::UnknownTimeRolloverResources,
    /// Unconsumed inputs if the closure did not start.
    pub inputs: Option<Inputs>,
    /// True if a panic or inconsistent worker state requires reconciliation.
    pub fenced: bool,
}

struct CurrentRead<'a> {
    cx: &'a Cx,
    inner: &'a dyn archive::ReadAuthority,
}
impl archive::ReadAuthority for CurrentRead<'_> {
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool {
        self.cx.checkpoint().is_ok() && self.inner.permits(retention, root)
    }
}

impl Worker {
    /// Own the pending-media resources and caller-supplied transition inputs.
    pub fn new(resources: av_worker::UnknownTimeRolloverResources, inputs: Inputs) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                resources,
                inputs: Some(inputs),
                result: None,
            })),
            running: None,
            fenced: false,
        }
    }

    /// Admit the transition to the runtime blocking pool under task grants.
    pub fn start<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        if self.fenced {
            return Err(StartError::Fenced);
        }
        if self.running.is_some() {
            return Err(StartError::Running);
        }
        if !clock.matches(task, cx) {
            return Err(StartError::Context);
        }
        let now = clock.now().map_err(|_| StartError::Clock)?;
        {
            let state = self.state.try_lock().map_err(|_| StartError::Fenced)?;
            if state.result.is_some() {
                return Err(StartError::Fenced);
            }
            let inputs = state.inputs.as_ref().ok_or(StartError::Empty)?;
            if !(1..=100_000_000_000).contains(&inputs.work_limit) {
                return Err(StartError::WorkLimit);
            }
        }
        task.checkpoint_for(
            RuntimeGrant::ObjectPublish,
            resource,
            now,
            &BudgetVector::ZERO,
        )
        .map_err(StartError::Task)?;
        task.checkpoint_for(RuntimeGrant::ObjectStage, resource, now, cost)
            .map_err(StartError::Task)?;
        let state = Arc::clone(&self.state);
        let job: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            if child.is_cancel_requested() {
                state.result = Some(Outcome::CancelledBefore);
                return;
            }
            let Some(inputs) = state.inputs.take() else {
                return;
            };
            let Inputs {
                previous,
                next_journal,
                next_keeper,
                switch,
                read,
                object_limits,
                work_limit,
            } = inputs;
            let staged = match archive::journal::rollover::Staged::begin(
                previous,
                next_journal,
                next_keeper,
                state.resources.replay(),
            ) {
                Ok(staged) => staged,
                Err(refusal) => {
                    state.result = Some(Outcome::BeginRefused(refusal));
                    return;
                }
            };
            if child.is_cancel_requested() {
                state.result = Some(Outcome::CancelledStaged { staged, switch });
                return;
            }
            let mut active = match staged.commit(switch, state.resources.replay()) {
                Ok(active) => active,
                Err(error) => {
                    state.result = Some(Outcome::CommitRefused(error));
                    return;
                }
            };
            if child.is_cancel_requested() {
                state.result = Some(Outcome::CancelledActive(active));
                return;
            }
            let permit = CurrentRead {
                cx: &child,
                inner: read.as_ref(),
            };
            let cancel = || child.is_cancel_requested();
            let mut budget = WorkBudget::with_cancellation_probe(work_limit, &cancel);
            state.result = Some(
                match state.resources.replay_confirmed_av(
                    &mut active,
                    &permit,
                    object_limits,
                    &mut budget,
                ) {
                    Ok(receipt) if child.is_cancel_requested() => {
                        Outcome::Replayed { active, receipt }
                    }
                    Ok(receipt) => match state.resources.prepare_attachment(active) {
                        Ok(attachment) => Outcome::Prepared {
                            attachment,
                            receipt,
                        },
                        Err(active) => Outcome::AttachRefused { active, receipt },
                    },
                    Err(error) => Outcome::ReplayRefused {
                        active,
                        error: error.into(),
                    },
                },
            );
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Whether an admitted operation still requires a join.
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Request cooperative cancellation; `join` is still required.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether cancellation has reached the region-owned coordinator.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Await actual closure release and preserve the storage classification.
    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(job) => {
                drop(job);
                Outcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => state.result.take().unwrap_or_else(|| {
                    self.fenced = true;
                    Outcome::Indeterminate
                }),
                Err(_) => {
                    self.fenced = true;
                    Outcome::Indeterminate
                }
            },
            WorkOutcome::Panicked => {
                self.fenced = true;
                Outcome::Panicked
            }
            WorkOutcome::Indeterminate => {
                self.fenced = true;
                Outcome::Indeterminate
            }
        };
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover the original resources and inputs when no operation was ever
    /// admitted. Inconsistent or poisoned state is returned fenced.
    pub fn into_unstarted(self) -> Result<(av_worker::UnknownTimeRolloverResources, Inputs), Self> {
        if self.running.is_some() || self.fenced {
            return Err(self);
        }
        let Self {
            state,
            running,
            fenced,
        } = self;
        let mutex = match Arc::try_unwrap(state) {
            Ok(mutex) => mutex,
            Err(state) => {
                return Err(Self {
                    state,
                    running,
                    fenced,
                });
            }
        };
        let mut state = match mutex.into_inner() {
            Ok(state) => state,
            Err(poison) => {
                return Err(Self {
                    state: Arc::new(Mutex::new(poison.into_inner())),
                    running,
                    fenced: true,
                });
            }
        };
        if state.result.is_some() || state.inputs.is_none() {
            return Err(Self {
                state: Arc::new(Mutex::new(state)),
                running,
                fenced: true,
            });
        }
        let Some(inputs) = state.inputs.take() else {
            return Err(Self {
                state: Arc::new(Mutex::new(state)),
                running,
                fenced: true,
            });
        };
        Ok((state.resources, inputs))
    }

    /// Recover the pending media after the closure is no longer running.
    pub fn retire(self) -> Result<Retirement, Self> {
        if self.running.is_some() {
            return Err(self);
        }
        let Self {
            state,
            running,
            fenced,
        } = self;
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let state = state
                    .into_inner()
                    .unwrap_or_else(|poison| poison.into_inner());
                Ok(Retirement {
                    resources: state.resources,
                    inputs: state.inputs,
                    fenced,
                })
            }
            Err(state) => Err(Self {
                state,
                running,
                fenced,
            }),
        }
    }
}
