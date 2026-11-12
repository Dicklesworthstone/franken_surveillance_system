#![forbid(unsafe_code)]
//! Region-owned blocking work for a single explicit video-only history transition.
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
    drained_blocking::{self, Drained, WorkOutcome},
    effect_journal::PinRetainedEffectJournal,
    execution::TaskCx,
};

use super::{archive, metered::MeteredClock, video_worker};

pub use super::av_rollover_worker::{Inputs, ReplayFailure, StartError, Supplies};

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
    /// Exact confirmed video root was replayed under the successor.
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
        attachment: video_worker::PreparedAttachment,
        /// Actual replay receipt.
        receipt: RootLedgerReceipt,
    },
    /// The closure panicked; transition state and disk effects are uncertain.
    Panicked,
    /// Worker or coordinator state could not be classified.
    Indeterminate,
}

/// A drained task result, separate from the transition outcome.
pub struct Completion {
    /// Runtime result, which may differ from the storage outcome.
    pub runtime: Result<(), JoinError>,
    /// Observed transition outcome.
    pub outcome: Outcome,
}

struct State {
    resources: video_worker::RolloverResources,
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
    attachment_ready: bool,
}

/// Exclusive resources returned after a drained attempt.
#[must_use = "account for the pending media and all transition owners"]
pub struct Retirement {
    /// Pending media and archive resources, retained even after a panic.
    pub resources: video_worker::RolloverResources,
    /// Unconsumed inputs if the closure did not start.
    pub inputs: Option<Inputs>,
    /// True if a panic or inconsistent worker state requires reconciliation.
    pub fenced: bool,
    attachment_ready: bool,
}

/// Failed attachment preserves the drained transition and successor.
#[must_use]
pub struct AttachRefusal {
    /// Original drained resources and any unused inputs.
    pub retirement: Retirement,
    /// Successor whose attachment needs reconciliation.
    pub attachment: video_worker::PreparedAttachment,
}

impl Retirement {
    /// Attach a prepared successor only after a classified, unfenced drain.
    pub fn attach(
        self,
        attachment: video_worker::PreparedAttachment,
    ) -> Result<video_worker::Worker, AttachRefusal> {
        if self.fenced || self.inputs.is_some() || !self.attachment_ready {
            return Err(AttachRefusal {
                retirement: self,
                attachment,
            });
        }
        match self.resources.attach_prepared(attachment) {
            Ok(worker) => Ok(worker),
            Err(refusal) => Err(AttachRefusal {
                retirement: Retirement {
                    resources: refusal.resources,
                    inputs: None,
                    fenced: false,
                    attachment_ready: true,
                },
                attachment: refusal.attachment,
            }),
        }
    }
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
    pub fn new(resources: video_worker::RolloverResources, inputs: Inputs) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                resources,
                inputs: Some(inputs),
                result: None,
            })),
            running: None,
            fenced: false,
            attachment_ready: false,
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
                match state.resources.replay_confirmed_video(
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
        self.attachment_ready =
            receipt.runtime.is_ok() && matches!(&outcome, Outcome::Prepared { .. });
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover the original resources and inputs when no operation was ever
    /// admitted. Inconsistent or poisoned state is returned fenced.
    pub fn into_unstarted(self) -> Result<(video_worker::RolloverResources, Inputs), Self> {
        if self.running.is_some() || self.fenced {
            return Err(self);
        }
        let Self {
            state,
            running,
            fenced,
            attachment_ready,
        } = self;
        let mutex = match Arc::try_unwrap(state) {
            Ok(mutex) => mutex,
            Err(state) => {
                return Err(Self {
                    state,
                    running,
                    fenced,
                    attachment_ready,
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
                    attachment_ready: false,
                });
            }
        };
        if state.result.is_some() || state.inputs.is_none() {
            return Err(Self {
                state: Arc::new(Mutex::new(state)),
                running,
                fenced: true,
                attachment_ready: false,
            });
        }
        let Some(inputs) = state.inputs.take() else {
            return Err(Self {
                state: Arc::new(Mutex::new(state)),
                running,
                fenced: true,
                attachment_ready: false,
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
            attachment_ready,
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
                    attachment_ready,
                })
            }
            Err(state) => Err(Self {
                state,
                running,
                fenced,
                attachment_ready,
            }),
        }
    }
}
