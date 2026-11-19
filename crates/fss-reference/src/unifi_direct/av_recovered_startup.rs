#![forbid(unsafe_code)]
//! Region-owned, cancellation-drained recovered A/V custody verification.
//!
//! The exact archive resources stay in this worker while its blocking closure
//! verifies retained history. A successful result is an observation, not a
//! reservation or camera authority; publication rechecks the custody later.

use std::sync::{Arc, Mutex};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    execution::{ExecutionError, TaskCx},
};

use super::{archive, av_unknown_worker_guard::BootstrapResources, metered::MeteredClock};

/// Result of the drained custody check.
#[must_use]
pub enum Outcome {
    /// The exact current lineage passed its storage check.
    Verified,
    /// The retained history or its current binding was not accepted.
    Refused(archive::journal::Error),
    /// Cancellation was observed before a verification could be committed.
    Cancelled,
    /// The blocking closure was never started.
    NotStarted,
    /// The closure panicked; resources require reconciliation.
    Panicked,
    /// The worker could not establish a complete outcome.
    Indeterminate,
}

/// Independent task and custody outcomes after drain.
#[must_use]
pub struct Completion {
    /// The runtime's actual terminal result.
    pub runtime: Result<(), JoinError>,
    /// The custody check's own outcome.
    pub outcome: Outcome,
}

/// A start failure leaves all archive resources with the worker.
#[derive(Debug)]
pub enum StartError {
    /// A previous attempt has not drained.
    Running,
    /// This owner requires reconciliation or has an uncollected outcome.
    Fenced,
    /// Task, runtime and clock bindings disagree.
    Context,
    /// The metered clock refused.
    Clock,
    /// The task did not authorize this archive work.
    Task(ExecutionError),
    /// The runtime did not admit the blocking operation.
    Runtime(StartFailure),
}

/// Retired resources and whether their owner needs reconciliation.
#[must_use = "retain or reconcile the exact returned archive owners"]
pub struct Retirement {
    /// Exact archive resources, including any retained rollover custody.
    pub resources: Box<BootstrapResources>,
    /// An uncertain worker result prevents use as a verified startup.
    pub fenced: bool,
}

struct State {
    resources: Box<BootstrapResources>,
    outcome: Option<Outcome>,
    approved: bool,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// Holds the original resources while a bounded blocking check runs.
#[must_use = "join the exact attempt and recover the archive owners"]
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

impl Worker {
    /// Attach recovered resources; fresh resources are returned unchanged.
    pub fn new(mut resources: Box<BootstrapResources>) -> Result<Self, Box<BootstrapResources>> {
        let Some(custody) = resources.rollover_custody.as_mut() else { return Err(resources); };
        custody.invalidate_startup_verification();
        Ok(Self {
            state: Arc::new(Mutex::new(State { resources, outcome: None, approved: false })),
            running: None,
            fenced: false,
        })
    }

    /// Start one task-admitted blocking check with no inline fallback.
    pub fn start<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        if self.fenced { return Err(StartError::Fenced); }
        if self.running.is_some() { return Err(StartError::Running); }
        if !clock.matches(task, cx) { return Err(StartError::Context); }
        let now = clock.now().map_err(|_| StartError::Clock)?;
        {
            let state = self.state.try_lock().map_err(|_| StartError::Fenced)?;
            if state.outcome.is_some() || state.approved { return Err(StartError::Fenced); }
        }
        task.checkpoint_for(RuntimeGrant::ObjectPublish, resource, now, &BudgetVector::ZERO)
            .map_err(StartError::Task)?;
        task.checkpoint_for(RuntimeGrant::ObjectStage, resource, now, cost)
            .map_err(StartError::Task)?;
        let state = Arc::clone(&self.state);
        let job: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else { return; };
            let BootstrapResources { journal, keeper, replay, rollover_custody, .. } = &mut *state.resources;
            let Some(custody) = rollover_custody.as_mut() else {
                state.outcome = Some(Outcome::Refused(archive::journal::Error::Invalid));
                return;
            };
            custody.invalidate_startup_verification();
            if child.is_cancel_requested() {
                state.outcome = Some(Outcome::Cancelled);
                return;
            }
            let checked = custody.check(journal, keeper, replay);
            let outcome = match checked {
                Err(error) => Outcome::Refused(error),
                Ok(()) if child.is_cancel_requested() => Outcome::Cancelled,
                Ok(()) if custody.mark_startup_verified(journal, keeper) => Outcome::Verified,
                Ok(()) => Outcome::Refused(archive::journal::Error::Invalid),
            };
            state.outcome = Some(outcome);
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => { self.running = Some(running); Ok(()) },
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation without asserting that the worker has drained.
    pub fn abort(&self) {
        if let Some(running) = &self.running { running.abort(); }
    }

    /// Whether a submitted attempt still requires joining.
    pub fn is_running(&self) -> bool { self.running.is_some() }

    /// Whether the coordinator has observed the cancellation request.
    pub fn cancellation_observed(&self) -> bool {
        self.running.as_ref().is_some_and(Drained::cancellation_observed)
    }

    /// Join the exact attempt; a dropped pending join leaves the worker owned.
    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(job) => { drop(job); Outcome::NotStarted },
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => state.outcome.take().unwrap_or_else(|| { self.fenced = true; Outcome::Indeterminate }),
                Err(_) => { self.fenced = true; Outcome::Indeterminate },
            },
            WorkOutcome::Panicked => { self.fenced = true; Outcome::Panicked },
            WorkOutcome::Indeterminate => { self.fenced = true; Outcome::Indeterminate },
        };
        if receipt.runtime.is_err() || matches!(outcome, Outcome::Refused(_)) {
            self.fenced = true;
        }
        if receipt.runtime.is_ok() && matches!(outcome, Outcome::Verified) {
            if let Ok(mut state) = self.state.try_lock() { state.approved = true; }
            else { self.fenced = true; }
        }
        Some(Completion { runtime: receipt.runtime, outcome })
    }

    /// Return the resources only after any running attempt has drained.
    pub fn retire(self) -> Result<Retirement, Self> {
        if self.running.is_some() { return Err(self); }
        let Self { state, running, fenced } = self;
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let mut state = state.into_inner().unwrap_or_else(|error| error.into_inner());
                if (!state.approved || fenced) && let Some(custody) = state.resources.rollover_custody.as_mut() {
                    custody.invalidate_startup_verification();
                }
                Ok(Retirement { resources: state.resources, fenced })
            }
            Err(state) => Err(Self { state, running, fenced }),
        }
    }
}
