#![forbid(unsafe_code)]
//! Region-owned validation of a retired A/V worker before journal rollover.
//!
//! The worker borrows the retirement while checking its retained lineage, so
//! the pending media remains owned even if the storage check panics.

use std::sync::{Arc, Mutex};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    execution::{ExecutionError, TaskCx},
};

use super::{av_worker, metered::MeteredClock};

pub(super) enum Outcome {
    Verified(av_worker::VerifiedRolloverPause),
    Refused(av_worker::RolloverPauseError),
    Cancelled,
    NotStarted,
    Panicked,
    Indeterminate,
}

pub(super) struct Completion {
    pub runtime: Result<(), JoinError>,
    pub outcome: Outcome,
}

struct State {
    retirement: av_worker::UnknownTimeRetirement,
    outcome: Option<Outcome>,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

#[must_use = "drain the preflight and retain the original retirement"]
pub(super) struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

#[derive(Debug)]
pub(super) enum StartError {
    Running,
    Fenced,
    Context,
    Clock,
    Task(ExecutionError),
    Runtime(StartFailure),
}

pub(super) struct Retirement {
    pub original: av_worker::UnknownTimeRetirement,
    pub fenced: bool,
}

impl Worker {
    pub fn new(retirement: av_worker::UnknownTimeRetirement) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                retirement,
                outcome: None,
            })),
            running: None,
            fenced: false,
        }
    }

    pub fn from_retirement(retirement: Retirement) -> Self {
        let mut worker = Self::new(retirement.original);
        worker.fenced = retirement.fenced;
        worker
    }

    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
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
            if state.outcome.is_some() {
                return Err(StartError::Fenced);
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
                state.outcome = Some(Outcome::Cancelled);
                return;
            }
            let result = state.retirement.verify_rollover_pause();
            state.outcome = Some(match result {
                Err(error) => Outcome::Refused(error),
                Ok(_) if child.is_cancel_requested() => Outcome::Cancelled,
                Ok(proof) => Outcome::Verified(proof),
            });
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(job) => {
                drop(job);
                Outcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => state.outcome.take().unwrap_or_else(|| {
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
                    original: state.retirement,
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
