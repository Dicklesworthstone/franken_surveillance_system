#![forbid(unsafe_code)]
//! Region-owned validation of a retired video worker before journal rollover.
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

use super::{metered::MeteredClock, video_worker};

/// Classified result after the borrowed preflight has drained.
pub enum Outcome {
    /// A verified, single-use predecessor observation.
    Verified(video_worker::VerifiedRolloverPause),
    /// Verification refused without transferring the source.
    Refused(video_worker::RolloverPauseError),
    /// Cancellation occurred before verification completed.
    Cancelled,
    /// The runtime did not start the closure.
    NotStarted,
    /// Storage panicked and requires reconciliation.
    Panicked,
    /// The worker outcome could not be determined.
    Indeterminate,
}

/// Runtime and storage results after draining.
pub struct Completion {
    /// Runtime join result.
    pub runtime: Result<(), JoinError>,
    /// Storage check result.
    pub outcome: Outcome,
}

struct State {
    retirement: video_worker::Retirement,
    outcome: Option<Outcome>,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

#[must_use = "drain the preflight and retain the original retirement"]
/// Region-owned preflight; drain before recovering the source.
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

#[derive(Debug)]
/// Refusal before the preflight starts.
pub enum StartError {
    /// A previous attempt still needs a join.
    Running,
    /// An uncertain or completed attempt requires reconciliation.
    Fenced,
    /// The supplied clock is bound to another task or context.
    Context,
    /// Clock observation failed.
    Clock,
    /// Task authority or budget refused admission.
    Task(ExecutionError),
    /// The runtime refused the blocking operation.
    Runtime(StartFailure),
}

/// Original source owner and its preflight fence.
pub struct Retirement {
    /// The unchanged pending video owner.
    pub original: video_worker::Retirement,
    /// True when the storage outcome is uncertain.
    pub fenced: bool,
}

impl Retirement {
    /// Consume a successful verification without another storage read.
    pub fn into_rollover(
        self,
        proof: video_worker::VerifiedRolloverPause,
    ) -> Result<
        (
            video_worker::RolloverResources,
            super::archive::journal::rollover::Previous,
        ),
        Self,
    > {
        if self.fenced {
            return Err(self);
        }
        match self.original.into_rollover_verified(proof) {
            Ok(parts) => Ok(parts),
            Err(original) => Err(Self {
                original,
                fenced: false,
            }),
        }
    }
}

impl Worker {
    /// Hold the retired worker while validating its predecessor.
    pub fn new(retirement: video_worker::Retirement) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                retirement,
                outcome: None,
            })),
            running: None,
            fenced: false,
        }
    }

    /// Reconstruct a worker without clearing a prior fence.
    pub fn from_retirement(retirement: Retirement) -> Self {
        let mut worker = Self::new(retirement.original);
        worker.fenced = retirement.fenced;
        worker
    }

    /// Admit a bounded storage check under the caller's task authority.
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

    /// Whether the admitted closure still requires a join.
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
    /// Request cancellation without discarding the pending owner.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }
    /// Whether cancellation reached the region-owned task.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Drain the actual closure and return its classified result.
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
        if receipt.runtime.is_err() {
            self.fenced = true;
        }
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover the original owner only after the closure has drained.
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
