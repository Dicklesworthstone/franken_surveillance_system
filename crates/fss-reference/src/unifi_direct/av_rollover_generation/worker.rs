#![forbid(unsafe_code)]
//! One region-owned blocking reservation operation. The caller must drain and
//! inspect the result before starting a creator or acknowledging a reservation.

use std::{
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    effect_journal::EffectJournalPin,
    execution::{ExecutionError, TaskCx},
};

use super::{
    CreatorObservation, Identity, OpenSwitchesError, OpenSwitchesRefusal, OpenedSwitches,
    ReservationError, ReservationRefusal, ReservedPlan, Worker,
};
use crate::{ReplayCx, unifi_direct::{archive::journal::rollover::{SelectedSwitch, SwitchPredecessor}, metered::MeteredClock}};

/// A single, explicitly selected operation. An evidence digest is a caller
/// assertion, not proof that the underlying creator has been reconciled.
pub enum ReservationRequest {
    /// Reserve one identity before transferring its unstarted creator.
    Reserve,
    /// Record a caller-provided reconciliation reference for this identity.
    Reconcile {
        /// Exact pending generation identity.
        identity: Identity,
        /// Reference to independently assessed evidence.
        evidence: ContentDigest,
    },
    /// Record the managed owner's observation of an exact successful creator.
    /// The observation is local and does not assert independent custody.
    ObservedCreator(CreatorObservation),
    /// Open and compare every candidate in a bounded retained inventory.
    /// This explicitly trusts the configured pin-storage roots.
    InspectSwitches {
        /// Exact predecessor to match.
        predecessor: SwitchPredecessor,
        /// Maximum number of candidates, at most 128.
        max_candidates: usize,
        /// Maximum reservation records, at most 65,536.
        max_records: usize,
        /// Explicit work allowance including storage-read ceilings.
        work_limit: u64,
    },
}

/// Exact owners and authority for one worker. Paths are caller assertions;
/// they do not prove the storage capability uses those paths or separate media.
pub struct ReservationInputs {
    /// Retained plan and its journal.
    pub plan: ReservedPlan,
    /// One selected operation.
    pub request: ReservationRequest,
    /// Journal resource directly under its replay root.
    pub journal_resource: PathBuf,
    /// Pin-custody resource directly under its replay root.
    pub custody_resource: PathBuf,
    /// Authority and cancellation for the journal resource.
    pub journal_replay: Arc<ReplayCx>,
    /// Authority and cancellation for the pin-custody resource.
    pub custody_replay: Arc<ReplayCx>,
}

/// Start refusal leaves the inputs owned by the worker and performs no I/O.
#[derive(Debug)]
pub enum ReservationStartError {
    /// This worker is already running.
    Running,
    /// This single-use owner is stopped, completed, or fenced.
    Fenced,
    /// The task, clock, or resource identity was invalid.
    Context,
    /// Clock observation failed.
    Clock,
    /// Task grant or budget was refused.
    Task(ExecutionError),
    /// Journal or custody replay authority was refused.
    Replay,
    /// The runtime did not admit the blocking task.
    Runtime(StartFailure),
}

/// Detailed result retained until the drained worker is retired.
#[must_use = "retain the creator or reconcile the exact refusal"]
pub enum ReservationOutcome {
    /// A durably reserved identity and its unstarted creator.
    Reserved {
        /// Exact identity committed by the reservation journal.
        identity: Identity,
        /// Unstarted creator; the caller retains the start decision.
        worker: Worker,
    },
    /// The finite in-memory plan had no further worker.
    Exhausted,
    /// Caller-provided reconciliation reference was retained at this head.
    Reconciled(EffectJournalPin),
    /// A reservation was refused; its unstarted candidate may be present.
    ReservationRefused(ReservationRefusal),
    /// Recording reconciliation was refused or became indeterminate.
    ReconciliationRefused(ReservationError),
    /// Inventory and candidate switches were opened and compared.
    SwitchesInspected {
        /// Complete opened candidate custody.
        opened: OpenedSwitches,
        /// Unique match among this inventory, if any.
        selected: Option<SelectedSwitch>,
    },
    /// Candidate opening refused while preserving all partial owners.
    SwitchOpeningRefused(OpenSwitchesRefusal),
    /// Selection refused while retaining the complete opened owners.
    SwitchSelectionRefused {
        /// Candidate custody to retain or reconcile.
        opened: OpenedSwitches,
        /// Exact selection refusal.
        error: OpenSwitchesError,
    },
    /// Cancellation was observed after opening and before selection.
    SwitchInspectionCancelled(OpenedSwitches),
}

struct State {
    inputs: ReservationInputs,
    outcome: Option<ReservationOutcome>,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// A one-attempt blocking worker owned by its asynchronous region.
#[must_use = "abort if needed, join, and retain the retirement"]
pub struct ReservationWorker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    completed: bool,
    fenced: bool,
    aborted: Arc<AtomicBool>,
}

/// Runtime completion is independent from the retained semantic result.
pub struct ReservationCompletion {
    /// Runtime task outcome after the closure drained.
    pub runtime: Result<(), JoinError>,
    /// Whether the closure ran and returned a retained semantic result.
    pub outcome_available: bool,
    /// The blocking closure never ran; the original request remains owned.
    pub not_started: bool,
    /// Whether panic or inconsistent state requires cold reconciliation.
    pub indeterminate: bool,
    /// Cancellation was requested, including after a write may have completed.
    pub cancellation_requested: bool,
}

/// All original owners and any result, including partial or ambiguous outcomes.
#[must_use = "retain the plan, request and result for reconciliation"]
pub struct ReservationRetirement {
    /// Original retained plan, resources and authority.
    pub inputs: ReservationInputs,
    /// Detailed result, if the closure returned one.
    pub outcome: Option<ReservationOutcome>,
    /// Cancellation, runtime failure, panic, or inconsistent state fenced the plan.
    pub fenced: bool,
    /// Cancellation was requested.
    pub aborted: bool,
}

fn direct_child(path: &Path, root: &Path) -> bool {
    path.is_absolute()
        && path.parent() == Some(root)
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

impl ReservationWorker {
    /// Whether this owner holds an unstarted, uncancelled reservation request.
    /// This checks only local ownership; it performs no storage I/O.
    pub fn is_unstarted_reservation(&self) -> bool {
        self.running.is_none()
            && !self.completed
            && !self.fenced
            && !self.aborted.load(Ordering::Acquire)
            && self.state.try_lock().is_ok_and(|state| {
                state.outcome.is_none()
                    && matches!(&state.inputs.request, ReservationRequest::Reserve)
            })
    }

    /// Whether an unstarted reconciliation names the exact pending generation.
    /// The reference may be a caller assertion or a local creator observation;
    /// neither establishes independent custody.
    pub fn is_unstarted_reconciliation(&self) -> bool {
        self.running.is_none()
            && !self.completed
            && !self.fenced
            && !self.aborted.load(Ordering::Acquire)
            && self.state.try_lock().is_ok_and(|state| {
                state.outcome.is_none()
                    && match &state.inputs.request {
                        ReservationRequest::Reconcile { identity, evidence } => {
                            state.inputs.plan.pending() == Some(identity)
                                && evidence.algorithm() == fss_core::DigestAlgorithm::Sha256
                                && !evidence.is_laboratory()
                                && evidence.bytes() != [0; 32]
                        }
                        ReservationRequest::ObservedCreator(observation) => {
                            state.inputs.plan.pending() == Some(observation.identity())
                        }
                        ReservationRequest::Reserve | ReservationRequest::InspectSwitches { .. } => false,
                    }
            })
    }
    /// Bind an unstarted operation without filesystem I/O.
    pub fn new(inputs: ReservationInputs) -> Result<Self, ReservationInputs> {
        if !direct_child(&inputs.journal_resource, inputs.journal_replay.root_dir())
            || !direct_child(&inputs.custody_resource, inputs.custody_replay.root_dir())
            || inputs.journal_resource == inputs.custody_resource
            || matches!(&inputs.request, ReservationRequest::InspectSwitches { max_candidates, max_records, work_limit, .. }
                if !(1..=128).contains(max_candidates) || !(1..=65_536).contains(max_records)
                    || !(1..=100_000_000_000).contains(work_limit)
                    || !inputs.plan.uses_replays(&inputs.journal_replay, &inputs.custody_replay))
        {
            return Err(inputs);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                inputs,
                outcome: None,
            })),
            running: None,
            completed: false,
            fenced: false,
            aborted: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Admit one operation to the runtime's blocking pool with both grants.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        cost: &BudgetVector,
    ) -> Result<(), ReservationStartError> {
        if self.fenced || self.completed || self.aborted.load(Ordering::Acquire) {
            return Err(ReservationStartError::Fenced);
        }
        if self.running.is_some() {
            return Err(ReservationStartError::Running);
        }
        if !clock.matches(task, cx) {
            return Err(ReservationStartError::Context);
        }
        let now = clock.now().map_err(|_| ReservationStartError::Clock)?;
        {
            let state = self
                .state
                .try_lock()
                .map_err(|_| ReservationStartError::Fenced)?;
            let journal = state
                .inputs
                .journal_resource
                .to_str()
                .ok_or(ReservationStartError::Context)?;
            let custody = state
                .inputs
                .custody_resource
                .to_str()
                .ok_or(ReservationStartError::Context)?;
            task.checkpoint_for(RuntimeGrant::ObjectStage, journal, now, cost)
                .map_err(ReservationStartError::Task)?;
            task.checkpoint_for(RuntimeGrant::ObjectStage, custody, now, &BudgetVector::ZERO)
                .map_err(ReservationStartError::Task)?;
            if matches!(&state.inputs.request, ReservationRequest::InspectSwitches { .. }) {
                for root in [state.inputs.journal_replay.root_dir(), state.inputs.custody_replay.root_dir()] {
                    task.checkpoint_for(RuntimeGrant::ObjectStage, root.to_str().ok_or(ReservationStartError::Context)?, now, &BudgetVector::ZERO)
                        .map_err(ReservationStartError::Task)?;
                }
            }
            state
                .inputs
                .journal_replay
                .checkpoint("unifi-reservation-worker-admit")
                .map_err(|_| ReservationStartError::Replay)?;
            state
                .inputs
                .custody_replay
                .checkpoint("unifi-reservation-worker-admit")
                .map_err(|_| ReservationStartError::Replay)?;
        }
        let state = Arc::clone(&self.state);
        let aborted = Arc::clone(&self.aborted);
        let job: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            if aborted.load(Ordering::Acquire) || child.is_cancel_requested() {
                return;
            }
            let journal = state.inputs.journal_replay.clone();
            let custody = state.inputs.custody_replay.clone();
            let mut guard = || {
                if aborted.load(Ordering::Acquire)
                    || child.is_cancel_requested()
                    || custody
                        .checkpoint("unifi-reservation-worker-write")
                        .is_err()
                {
                    Err(ReservationError::Cancelled)
                } else {
                    Ok(())
                }
            };
            // The request is retained in inputs. Only its immutable values are
            // cloned; the plan and every outcome remain owned by State.
            enum Action {
                Reserve,
                Reconcile(Identity, ContentDigest),
                Observed(Identity),
                Inspect(SwitchPredecessor, usize, usize, u64),
            }
            let result = match &state.inputs.request {
                ReservationRequest::Reserve => Action::Reserve,
                ReservationRequest::Reconcile { identity, evidence } => {
                    Action::Reconcile(identity.clone(), *evidence)
                }
                ReservationRequest::ObservedCreator(observation) => {
                    Action::Observed(observation.identity().clone())
                }
                ReservationRequest::InspectSwitches { predecessor, max_candidates, max_records, work_limit } => {
                    Action::Inspect(*predecessor, *max_candidates, *max_records, *work_limit)
                }
            };
            let outcome = match result {
                Action::Reserve => {
                    match state.inputs.plan.reserve_next_guarded(&journal, &mut guard) {
                        Ok(Some((identity, worker))) => {
                            ReservationOutcome::Reserved { identity, worker }
                        }
                        Ok(None) => ReservationOutcome::Exhausted,
                        Err(refusal) => ReservationOutcome::ReservationRefused(refusal),
                    }
                }
                Action::Reconcile(identity, evidence) => match state
                    .inputs
                    .plan
                    .record_reconciliation_guarded(&identity, evidence, &journal, &mut guard)
                {
                    Ok(pin) => ReservationOutcome::Reconciled(pin),
                    Err(error) => ReservationOutcome::ReconciliationRefused(error),
                },
                Action::Observed(identity) => match state
                    .inputs
                    .plan
                    .record_creator_observation_guarded(&identity, &journal, &mut guard)
                {
                    Ok(pin) => ReservationOutcome::Reconciled(pin),
                    Err(error) => ReservationOutcome::ReconciliationRefused(error),
                },
                Action::Inspect(predecessor, max_candidates, max_records, work_limit) => {
                    let cancelled = || aborted.load(Ordering::Acquire) || child.is_cancel_requested();
                    let mut work = fss_geometry::WorkBudget::with_cancellation_probe(work_limit, &cancelled);
                    match state.inputs.plan.open_switches_trusting_custody(max_candidates, max_records, &mut work, &journal) {
                        Err(refusal) => ReservationOutcome::SwitchOpeningRefused(refusal),
                        Ok(opened) if guard().is_err() => ReservationOutcome::SwitchInspectionCancelled(opened),
                        Ok(mut opened) => match opened.select(&mut state.inputs.plan, predecessor, max_records, &mut work, &journal) {
                            Ok(_) if guard().is_err() => ReservationOutcome::SwitchInspectionCancelled(opened),
                            Ok(selected) => ReservationOutcome::SwitchesInspected { opened, selected },
                            Err(error) => ReservationOutcome::SwitchSelectionRefused { opened, error },
                        },
                    }
                }
            };
            state.outcome = Some(outcome);
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(ReservationStartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation; the running closure still has to be joined.
    pub fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Join the closure and keep its actual result for retirement.
    pub async fn join(&mut self) -> Option<ReservationCompletion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let (not_started, indeterminate) = match receipt.work {
            WorkOutcome::NotStarted(job) => {
                drop(job);
                (true, false)
            }
            WorkOutcome::Finished(()) => (false, false),
            WorkOutcome::Panicked | WorkOutcome::Indeterminate => (false, true),
        };
        let outcome_available = self
            .state
            .try_lock()
            .ok()
            .is_some_and(|state| state.outcome.is_some());
        let cancelled = self.aborted.load(Ordering::Acquire);
        let indeterminate = indeterminate || (!not_started && !outcome_available && !cancelled);
        self.fenced |= indeterminate || receipt.runtime.is_err();
        self.completed = true;
        Some(ReservationCompletion {
            runtime: receipt.runtime,
            outcome_available,
            not_started,
            indeterminate,
            cancellation_requested: cancelled,
        })
    }

    /// Transfer every owner after the blocking closure has drained.
    pub fn retire(self) -> Result<ReservationRetirement, Self> {
        if self.running.is_some() {
            return Err(self);
        }
        let Self {
            state,
            running,
            completed,
            fenced,
            aborted,
        } = self;
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let (mut state, poisoned) = match state.into_inner() {
                    Ok(state) => (state, false),
                    Err(poisoned) => (poisoned.into_inner(), true),
                };
                let aborted = aborted.load(Ordering::Acquire);
                if fenced || poisoned || aborted {
                    state.inputs.plan.fence();
                }
                Ok(ReservationRetirement {
                    inputs: state.inputs,
                    outcome: state.outcome,
                    fenced: fenced || poisoned || aborted,
                    aborted,
                })
            }
            Err(state) => Err(Self {
                state,
                running,
                completed,
                fenced,
                aborted,
            }),
        }
    }
}
