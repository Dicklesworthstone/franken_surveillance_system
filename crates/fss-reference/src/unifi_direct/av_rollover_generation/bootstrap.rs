#![forbid(unsafe_code)]
//! Drained, region-owned creation or reopening of a retained generation plan.
//! Separate paths and pins are caller assertions, not proof of independent media.

use super::{DiscoverError, Plan, ReservationError, ReservedPlan};
use crate::{ReplayCx, unifi_direct::metered::MeteredClock};
use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, RuntimeGrant};
use fss_object::{
    SpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    effect_journal::{
        EffectJournalPin, EffectJournalStore, EffectPersistenceError, EffectPinRetainer,
        PinRetainedEffectJournal,
    },
    execution::{ExecutionError, TaskCx},
};
use std::{
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Whether to create new exclusive custody or reopen at an independently held pin.
#[derive(Clone, Copy, Debug)]
pub enum BootstrapMode {
    /// Create new exclusive journal and pin-custody directories.
    Create,
    /// Reopen existing custody at this caller-supplied minimum.
    Recover {
        /// Independently retained minimum, not an external-effect receipt.
        minimum: EffectJournalPin,
    },
    /// Reopen and derive the next generation from the retained history.
    Discover {
        /// Independently retained minimum, not an external-effect receipt.
        minimum: EffectJournalPin,
        /// Maximum reservation records to inspect, at most 65,536.
        max_records: usize,
        /// Explicit bounded allowance for history work.
        work_limit: u64,
    },
}

/// Explicit filesystem capabilities and authority for both custody domains.
pub struct BootstrapStorage {
    /// Create or reopen behavior.
    pub mode: BootstrapMode,
    /// Dedicated journal directory directly under its replay root.
    pub journal_root: PathBuf,
    /// Dedicated pin-custody directory directly under its replay root.
    pub custody_root: PathBuf,
    /// Journal I/O and cancellation authority.
    pub journal_replay: Arc<ReplayCx>,
    /// Pin-custody I/O and cancellation authority.
    pub custody_replay: Arc<ReplayCx>,
    /// Journal filesystem capability.
    pub journal_io: Arc<dyn SpoolIo>,
    /// Pin-custody filesystem capability.
    pub custody_io: Arc<dyn SpoolIo>,
    /// Journal storage limits.
    pub journal_limits: EffectJournalLimits,
    /// Pin-custody storage limits.
    pub custody_limits: EffectJournalLimits,
    /// Caller-selected pin-custody scope.
    pub custody_scope: ContentDigest,
}

/// Original plan and separately supplied custody.
pub struct BootstrapInputs {
    /// Unstarted fresh or recovery plan.
    pub plan: Plan,
    /// Journal and pin-custody configuration.
    pub storage: BootstrapStorage,
}

/// Storage stage that stopped; writes may require reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStage {
    /// Authority or cancellation refused work.
    Checkpoint,
    /// Journal root create/open or directory sync failed.
    Journal,
    /// Pin-custody root create/open or directory sync failed.
    Custody,
    /// Binding the journal to pin custody failed.
    Binding,
    /// The retained plan could not be created or reopened.
    Plan,
}

/// Actual outcome after the blocking closure has drained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapOutcome {
    /// Retained plan is held in the retirement.
    Ready,
    /// Cancellation was observed; inspect all partial owners.
    Cancelled,
    /// A stage refused; inspect paths and exact retained owners.
    Refused(BootstrapStage),
    /// The closure never started.
    NotStarted,
    /// The closure panicked or its outcome could not be classified.
    Indeterminate,
}

/// Refusal before blocking work starts.
#[derive(Debug)]
pub enum BootstrapStartError {
    /// An attempt is already running.
    Running,
    /// This single-use owner is stopped or fenced.
    Fenced,
    /// Task, clock, or resource context did not match.
    Context,
    /// Clock read failed.
    Clock,
    /// Task grant or budget refused admission.
    Task(ExecutionError),
    /// Replay or custody authority refused admission.
    Replay,
    /// Runtime pool admission failed.
    Runtime(StartFailure),
}

struct State {
    plan: Option<Plan>,
    storage: BootstrapStorage,
    journal_attempted: bool,
    journal_root_created: bool,
    custody_attempted: bool,
    custody_root_created: bool,
    journal: Option<Box<dyn EffectJournalStore>>,
    retainer: Option<Box<dyn EffectPinRetainer>>,
    bound: Option<PinRetainedEffectJournal>,
    ready: Option<ReservedPlan>,
    error: Option<EffectPersistenceError>,
    plan_error: Option<ReservationError>,
    discover_error: Option<DiscoverError>,
    outcome: Option<BootstrapOutcome>,
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One create or recover attempt, owned until it drains.
#[must_use = "abort if needed, join, and retain all partial owners"]
pub struct BootstrapWorker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    completed: bool,
    fenced: bool,
    aborted: Arc<AtomicBool>,
}

/// Runtime outcome is distinct from storage outcome.
pub struct BootstrapCompletion {
    /// Runtime result after the closure drained.
    pub runtime: Result<(), JoinError>,
    /// Classified storage result.
    pub outcome: BootstrapOutcome,
    /// Cancellation was explicitly requested.
    pub cancellation_requested: bool,
}

/// Original plan, configuration, all partial handles and the final outcome.
#[must_use = "retain or reconcile all partially created or reopened custody"]
pub struct BootstrapRetirement {
    /// Original plan if it did not bind.
    pub plan: Option<Plan>,
    /// Original storage configuration and authorities.
    pub storage: BootstrapStorage,
    /// Whether journal creation or open was attempted.
    pub journal_attempted: bool,
    /// Whether exclusive journal-root creation succeeded.
    pub journal_root_created: bool,
    /// Whether pin-custody creation or open was attempted.
    pub custody_attempted: bool,
    /// Whether exclusive pin-root creation succeeded.
    pub custody_root_created: bool,
    /// Unbound journal owner, if retained.
    pub journal: Option<Box<dyn EffectJournalStore>>,
    /// Unbound pin custodian, if retained.
    pub retainer: Option<Box<dyn EffectPinRetainer>>,
    /// Bound journal if plan binding was refused.
    pub bound: Option<PinRetainedEffectJournal>,
    /// Retained plan if binding returned success.
    pub ready: Option<ReservedPlan>,
    /// Storage failure, when available.
    pub error: Option<EffectPersistenceError>,
    /// Plan-binding failure, when available.
    pub plan_error: Option<ReservationError>,
    /// Generation-discovery failure, when that mode was selected.
    pub discover_error: Option<DiscoverError>,
    /// Storage outcome, or none if no attempt was started.
    pub outcome: Option<BootstrapOutcome>,
    /// An uncertain result or cancellation prevents automatic use.
    pub fenced: bool,
}

impl BootstrapRetirement {
    /// Transfer a successful plan only after an uncancelled, unfenced completion.
    pub fn take_ready(&mut self) -> Option<ReservedPlan> {
        if !self.fenced && self.outcome == Some(BootstrapOutcome::Ready) {
            self.ready.take()
        } else {
            None
        }
    }
}

fn direct_child(path: &Path, root: &Path) -> bool {
    path.is_absolute()
        && path.parent() == Some(root)
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn valid_limits(limits: EffectJournalLimits) -> bool {
    (1..=65_536).contains(&limits.max_records)
        && (1..=512 * 1024).contains(&limits.max_record_bytes)
        && (1..=1024 * 1024 * 1024).contains(&limits.max_total_bytes)
        && limits.max_read_bytes > 0
}

fn valid_minimum(mode: BootstrapMode) -> bool {
    match mode {
        BootstrapMode::Create => true,
        BootstrapMode::Recover { minimum } | BootstrapMode::Discover { minimum, .. } => {
            minimum.sequence > 0
                && minimum.root.algorithm() == DigestAlgorithm::Sha256
                && !minimum.root.is_laboratory()
                && minimum.root.bytes() != [0; 32]
                && match mode {
                    BootstrapMode::Discover { max_records, work_limit, .. } =>
                        (1..=65_536).contains(&max_records) && (1..=100_000_000_000).contains(&work_limit),
                    _ => true,
                }
        }
    }
}

impl BootstrapWorker {
    /// Whether this owner holds an unstarted, uncancelled bootstrap operation.
    /// This checks local ownership without filesystem I/O.
    pub fn is_unstarted(&self) -> bool {
        self.running.is_none()
            && !self.completed
            && !self.fenced
            && !self.aborted.load(Ordering::Acquire)
            && self
                .state
                .try_lock()
                .is_ok_and(|state| state.outcome.is_none() && state.plan.is_some())
    }

    /// Bind one operation without storage I/O.
    pub fn new(inputs: BootstrapInputs) -> Result<Self, BootstrapInputs> {
        let s = &inputs.storage;
        if !direct_child(&s.journal_root, s.journal_replay.root_dir())
            || !direct_child(&s.custody_root, s.custody_replay.root_dir())
            || s.journal_root.starts_with(&s.custody_root)
            || s.custody_root.starts_with(&s.journal_root)
            || !valid_limits(s.journal_limits)
            || !valid_limits(s.custody_limits)
            || !valid_minimum(s.mode)
            || s.custody_scope.algorithm() != DigestAlgorithm::Sha256
            || s.custody_scope.is_laboratory()
            || s.custody_scope.bytes() == [0; 32]
        {
            return Err(inputs);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                plan: Some(inputs.plan),
                storage: inputs.storage,
                journal_attempted: false,
                journal_root_created: false,
                custody_attempted: false,
                custody_root_created: false,
                journal: None,
                retainer: None,
                bound: None,
                ready: None,
                error: None,
                plan_error: None,
                discover_error: None,
                outcome: None,
            })),
            running: None,
            completed: false,
            fenced: false,
            aborted: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Admit a single region-owned blocking operation under both task grants.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        cost: &BudgetVector,
    ) -> Result<(), BootstrapStartError> {
        if self.fenced || self.completed || self.aborted.load(Ordering::Acquire) {
            return Err(BootstrapStartError::Fenced);
        }
        if self.running.is_some() {
            return Err(BootstrapStartError::Running);
        }
        if !clock.matches(task, cx) {
            return Err(BootstrapStartError::Context);
        }
        let now = clock.now().map_err(|_| BootstrapStartError::Clock)?;
        {
            let state = self
                .state
                .try_lock()
                .map_err(|_| BootstrapStartError::Fenced)?;
            let s = &state.storage;
            for (path, budget) in [
                (&s.journal_root, cost),
                (&s.custody_root, &BudgetVector::ZERO),
            ] {
                task.checkpoint_for(
                    RuntimeGrant::ObjectStage,
                    path.to_str().ok_or(BootstrapStartError::Context)?,
                    now,
                    budget,
                )
                .map_err(BootstrapStartError::Task)?;
            }
            s.journal_replay
                .checkpoint("unifi-reservation-bootstrap-admit")
                .map_err(|_| BootstrapStartError::Replay)?;
            s.custody_replay
                .checkpoint("unifi-reservation-bootstrap-admit")
                .map_err(|_| BootstrapStartError::Replay)?;
        }
        let state = Arc::clone(&self.state);
        let aborted = Arc::clone(&self.aborted);
        let job: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            let journal_replay = state.storage.journal_replay.clone();
            let custody_replay = state.storage.custody_replay.clone();
            let mut guard = || {
                if aborted.load(Ordering::Acquire)
                    || child.is_cancel_requested()
                    || journal_replay
                        .checkpoint("unifi-reservation-bootstrap-work")
                        .is_err()
                    || custody_replay
                        .checkpoint("unifi-reservation-bootstrap-work")
                        .is_err()
                {
                    Err(ReservationError::Cancelled)
                } else {
                    Ok(())
                }
            };
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            state.journal_attempted = true;
            let s = &state.storage;
            if matches!(s.mode, BootstrapMode::Create) {
                if create_private_root(&s.journal_root).is_err() {
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Journal));
                    return;
                }
                state.journal_root_created = true;
                let s = &state.storage;
                if s.journal_io
                    .sync_directory(s.journal_replay.root_dir())
                    .is_err()
                {
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Journal));
                    return;
                }
            }
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            let s = &state.storage;
            let journal = match s.mode {
                BootstrapMode::Create => FileEffectJournal::create(
                    &s.journal_root,
                    s.journal_limits,
                    s.journal_io.clone(),
                ),
                BootstrapMode::Recover { minimum } | BootstrapMode::Discover { minimum, .. } => FileEffectJournal::open(
                    &s.journal_root,
                    s.journal_limits,
                    s.journal_io.clone(),
                    minimum,
                ),
            };
            match journal {
                Ok(journal) => state.journal = Some(Box::new(journal)),
                Err(error) => {
                    state.error = Some(error);
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Journal));
                    return;
                }
            }
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            state.custody_attempted = true;
            let s = &state.storage;
            if matches!(s.mode, BootstrapMode::Create) {
                if create_private_root(&s.custody_root).is_err() {
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Custody));
                    return;
                }
                state.custody_root_created = true;
                let s = &state.storage;
                if s.custody_io
                    .sync_directory(s.custody_replay.root_dir())
                    .is_err()
                {
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Custody));
                    return;
                }
            }
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            let s = &state.storage;
            let retainer = match s.mode {
                BootstrapMode::Create => FileTrustedRootPinRetainer::create(
                    &s.custody_root,
                    s.custody_limits,
                    s.custody_io.clone(),
                    s.custody_scope,
                ),
                BootstrapMode::Recover { .. } | BootstrapMode::Discover { .. } => FileTrustedRootPinRetainer::open_trusting_storage(
                    &s.custody_root,
                    s.custody_limits,
                    s.custody_io.clone(),
                    s.custody_scope,
                ),
            };
            match retainer {
                Ok(retainer) => state.retainer = Some(Box::new(retainer)),
                Err(error) => {
                    state.error = Some(error);
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Custody));
                    return;
                }
            }
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            if state.journal.is_none() || state.retainer.is_none() {
                state.outcome = Some(BootstrapOutcome::Indeterminate);
                return;
            }
            let (Some(journal), Some(retainer)) = (state.journal.take(), state.retainer.take())
            else {
                state.outcome = Some(BootstrapOutcome::Indeterminate);
                return;
            };
            let bound = match state.storage.mode {
                BootstrapMode::Create => PinRetainedEffectJournal::try_new(journal, retainer),
                BootstrapMode::Recover { .. } | BootstrapMode::Discover { .. } => {
                    PinRetainedEffectJournal::try_for_reconciliation(journal, retainer)
                }
            };
            match bound {
                Ok(bound) => state.bound = Some(bound),
                Err(refusal) => {
                    state.journal = Some(refusal.journal);
                    state.retainer = Some(refusal.retainer);
                    state.error = Some(refusal.error);
                    state.outcome = Some(BootstrapOutcome::Refused(BootstrapStage::Binding));
                    return;
                }
            }
            if guard().is_err() {
                state.outcome = Some(BootstrapOutcome::Cancelled);
                return;
            }
            if state.plan.is_none() || state.bound.is_none() {
                state.outcome = Some(BootstrapOutcome::Indeterminate);
                return;
            }
            let (Some(plan), Some(bound)) = (state.plan.take(), state.bound.take()) else {
                state.outcome = Some(BootstrapOutcome::Indeterminate);
                return;
            };
            enum PlanRefusal {
                Bound(super::BindRefusal),
                Discovered(super::DiscoverRefusal),
            }
            let result = match state.storage.mode {
                BootstrapMode::Create => {
                    ReservedPlan::create_guarded(plan, bound, &journal_replay, &mut guard).map_err(PlanRefusal::Bound)
                }
                BootstrapMode::Recover { .. } => {
                    ReservedPlan::recover_guarded(plan, bound, &journal_replay, &mut guard).map_err(PlanRefusal::Bound)
                }
                BootstrapMode::Discover { max_records, work_limit, .. } => {
                    ReservedPlan::recover_discovered_guarded(plan, bound, &journal_replay, max_records,
                        &mut fss_geometry::WorkBudget::new(work_limit), &mut guard).map_err(PlanRefusal::Discovered)
                }
            };
            match result {
                Ok(mut ready) => {
                    if guard().is_err() {
                        ready.fence();
                        state.ready = Some(ready);
                        state.outcome = Some(BootstrapOutcome::Cancelled);
                    } else {
                        state.ready = Some(ready);
                        state.outcome = Some(BootstrapOutcome::Ready);
                    }
                }
                Err(refusal) => {
                    let cancelled = match refusal {
                        PlanRefusal::Bound(refusal) => {
                            let cancelled = matches!(refusal.reason, ReservationError::Cancelled);
                            state.plan = Some(refusal.plan);
                            state.bound = Some(refusal.journal);
                            state.plan_error = Some(refusal.reason);
                            cancelled
                        }
                        PlanRefusal::Discovered(refusal) => {
                            let cancelled = matches!(refusal.reason, DiscoverError::Cancelled | DiscoverError::Bind(ReservationError::Cancelled) | DiscoverError::Work(fss_geometry::GeometryError::Cancelled));
                            state.plan = Some(refusal.plan);
                            state.bound = Some(refusal.journal);
                            state.discover_error = Some(refusal.reason);
                            cancelled
                        }
                    };
                    state.outcome = Some(if cancelled {
                        BootstrapOutcome::Cancelled
                    } else {
                        BootstrapOutcome::Refused(BootstrapStage::Plan)
                    });
                }
            }
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(BootstrapStartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation. The original owner must still be joined.
    pub fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Drain the operation while retaining its actual storage result.
    pub async fn join(&mut self) -> Option<BootstrapCompletion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(job) => {
                drop(job);
                BootstrapOutcome::NotStarted
            }
            WorkOutcome::Finished(()) => self
                .state
                .try_lock()
                .ok()
                .and_then(|state| state.outcome)
                .unwrap_or(BootstrapOutcome::Indeterminate),
            WorkOutcome::Panicked | WorkOutcome::Indeterminate => BootstrapOutcome::Indeterminate,
        };
        self.fenced |= receipt.runtime.is_err() || outcome == BootstrapOutcome::Indeterminate;
        self.completed = true;
        Some(BootstrapCompletion {
            runtime: receipt.runtime,
            outcome,
            cancellation_requested: self.aborted.load(Ordering::Acquire),
        })
    }

    /// Transfer the original plan, configuration and every partial handle.
    pub fn retire(self) -> Result<BootstrapRetirement, Self> {
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
                let fenced = fenced
                    || poisoned
                    || aborted.load(Ordering::Acquire)
                    || matches!(
                        state.outcome,
                        Some(
                            BootstrapOutcome::Cancelled
                                | BootstrapOutcome::Indeterminate
                                | BootstrapOutcome::Refused(_)
                        )
                    );
                if fenced {
                    if let Some(ready) = state.ready.as_mut() {
                        ready.fence();
                    }
                }
                Ok(BootstrapRetirement {
                    plan: state.plan,
                    storage: state.storage,
                    journal_attempted: state.journal_attempted,
                    journal_root_created: state.journal_root_created,
                    custody_attempted: state.custody_attempted,
                    custody_root_created: state.custody_root_created,
                    journal: state.journal,
                    retainer: state.retainer,
                    bound: state.bound,
                    ready: state.ready,
                    error: state.error,
                    plan_error: state.plan_error,
                    discover_error: state.discover_error,
                    outcome: state.outcome,
                    fenced,
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

#[cfg(unix)]
fn create_private_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(root)
}
#[cfg(not(unix))]
fn create_private_root(_root: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private journal storage unsupported",
    ))
}
