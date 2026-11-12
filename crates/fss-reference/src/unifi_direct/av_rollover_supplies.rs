#![forbid(unsafe_code)]
//! Region-owned creation of fresh A/V rollover journal and keeper stores.
//!
//! A caller may supply a switch or request creation in separately selected
//! journal and pin-custody locations.
//! A failed or cancelled creation retains the exact path and partial owners;
//! no files are deleted, reopened, or silently retried.

use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, RuntimeGrant};
use fss_object::{
    SpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal, FileTrustedRootPinRetainer},
};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    effect_journal::{EffectJournalStore, EffectPinRetainer, PinRetainedEffectJournal},
    execution::{ExecutionError, TaskCx},
};

use super::{archive, av_rollover_worker, metered::MeteredClock};
use crate::ReplayCx;

/// Caller-selected custody for a new switch retainer. The caller must establish
/// the storage domain's trust and independence; this value does not prove it.
pub struct SwitchCustody {
    /// New exclusive directory directly under the pin replay root.
    pub root: PathBuf,
    /// Explicit authority for pin-root creation and later recovery.
    pub replay: Arc<ReplayCx>,
    /// Filesystem capability for this pin-custody domain.
    pub io: Arc<dyn SpoolIo>,
    /// Bounds for the pin-retainer journal.
    pub limits: EffectJournalLimits,
    /// Caller-selected non-laboratory SHA-256 scope.
    pub scope: ContentDigest,
}

/// Either an already bound switch or an explicit fresh-custody plan.
pub enum SwitchInput {
    /// Caller-prepared empty switch with pin custody.
    Prepared(PinRetainedEffectJournal),
    /// Create the switch and its caller-selected pin retainer on the worker.
    Create(SwitchCustody),
}

/// Exclusive creation inputs, including the caller's switch-custody choice.
pub struct Inputs {
    /// New absolute directory, directly under the replay-authorized root.
    pub root: PathBuf,
    /// Exact replay authority and cancellation state for the directory.
    pub replay: Arc<ReplayCx>,
    /// Filesystem capability used for journal creation and synchronization.
    pub io: Arc<dyn SpoolIo>,
    /// Bounds used for each newly created journal.
    pub journal_limits: EffectJournalLimits,
    /// Prepared switch or a fresh switch and pin-custody plan.
    pub switch: SwitchInput,
    /// Read authorization for the eventual confirmed-graph replay.
    pub read: Arc<dyn archive::ReadAuthority + Send + Sync>,
    /// Limits for reading the confirmed A/V graph.
    pub object_limits: archive::StagedAvLimits,
    /// Bounded work for eventual rollover replay.
    pub work_limit: u64,
}

/// Creation stage at which a storage operation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Authority or cancellation refused the next operation.
    Checkpoint,
    /// The private root could not be created exclusively or synced.
    Root,
    /// Successor publication journal creation failed.
    Journal,
    /// Successor keeper creation failed.
    Keeper,
    /// The pin root could not be created or synchronized.
    PinRoot,
    /// Pin-retainer initialization failed and may have written history.
    PinRetainer,
    /// Empty switch-journal creation failed.
    SwitchJournal,
    /// Binding the new switch to its pin retainer was refused.
    SwitchBinding,
}

/// Payload-free outcome. Partial filesystem effects require inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Both successor stores were created and retained in the worker.
    Ready,
    /// Cancellation was observed; inspect partial creation state.
    Cancelled,
    /// Creation refused at this stage; inspect partial creation state.
    Refused(Stage),
    /// The blocking closure never started.
    NotStarted,
    /// A panic requires inspection of the root and retained owners.
    Panicked,
    /// The runtime or worker result could not be classified.
    Indeterminate,
}

/// Runtime completion and the independently classified creation outcome.
pub struct Completion {
    /// Runtime result after the blocking task drained.
    pub runtime: Result<(), JoinError>,
    /// Actual worker classification.
    pub outcome: Outcome,
}

/// Start admission refusal; no filesystem operation has been launched.
#[derive(Debug)]
pub enum StartError {
    /// A creation task is already running.
    Running,
    /// A completed or uncertain attempt requires retirement.
    Fenced,
    /// Task, context, and clock did not match.
    Context,
    /// Clock observation was refused.
    Clock,
    /// Task grant or budget refused creation.
    Task(ExecutionError),
    /// Replay authority refused admission.
    Replay,
    /// The runtime refused the blocking task.
    Runtime(StartFailure),
}

struct State {
    inputs: Inputs,
    root_created: bool,
    journal: Option<Box<dyn EffectJournalStore>>,
    keeper: Option<Box<dyn EffectJournalStore>>,
    pin_root_created: bool,
    switch_journal: Option<Box<dyn EffectJournalStore>>,
    pin_retainer: Option<Box<dyn EffectPinRetainer>>,
    switch: Option<PinRetainedEffectJournal>,
    outcome: Option<Outcome>,
}

type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// A single region-owned creation attempt.
#[must_use = "join active work and retain the exact creation state"]
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    completed: Option<Outcome>,
    fenced: bool,
}

/// All original inputs and any partial stores after a drained attempt.
#[must_use = "attach ready supplies or inspect partial creation"]
pub struct Retirement {
    /// Original creation inputs, including the original switch-custody choice.
    pub inputs: Option<Inputs>,
    /// Whether exclusive root creation returned success.
    pub root_created: bool,
    /// Created publication store, if that operation returned success.
    pub journal: Option<Box<dyn EffectJournalStore>>,
    /// Created keeper store, if that operation returned success.
    pub keeper: Option<Box<dyn EffectJournalStore>>,
    /// Whether pin-root creation returned success.
    pub pin_root_created: bool,
    /// Created but not yet bound switch journal, if any.
    pub switch_journal: Option<Box<dyn EffectJournalStore>>,
    /// Created but not yet bound pin custodian, if any.
    pub pin_retainer: Option<Box<dyn EffectPinRetainer>>,
    /// New switch after successful binding, if any.
    pub switch: Option<PinRetainedEffectJournal>,
    /// Final outcome, or `None` if no attempt ran.
    pub outcome: Option<Outcome>,
    /// A panic or uncertain result requires reconciliation.
    pub fenced: bool,
}

/// Fresh supplies together with their original storage path and authority.
#[must_use = "retain the path and authority for recovery and attach the supplies"]
pub struct Created {
    /// Original exclusive creation directory.
    pub root: PathBuf,
    /// Replay authority bound to the directory's parent.
    pub replay: Arc<ReplayCx>,
    /// Filesystem capability used to create the stores.
    pub io: Arc<dyn SpoolIo>,
    /// Exact limits needed to inspect or reopen these stores.
    pub journal_limits: EffectJournalLimits,
    /// Original pin-custody configuration when this worker created it.
    pub switch_custody: Option<SwitchCustody>,
    /// Fresh stores and the caller's retained switch.
    pub supplies: av_rollover_worker::Supplies,
}

impl Retirement {
    /// Transfer ready stores exactly once. Failure leaves all owners intact.
    pub fn take_supplies(&mut self) -> Option<Created> {
        if self.fenced
            || self.outcome != Some(Outcome::Ready)
            || self.inputs.is_none()
            || self.journal.is_none()
            || self.keeper.is_none()
            || self.inputs.as_ref().is_some_and(|inputs| {
                matches!(inputs.switch, SwitchInput::Create(_)) && self.switch.is_none()
            })
        {
            return None;
        }
        let inputs = self.inputs.take()?;
        let journal = self.journal.take()?;
        let keeper = self.keeper.take()?;
        let (switch, switch_custody) = match inputs.switch {
            SwitchInput::Prepared(switch) => (switch, None),
            SwitchInput::Create(custody) => (self.switch.take()?, Some(custody)),
        };
        self.outcome = None;
        Some(Created {
            root: inputs.root,
            replay: inputs.replay,
            io: inputs.io,
            journal_limits: inputs.journal_limits,
            switch_custody,
            supplies: av_rollover_worker::Supplies {
                next_journal: journal,
                next_keeper: keeper,
                switch,
                read: inputs.read,
                object_limits: inputs.object_limits,
                work_limit: inputs.work_limit,
            },
        })
    }
}

impl Worker {
    /// Validate configuration without I/O or consuming inputs on refusal.
    pub fn new(inputs: Inputs) -> Result<Self, Inputs> {
        let root = &inputs.root;
        let valid = root.is_absolute()
            && root.file_name().is_some()
            && root.parent() == Some(inputs.replay.root_dir())
            && root
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && (1..=8192).contains(&inputs.object_limits.max_objects)
            && inputs.object_limits.max_object_bytes > 0
            && (1..=256 * 1024 * 1024).contains(&inputs.object_limits.max_total_bytes)
            && (1..=100_000_000_000).contains(&inputs.work_limit)
            && (1..=65_536).contains(&inputs.journal_limits.max_records)
            && (1..=512 * 1024).contains(&inputs.journal_limits.max_record_bytes)
            && (1..=1024 * 1024 * 1024).contains(&inputs.journal_limits.max_total_bytes)
            && inputs.journal_limits.max_read_bytes > 0
            && match &inputs.switch {
                SwitchInput::Prepared(_) => true,
                SwitchInput::Create(custody) => {
                    custody.root.is_absolute()
                        && custody.root.file_name().is_some()
                        && custody.root.parent() == Some(custody.replay.root_dir())
                        && custody
                            .root
                            .components()
                            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                        && !custody.root.starts_with(root)
                        && !root.starts_with(&custody.root)
                        && custody.scope.algorithm() == DigestAlgorithm::Sha256
                        && !custody.scope.is_laboratory()
                        && custody.scope.bytes() != [0; 32]
                        && (1..=65_536).contains(&custody.limits.max_records)
                        && (1..=512 * 1024).contains(&custody.limits.max_record_bytes)
                        && (1..=1024 * 1024 * 1024).contains(&custody.limits.max_total_bytes)
                        && custody.limits.max_read_bytes > 0
                }
            };
        if !valid {
            return Err(inputs);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                inputs,
                root_created: false,
                journal: None,
                keeper: None,
                pin_root_created: false,
                switch_journal: None,
                pin_retainer: None,
                switch: None,
                outcome: None,
            })),
            running: None,
            completed: None,
            fenced: false,
        })
    }

    /// Admit exactly one blocking creation attempt under the supplied grant.
    pub fn start<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        if self.fenced || self.completed.is_some() {
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
            let resource = state.inputs.root.to_str().ok_or(StartError::Context)?;
            task.checkpoint_for(RuntimeGrant::ObjectStage, resource, now, cost)
                .map_err(StartError::Task)?;
            if let SwitchInput::Create(custody) = &state.inputs.switch {
                let resource = custody.root.to_str().ok_or(StartError::Context)?;
                task.checkpoint_for(
                    RuntimeGrant::ObjectStage,
                    resource,
                    now,
                    &BudgetVector::ZERO,
                )
                .map_err(StartError::Task)?;
                custody
                    .replay
                    .checkpoint("unifi-rollover-pin-admit")
                    .map_err(|_| StartError::Replay)?;
            }
            state
                .inputs
                .replay
                .checkpoint("unifi-rollover-supplies-admit")
                .map_err(|_| StartError::Replay)?;
        }
        let state = Arc::clone(&self.state);
        let job: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            let checkpoint = |state: &State| {
                if child.is_cancel_requested() {
                    Err(Outcome::Cancelled)
                } else if state
                    .inputs
                    .replay
                    .checkpoint("unifi-rollover-supplies-create")
                    .is_err()
                {
                    Err(Outcome::Refused(Stage::Checkpoint))
                } else if let SwitchInput::Create(custody) = &state.inputs.switch {
                    custody
                        .replay
                        .checkpoint("unifi-rollover-pin-create")
                        .map_err(|_| Outcome::Refused(Stage::Checkpoint))
                } else {
                    Ok(())
                }
            };
            if let Err(outcome) = checkpoint(&state) {
                state.outcome = Some(outcome);
                return;
            }
            if create_private_root(&state.inputs.root).is_err() {
                state.outcome = Some(Outcome::Refused(Stage::Root));
                return;
            }
            state.root_created = true;
            if let Err(outcome) = checkpoint(&state) {
                state.outcome = Some(outcome);
                return;
            }
            if state
                .inputs
                .io
                .sync_directory(state.inputs.replay.root_dir())
                .is_err()
            {
                state.outcome = Some(Outcome::Refused(Stage::Root));
                return;
            }
            if let Err(outcome) = checkpoint(&state) {
                state.outcome = Some(outcome);
                return;
            }
            let journal = FileEffectJournal::create(
                state.inputs.root.join("journal"),
                state.inputs.journal_limits,
                state.inputs.io.clone(),
            );
            match journal {
                Ok(store) => state.journal = Some(Box::new(store)),
                Err(_) => {
                    state.outcome = Some(Outcome::Refused(Stage::Journal));
                    return;
                }
            }
            if let Err(outcome) = checkpoint(&state) {
                state.outcome = Some(outcome);
                return;
            }
            let keeper = FileEffectJournal::create(
                state.inputs.root.join("keeper"),
                state.inputs.journal_limits,
                state.inputs.io.clone(),
            );
            match keeper {
                Ok(store) => state.keeper = Some(Box::new(store)),
                Err(_) => {
                    state.outcome = Some(Outcome::Refused(Stage::Keeper));
                    return;
                }
            }
            if matches!(state.inputs.switch, SwitchInput::Create(_)) {
                if let Err(outcome) = checkpoint(&state) {
                    state.outcome = Some(outcome);
                    return;
                }
                let SwitchInput::Create(custody) = &state.inputs.switch else {
                    state.outcome = Some(Outcome::Indeterminate);
                    return;
                };
                if create_private_root(&custody.root).is_err() {
                    state.outcome = Some(Outcome::Refused(Stage::PinRoot));
                    return;
                }
                state.pin_root_created = true;
                if let Err(outcome) = checkpoint(&state) {
                    state.outcome = Some(outcome);
                    return;
                }
                let SwitchInput::Create(custody) = &state.inputs.switch else {
                    state.outcome = Some(Outcome::Indeterminate);
                    return;
                };
                if custody
                    .io
                    .sync_directory(custody.replay.root_dir())
                    .is_err()
                {
                    state.outcome = Some(Outcome::Refused(Stage::PinRoot));
                    return;
                }
                if let Err(outcome) = checkpoint(&state) {
                    state.outcome = Some(outcome);
                    return;
                }
                let SwitchInput::Create(custody) = &state.inputs.switch else {
                    state.outcome = Some(Outcome::Indeterminate);
                    return;
                };
                match FileTrustedRootPinRetainer::create(
                    &custody.root,
                    custody.limits,
                    custody.io.clone(),
                    custody.scope,
                ) {
                    Ok(retainer) => state.pin_retainer = Some(Box::new(retainer)),
                    Err(_) => {
                        state.outcome = Some(Outcome::Refused(Stage::PinRetainer));
                        return;
                    }
                }
                if let Err(outcome) = checkpoint(&state) {
                    state.outcome = Some(outcome);
                    return;
                }
                match FileEffectJournal::create(
                    state.inputs.root.join("switch"),
                    state.inputs.journal_limits,
                    state.inputs.io.clone(),
                ) {
                    Ok(store) => state.switch_journal = Some(Box::new(store)),
                    Err(_) => {
                        state.outcome = Some(Outcome::Refused(Stage::SwitchJournal));
                        return;
                    }
                }
                if let Err(outcome) = checkpoint(&state) {
                    state.outcome = Some(outcome);
                    return;
                }
                let (journal, retainer) =
                    match (state.switch_journal.take(), state.pin_retainer.take()) {
                        (Some(journal), Some(retainer)) => (journal, retainer),
                        (journal, retainer) => {
                            state.switch_journal = journal;
                            state.pin_retainer = retainer;
                            state.outcome = Some(Outcome::Indeterminate);
                            return;
                        }
                    };
                match PinRetainedEffectJournal::try_new(journal, retainer) {
                    Ok(switch) => state.switch = Some(switch),
                    Err(refusal) => {
                        state.switch_journal = Some(refusal.journal);
                        state.pin_retainer = Some(refusal.retainer);
                        state.outcome = Some(Outcome::Refused(Stage::SwitchBinding));
                        return;
                    }
                }
            }
            state.outcome =
                Some(checkpoint(&state).map_or_else(|outcome| outcome, |()| Outcome::Ready));
        });
        match drained_blocking::start(cx, job) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation; the worker must still be joined.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }
    /// Whether runtime cancellation has been observed.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }
    /// Join the single operation and retain all creation state.
    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(job) => {
                drop(job);
                Outcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(state) => state.outcome.unwrap_or_else(|| {
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
        if receipt.runtime.is_err() || matches!(outcome, Outcome::Panicked | Outcome::Indeterminate)
        {
            self.fenced = true;
        }
        self.completed = Some(outcome);
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }
    /// Recover all inputs and partial store owners after draining.
    pub fn retire(self) -> Result<Retirement, Self> {
        if self.running.is_some() {
            return Err(self);
        }
        let Self {
            state,
            running,
            completed,
            fenced,
        } = self;
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let state = state
                    .into_inner()
                    .unwrap_or_else(|poison| poison.into_inner());
                Ok(Retirement {
                    inputs: Some(state.inputs),
                    root_created: state.root_created,
                    journal: state.journal,
                    keeper: state.keeper,
                    pin_root_created: state.pin_root_created,
                    switch_journal: state.switch_journal,
                    pin_retainer: state.pin_retainer,
                    switch: state.switch,
                    outcome: completed,
                    fenced,
                })
            }
            Err(state) => Err(Self {
                state,
                running,
                completed,
                fenced,
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
