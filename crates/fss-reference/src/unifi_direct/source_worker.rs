#![forbid(unsafe_code)]
//! Cancellation-drained publication of one separately returned source record.
//!
//! This is a task-owned building block. It neither starts a recorder service
//! nor authenticates a camera, establishes capture time, or grants retention.

use std::sync::{Arc, Mutex, TryLockError};

use asupersync::{Cx, runtime::JoinError};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, RuntimeGrant};
use fss_geometry::WorkBudget;
use fss_packet::extended_flv::stream::SourceRecord;
use fss_publication::RootLedgerReceipt;
use fss_runtime::{
    drained_blocking::{self, Drained, WorkOutcome},
    effect_journal::EffectJournalPin,
    execution::TaskCx,
};

use super::{
    archive,
    av_worker::{self, StartError},
    metered::MeteredClock,
    recording::SourceDisposition,
    source_evidence,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Original or verified recovered source held by the worker.
pub enum Input {
    /// An original record and its caller-supplied, unverified claims.
    Original {
        /// Exact original record; retained on refusal or uncertainty.
        record: SourceRecord,
        /// Caller-bound source connection and generation.
        key: SourceKey,
        /// Caller-supplied reason the record was returned separately.
        disposition: SourceDisposition,
        /// Caller-bound camera claim, not independently authenticated identity.
        camera_claim: ContentDigest,
    },
    /// A source recovered through an authorized ledgered or staged read.
    Recovered(archive::RecoveredSource),
}
impl Input {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Original { record, .. } => record.bytes(),
            Self::Recovered(source) => source.bytes(),
        }
    }
}

/// Exclusive archive owners for a dedicated standalone-source journal.
pub struct Parts {
    /// Archive deployment; a different live owner cannot share it concurrently.
    pub deployment: ReferenceDeployment,
    /// Dedicated unknown-time publication intent history.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Independently retained history of journal anchors.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Explicit archive and cancellation authority.
    pub replay: ReplayCx,
    /// Current retention authorization, rechecked during publication.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Retention decision identity; this digest is not itself authority.
    pub retention: ContentDigest,
    /// Archive limits.
    pub limits: archive::Limits,
    /// Maximum bytes in one original record, at most 64 MiB.
    pub max_source_bytes: usize,
    /// Maximum work per publication attempt.
    pub work_limit: u64,
}

/// A refused offer returns the unchanged original input.
#[must_use]
pub enum OfferRefusal {
    /// A previous record or attempt is still owned.
    Busy(Input),
    /// The record or caller claims failed bounded preparation.
    Invalid(Input),
    /// A previous panic, poisoned lock, or uncertain outcome fenced this owner.
    Fenced(Input),
}

/// Publication result, distinct from runtime task completion.
pub enum Publication {
    /// Ledger and journal confirmation completed.
    Published {
        /// Exact unknown-time root and retention decision.
        pin: archive::UnknownTimePin,
        /// Actual ledger receipt.
        receipt: RootLedgerReceipt,
    },
    /// Source preparation or publication refused; the record remains owned.
    Refused {
        /// Exact candidate if preparation succeeded.
        pin: Option<archive::UnknownTimePin>,
        /// Bounded preparation, work admission, or publication failure.
        reason: Refusal,
    },
}

/// Why a source was retained instead of confirmed as published.
pub enum Refusal {
    /// Source graph preparation refused the input.
    Preparation(source_evidence::Error),
    /// Work allowance or cancellation stopped preparation.
    Work,
    /// The candidate conflicts with the journal's pending or replay pin.
    Candidate,
    /// Journal preparation or independent anchoring did not complete.
    BeforePublication(av_worker::FailureReason),
    /// Staging or root publication did not complete cleanly.
    Archive(av_worker::FailureReason),
    /// A receipt exists but confirmation or its anchor requires reconciliation.
    AfterPublication {
        /// Payload-free journal failure classification.
        reason: av_worker::FailureReason,
        /// The actual ledger receipt, preserved for reconciliation.
        receipt: Box<RootLedgerReceipt>,
    },
}

/// Outcome of the fully drained blocking closure.
pub enum Outcome {
    /// The closure never started; the original record remains pending.
    NotStarted,
    /// The closure produced a publication classification.
    Publication(Publication),
    /// The closure panicked and must be reconciled.
    Panicked,
    /// The coordinator could not establish the closure outcome.
    Indeterminate,
}

/// Runtime and publication outcomes after the blocking closure has drained.
pub struct Completion {
    /// Runtime task classification.
    pub runtime: Result<(), JoinError>,
    /// Actual publication classification.
    pub outcome: Outcome,
}

/// Whether a separate source must be dealt with before polling more media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// No original source or attempt is held.
    Idle,
    /// A source is held without a running publication attempt.
    Pending,
    /// A publication attempt must be joined or drained.
    Running,
    /// An uncertain outcome requires reconciliation.
    Fenced,
    /// The source state could not be inspected; do not resume media.
    Unavailable,
}

/// Exclusive storage and any unresolved original source returned at retirement.
#[must_use]
pub struct Retirement {
    /// Archive, journals, policy and replay owners.
    pub parts: Parts,
    /// Original source not released after a confirmed successful publication.
    pub pending: Option<Input>,
    /// Panic or uncertainty requires explicit reconciliation.
    pub fenced: bool,
    /// Custody for every attached rollover transition.
    pub rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}

struct State {
    parts: Parts,
    pending: Option<Input>,
    report: Option<Publication>,
    rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}

/// Source resources and the exact pending input held during rollover.
#[must_use = "restore the predecessor or attach a verified successor"]
pub struct RolloverResources {
    deployment: ReferenceDeployment,
    replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    retention: ContentDigest,
    limits: archive::Limits,
    max_source_bytes: usize,
    work_limit: u64,
    pending: Option<Input>,
    original_scope: ContentDigest,
    original_journal: EffectJournalPin,
    original_keeper: EffectJournalPin,
    prior_custody: Option<archive::journal::rollover::WorkerCustody>,
}

/// Refusal preserves the resources and active successor.
#[must_use = "reconcile or restore the returned owners"]
pub struct RolloverAttachRefusal {
    /// Resources, including any pending original input.
    pub resources: RolloverResources,
    /// The transition which could not be attached.
    pub active: archive::journal::rollover::Active,
}

/// Refusal to restore a different predecessor preserves both owners.
#[must_use = "inspect the returned predecessor and resources"]
pub struct RolloverRestoreRefusal {
    /// Resources, including any pending original input.
    pub resources: RolloverResources,
    /// Predecessor that did not match the original heads.
    pub previous: archive::journal::rollover::Previous,
}

fn valid_configuration(work_limit: u64, max_source_bytes: usize, retention: ContentDigest) -> bool {
    (1..=100_000_000_000).contains(&work_limit)
        && (1..=64 * 1024 * 1024).contains(&max_source_bytes)
        && retention.algorithm() == DigestAlgorithm::Sha256
        && !retention.is_laboratory()
        && retention.bytes() != [0; 32]
}

fn valid_input(input: &Input, parts: &Parts) -> bool {
    match input {
        Input::Original {
            record,
            key,
            disposition,
            camera_claim,
        } => source_evidence::validate_input(
            record,
            *key,
            *disposition,
            *camera_claim,
            parts.retention,
            parts.max_source_bytes,
        )
        .is_ok(),
        Input::Recovered(source) => {
            source.retention == parts.retention
                && !source.bytes().is_empty()
                && source.bytes().len() <= parts.max_source_bytes
        }
    }
}

impl Retirement {
    /// Detach an unfenced worker's resources and predecessor; a pending input
    /// remains owned, as does any earlier verified transition custody.
    pub fn into_rollover(
        mut self,
    ) -> Result<(RolloverResources, archive::journal::rollover::Previous), Self> {
        if self.fenced
            || !valid_configuration(
                self.parts.work_limit,
                self.parts.max_source_bytes,
                self.parts.retention,
            )
            || self
                .parts
                .journal
                .confirmed()
                .is_none_or(|pin| pin.retention != self.parts.retention)
            || self
                .pending
                .as_ref()
                .is_some_and(|input| !valid_input(input, &self.parts))
        {
            return Err(self);
        }
        if let Some(custody) = &mut self.rollover_custody {
            if custody
                .check(&self.parts.journal, &self.parts.keeper, &self.parts.replay)
                .is_err()
                || !custody.reserve_next()
            {
                return Err(self);
            }
        }
        let Parts {
            deployment,
            journal,
            keeper,
            replay,
            authority,
            retention,
            limits,
            max_source_bytes,
            work_limit,
        } = self.parts;
        let resources = RolloverResources {
            deployment,
            replay,
            authority,
            retention,
            limits,
            max_source_bytes,
            work_limit,
            pending: self.pending,
            original_scope: journal.scope(),
            original_journal: journal.anchor(),
            original_keeper: keeper.anchor(),
            prior_custody: self.rollover_custody,
        };
        Ok((
            resources,
            archive::journal::rollover::Previous { journal, keeper },
        ))
    }
}

impl RolloverResources {
    /// Existing scoped replay authority for staging and committing the successor.
    pub fn replay(&self) -> &ReplayCx {
        &self.replay
    }

    /// Whether a source is held during the transition.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Revalidate and replay the rolled source against this worker's archive.
    pub fn replay_confirmed_source(
        &mut self,
        active: &mut archive::journal::rollover::Active,
        camera_claim: ContentDigest,
        read: &dyn archive::ReadAuthority,
        work: &mut WorkBudget<'_>,
    ) -> Result<RootLedgerReceipt, archive::journal::rollover::SourceReplayError> {
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.retention
        {
            return Err(archive::journal::rollover::SourceReplayError::History(
                archive::journal::Error::Invalid,
            ));
        }
        if let Some(prior) = &mut self.prior_custody {
            active
                .check_prior(prior, &self.replay)
                .map_err(archive::journal::rollover::SourceReplayError::History)?;
        }
        active.replay_confirmed_source(
            &mut self.deployment,
            camera_claim,
            read,
            self.authority.as_ref(),
            self.limits,
            work,
            &self.replay,
        )
    }

    /// Restore the exact original predecessor after an uncommitted transition.
    pub fn restore(
        self,
        previous: archive::journal::rollover::Previous,
    ) -> Result<Retirement, RolloverRestoreRefusal> {
        if previous.journal.scope() != self.original_scope
            || previous.journal.anchor() != self.original_journal
            || previous.keeper.anchor() != self.original_keeper
        {
            return Err(RolloverRestoreRefusal {
                resources: self,
                previous,
            });
        }
        Ok(Retirement {
            parts: Parts {
                deployment: self.deployment,
                journal: previous.journal,
                keeper: previous.keeper,
                replay: self.replay,
                authority: self.authority,
                retention: self.retention,
                limits: self.limits,
                max_source_bytes: self.max_source_bytes,
                work_limit: self.work_limit,
            },
            pending: self.pending,
            fenced: false,
            rollover_custody: self.prior_custody,
        })
    }

    /// Attach a replayed successor, retaining rollover custody in the worker.
    /// On refusal both resources and transition remain available.
    pub fn attach(
        mut self,
        active: archive::journal::rollover::Active,
    ) -> Result<Worker, RolloverAttachRefusal> {
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.retention
            || !valid_configuration(self.work_limit, self.max_source_bytes, self.retention)
        {
            return Err(RolloverAttachRefusal {
                resources: self,
                active,
            });
        }
        if let Some(prior) = &mut self.prior_custody {
            if active.check_prior(prior, &self.replay).is_err() {
                return Err(RolloverAttachRefusal {
                    resources: self,
                    active,
                });
            }
        }
        let (journal, keeper, custody) = match active.into_worker_parts(&self.replay) {
            Ok(parts) => parts,
            Err(active) => {
                return Err(RolloverAttachRefusal {
                    resources: self,
                    active,
                });
            }
        };
        let custody = match self.prior_custody {
            Some(mut prior) => {
                prior.append(custody);
                prior
            }
            None => custody,
        };
        let parts = Parts {
            deployment: self.deployment,
            journal,
            keeper,
            replay: self.replay,
            authority: self.authority,
            retention: self.retention,
            limits: self.limits,
            max_source_bytes: self.max_source_bytes,
            work_limit: self.work_limit,
        };
        Ok(Worker {
            state: Arc::new(Mutex::new(State {
                parts,
                pending: self.pending,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One bounded source and at most one region-owned blocking attempt.
#[must_use = "join any running attempt and retire the source and storage owners"]
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

struct CurrentRetention<'a> {
    cx: &'a Cx,
    inner: &'a dyn archive::RetainAuthority,
}
impl archive::RetainAuthority for CurrentRetention<'_> {
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool {
        self.cx.checkpoint().is_ok() && self.inner.permits(retention, root)
    }
}

impl Worker {
    /// Whether an archive attempt still needs to be joined or drained.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Inspect custody without waiting for the archival worker's lock.
    #[must_use]
    pub fn status(&self) -> Status {
        if self.fenced {
            return Status::Fenced;
        }
        if self.running.is_some() {
            return Status::Running;
        }
        match self.state.try_lock() {
            Ok(state) if state.pending.is_some() => Status::Pending,
            Ok(_) => Status::Idle,
            Err(_) => Status::Unavailable,
        }
    }

    /// Construct without I/O; invalid limits return all owners unchanged.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if !valid_configuration(parts.work_limit, parts.max_source_bytes, parts.retention) {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                pending: None,
                report: None,
                rollover_custody: None,
            })),
            running: None,
            fenced: false,
        })
    }

    /// Reattach a replayed cold-recovered lineage to a new source worker.
    /// Refusal returns both the supplied resources and all switch owners.
    pub fn from_recovered(
        parts: Parts,
        mut custody: archive::journal::rollover::WorkerCustody,
    ) -> Result<Self, (Parts, archive::journal::rollover::WorkerCustody)> {
        if !valid_configuration(parts.work_limit, parts.max_source_bytes, parts.retention)
            || parts
                .journal
                .confirmed()
                .is_none_or(|pin| pin.retention != parts.retention)
            || custody
                .check(&parts.journal, &parts.keeper, &parts.replay)
                .is_err()
        {
            return Err((parts, custody));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                pending: None,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }

    /// Transfer one exact source into the idle worker; refusal returns it.
    pub fn offer(&mut self, input: Input) -> Result<(), OfferRefusal> {
        if self.fenced {
            return Err(OfferRefusal::Fenced(input));
        }
        if self.running.is_some() {
            return Err(OfferRefusal::Busy(input));
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(OfferRefusal::Busy(input)),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                return Err(OfferRefusal::Fenced(input));
            }
        };
        if state.pending.is_some() {
            return Err(OfferRefusal::Busy(input));
        }
        let valid = valid_input(&input, &state.parts);
        if !valid {
            return Err(OfferRefusal::Invalid(input));
        }
        state.pending = Some(input);
        Ok(())
    }

    /// Start a task-admitted archive attempt; no inline blocking fallback exists.
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
        match self.state.try_lock() {
            Ok(state) if state.pending.is_none() => return Err(StartError::Empty),
            Ok(_) => (),
            Err(_) => {
                self.fenced = true;
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
        let work: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            let State {
                parts,
                pending,
                report,
                rollover_custody,
            } = &mut *state;
            let Some(input) = pending.as_ref() else {
                return;
            };
            if child.is_cancel_requested() {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::BeforePublication(av_worker::FailureReason::CancelledOrDenied),
                });
                return;
            }
            if let Some(custody) = rollover_custody {
                if let Err(error) = custody.check(&parts.journal, &parts.keeper, &parts.replay) {
                    *report = Some(Publication::Refused {
                        pin: None,
                        reason: Refusal::BeforePublication(av_worker::journal_reason(error)),
                    });
                    return;
                }
            }
            if child.is_cancel_requested() {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::BeforePublication(av_worker::FailureReason::CancelledOrDenied),
                });
                return;
            }
            let cancel = || child.is_cancel_requested();
            let mut budget = WorkBudget::with_cancellation_probe(parts.work_limit, &cancel);
            let Some(preparation_cost) = (input.bytes().len() as u64).checked_mul(2) else {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::Work,
                });
                return;
            };
            if budget.charge(preparation_cost).is_err() {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::Work,
                });
                return;
            }
            let prepared = match input {
                Input::Original {
                    record,
                    key,
                    disposition,
                    camera_claim,
                } => source_evidence::Prepared::new(
                    record,
                    *key,
                    *disposition,
                    *camera_claim,
                    parts.retention,
                    parts.max_source_bytes,
                ),
                Input::Recovered(source) => Ok(source_evidence::Prepared::from_recovered(source)),
            };
            let plan = match prepared {
                Ok(plan) => plan,
                Err(error) => {
                    *report = Some(Publication::Refused {
                        pin: None,
                        reason: Refusal::Preparation(error),
                    });
                    return;
                }
            };
            let pin = archive::UnknownTimePin::from_source_plan(&plan);
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            *report = Some(
                match archive::publish_unknown_time_source_anchored(
                    &plan,
                    &mut parts.deployment,
                    &access,
                    parts.limits,
                    &mut budget,
                    &parts.replay,
                    &mut parts.journal,
                    &mut parts.keeper,
                ) {
                    Ok(receipt) => Publication::Published { pin, receipt },
                    Err(error) => {
                        let reason = match error {
                            archive::UnknownTimePublishError::Candidate => Refusal::Candidate,
                            archive::UnknownTimePublishError::BeforePublication(error) => {
                                Refusal::BeforePublication(av_worker::journal_reason(error))
                            }
                            archive::UnknownTimePublishError::Archive(error) => Refusal::Archive(
                                av_worker::archive_reason(error, child.is_cancel_requested()),
                            ),
                            archive::UnknownTimePublishError::AfterPublication {
                                receipt,
                                source,
                            } => Refusal::AfterPublication {
                                reason: av_worker::journal_reason(source),
                                receipt,
                            },
                        };
                        Publication::Refused {
                            pin: Some(pin),
                            reason,
                        }
                    }
                },
            );
        });
        match drained_blocking::start(cx, work) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation; source and storage remain owned until joined.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether the blocking coordinator observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Join the exact attempt before releasing any owner.
    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(work) => {
                drop(work);
                Outcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => match state.report.take() {
                    Some(report) => {
                        if receipt.runtime.is_ok()
                            && matches!(report, Publication::Published { .. })
                        {
                            drop(state.pending.take());
                        } else if receipt.runtime.is_err() {
                            self.fenced = true;
                        }
                        Outcome::Publication(report)
                    }
                    None => {
                        self.fenced = true;
                        Outcome::Indeterminate
                    }
                },
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

    /// Return all owners only when no attempt remains running.
    pub fn retire(self) -> Result<Retirement, Self> {
        let Self {
            state,
            running,
            fenced,
        } = self;
        if running.is_some() {
            return Err(Self {
                state,
                running,
                fenced,
            });
        }
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let state = state
                    .into_inner()
                    .unwrap_or_else(|error| error.into_inner());
                Ok(Retirement {
                    parts: state.parts,
                    pending: state.pending,
                    fenced,
                    rollover_custody: state.rollover_custody,
                })
            }
            Err(state) => Err(Self {
                state,
                running: None,
                fenced,
            }),
        }
    }
}
