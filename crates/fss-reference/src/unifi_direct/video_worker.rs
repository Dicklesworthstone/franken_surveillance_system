#![forbid(unsafe_code)]
//! Task-admitted, cancellation-drained unknown-time video archive worker.
//!
//! The worker owns its source and storage while one bounded blocking operation
//! runs. It does not supervise a camera or grant retry or retention authority.

use std::sync::{Arc, Mutex, TryLockError};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_geometry::WorkBudget;
use fss_runtime::{
    drained_blocking::{self, Drained, WorkOutcome},
    execution::TaskCx,
};

use super::{
    archive,
    av_worker::{self, StartError},
    evidence,
    metered::MeteredClock,
    recording, video_owned_sink,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Exclusive source, archive and authority owners for this worker.
pub struct Parts {
    /// Video configuration and any pending original segment.
    pub sink: video_owned_sink::Sink,
    /// Exclusive archive deployment.
    pub deployment: ReferenceDeployment,
    /// Unknown-time intent history.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Separate owner of journal anchor history.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Filesystem and cancellation authority for archive operations.
    pub replay: ReplayCx,
    /// Retention authority, revalidated during publication.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Archive limits for each attempt.
    pub limits: archive::Limits,
    /// Maximum work units per attempt, at most 100 billion.
    pub work_limit: u64,
}

/// A refused offer returns its unconsumed segment.
#[must_use]
pub enum OfferRefusal {
    /// A source or running task is already owned.
    Busy(recording::Segment),
    /// An uncertain or poisoned worker must be retired.
    Fenced(recording::Segment),
    /// The sink refused the source without consuming it.
    Sink(video_owned_sink::OfferRefusal),
}

/// Why a source remains owned after an attempt.
#[derive(Debug)]
pub enum Refusal {
    /// Cancellation was observed before archive work began.
    Cancelled,
    /// Bounded work admission failed.
    Work,
    /// Source or derivative validation refused.
    Preparation(evidence::Error),
    /// No source or the proposed candidate conflicted with retained state.
    Candidate,
    /// Journal preparation or anchoring refused.
    BeforePublication(av_worker::FailureReason),
    /// Staging or publication refused or may be indeterminate.
    Archive(av_worker::FailureReason),
    /// Publication returned a receipt but confirmation or anchoring failed.
    AfterPublication {
        /// Payload-free failure category.
        reason: av_worker::FailureReason,
        /// The actual receipt, retained for reconciliation.
        receipt: Box<fss_publication::RootLedgerReceipt>,
    },
}

/// Full domain outcome, independent of the runtime join classification.
#[must_use]
pub enum Publication {
    /// Ledger and journal confirmation completed; the original segment is returned.
    Published(video_owned_sink::Published),
    /// The source remains with the worker and may require reconciliation.
    Refused {
        /// Exact retained candidate, if preparation completed.
        pending: Option<archive::UnknownTimePin>,
        /// Payload-free failure and any actual receipt.
        reason: Refusal,
    },
}

/// Result after the blocking closure has drained.
#[must_use]
pub enum Outcome {
    /// The closure never started; the source remains pending.
    NotStarted,
    /// The closure returned a domain outcome.
    Publication(Publication),
    /// The closure panicked and must be reconciled.
    Panicked,
    /// The closure outcome could not be established.
    Indeterminate,
}

/// Runtime result and independently preserved publication outcome.
#[must_use]
pub struct Completion {
    /// Runtime classification after drain.
    pub runtime: Result<(), JoinError>,
    /// Actual domain outcome.
    pub outcome: Outcome,
}

/// Exact state after retirement; a report must not be silently discarded.
#[must_use]
pub struct Retirement {
    /// Original source and storage owners.
    pub parts: Parts,
    /// Report retained if a join could not recover it.
    pub report: Option<Publication>,
    /// Panic, poison or uncertain runtime result requires reconciliation.
    pub fenced: bool,
    /// Prior journal transitions that must remain in custody.
    pub rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}

/// Video sink, pending segment and storage held during a journal transition.
#[must_use = "restore the predecessor or attach a verified successor"]
pub struct RolloverResources {
    sink: video_owned_sink::Sink,
    deployment: ReferenceDeployment,
    replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    limits: archive::Limits,
    work_limit: u64,
    original_scope: ContentDigest,
    original_journal: fss_runtime::effect_journal::EffectJournalPin,
    original_keeper: fss_runtime::effect_journal::EffectJournalPin,
    prior_custody: Option<archive::journal::rollover::WorkerCustody>,
    verified_replay: Option<(
        archive::journal::rollover::Binding,
        fss_runtime::effect_journal::EffectJournalPin,
    )>,
}

/// Restore refusal retains the exact resources and supplied predecessor.
#[must_use]
pub struct RolloverRestoreRefusal {
    /// Video source and storage owners.
    pub resources: RolloverResources,
    /// Predecessor which did not match the saved heads.
    pub previous: archive::journal::rollover::Previous,
}

/// Attach refusal retains the exact resources and active transition.
#[must_use]
pub struct RolloverAttachRefusal {
    /// Video source and storage owners.
    pub resources: RolloverResources,
    /// Transition requiring reconciliation.
    pub active: archive::journal::rollover::Active,
}

/// A successor whose storage and lineage were checked on a blocking worker.
#[must_use = "attach or retain the checked successor and its custody"]
pub struct PreparedAttachment {
    binding: archive::journal::rollover::Binding,
    switch_head: fss_runtime::effect_journal::EffectJournalPin,
    journal: archive::journal::UnknownTimeJournal,
    keeper: archive::journal::UnknownTimeAnchorKeeper,
    custody: archive::journal::rollover::WorkerCustody,
}

/// A refused prepared attachment retains both owners.
#[must_use]
pub struct PreparedAttachRefusal {
    /// Pending source and original archive resources.
    pub resources: RolloverResources,
    /// Checked successor and transition custody.
    pub attachment: PreparedAttachment,
}

/// A single-use, in-memory check of the settled video predecessor.
pub struct VerifiedRolloverPause {
    scope: ContentDigest,
    confirmed: archive::UnknownTimePin,
    journal: fss_runtime::effect_journal::EffectJournalPin,
    keeper: fss_runtime::effect_journal::EffectJournalPin,
    transitions: usize,
}

/// Why a video predecessor cannot be safely prepared for a transition.
#[derive(Debug)]
pub enum RolloverPauseError {
    /// An unresolved journal, pending report or incompatible retention remains.
    NotReady,
    /// Existing transition custody failed verification.
    Custody(archive::journal::Error),
    /// Existing custody cannot retain another transition.
    Capacity,
}

impl Retirement {
    /// Detach the settled predecessor while retaining the exact video sink.
    /// A pending segment may remain, but an uncertain journal may not advance.
    pub fn into_rollover(
        mut self,
    ) -> Result<(RolloverResources, archive::journal::rollover::Previous), Self> {
        let verified = match self.verify_rollover_pause() {
            Ok(verified) => verified,
            Err(_) => return Err(self),
        };
        self.into_rollover_verified(verified)
    }

    /// Check history while borrowing the pending source owner.
    pub(crate) fn verify_rollover_pause(
        &mut self,
    ) -> Result<VerifiedRolloverPause, RolloverPauseError> {
        let Some(confirmed) = self.parts.journal.confirmed() else {
            return Err(RolloverPauseError::NotReady);
        };
        if self.fenced
            || self.report.is_some()
            || self.parts.journal.pending().is_some()
            || self.parts.journal.replay_pin().is_some()
            || self.parts.journal.anchor().sequence <= 3
            || self.parts.keeper.target() != self.parts.journal.anchor()
            || confirmed.retention != self.parts.sink.retention()
            || !(1..=100_000_000_000).contains(&self.parts.work_limit)
        {
            return Err(RolloverPauseError::NotReady);
        }
        if let Some(custody) = &mut self.rollover_custody {
            custody
                .check(&self.parts.journal, &self.parts.keeper, &self.parts.replay)
                .map_err(RolloverPauseError::Custody)?;
            if !custody.reserve_next() {
                return Err(RolloverPauseError::Capacity);
            }
        }
        Ok(VerifiedRolloverPause {
            scope: self.parts.journal.scope(),
            confirmed,
            journal: self.parts.journal.anchor(),
            keeper: self.parts.keeper.anchor(),
            transitions: self
                .rollover_custody
                .as_ref()
                .map_or(0, |c| c.transition_count()),
        })
    }

    /// Transfer only the predecessor validated by this single-use observation.
    pub(crate) fn into_rollover_verified(
        self,
        verified: VerifiedRolloverPause,
    ) -> Result<(RolloverResources, archive::journal::rollover::Previous), Self> {
        if self.fenced
            || self.report.is_some()
            || self.parts.journal.pending().is_some()
            || self.parts.journal.replay_pin().is_some()
            || self.parts.journal.anchor().sequence <= 3
            || self.parts.keeper.target() != self.parts.journal.anchor()
            || self.parts.journal.scope() != verified.scope
            || self.parts.journal.confirmed() != Some(verified.confirmed)
            || verified.confirmed.retention != self.parts.sink.retention()
            || self.parts.journal.anchor() != verified.journal
            || self.parts.keeper.anchor() != verified.keeper
            || self
                .rollover_custody
                .as_ref()
                .map_or(0, |c| c.transition_count())
                != verified.transitions
            || !(1..=100_000_000_000).contains(&self.parts.work_limit)
        {
            return Err(self);
        }
        let Parts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = self.parts;
        let resources = RolloverResources {
            sink,
            deployment,
            replay,
            authority,
            limits,
            work_limit,
            original_scope: journal.scope(),
            original_journal: journal.anchor(),
            original_keeper: keeper.anchor(),
            prior_custody: self.rollover_custody,
            verified_replay: None,
        };
        Ok((
            resources,
            archive::journal::rollover::Previous { journal, keeper },
        ))
    }
}

impl RolloverResources {
    /// Scoped replay authority used for the exact successor transition.
    pub fn replay(&self) -> &ReplayCx {
        &self.replay
    }

    /// Whether the original video sink retains an uncommitted segment.
    pub fn has_pending(&self) -> bool {
        self.sink.has_pending()
    }

    /// Verify and detach a replayed successor while the source owner remains borrowed.
    pub(crate) fn prepare_attachment(
        &mut self,
        active: archive::journal::rollover::Active,
    ) -> Result<PreparedAttachment, archive::journal::rollover::Active> {
        let binding = active.binding();
        let switch_head = active.switch_head();
        if binding.scope != self.original_scope
            || binding.old_journal != self.original_journal
            || binding.old_keeper != self.original_keeper
            || binding.confirmed.retention != self.sink.retention()
            || self.verified_replay != Some((binding, switch_head))
            || !(1..=100_000_000_000).contains(&self.work_limit)
        {
            return Err(active);
        }
        if let Some(prior) = &mut self.prior_custody {
            if active.check_prior(prior, &self.replay).is_err() {
                return Err(active);
            }
        }
        let (journal, keeper, custody) = active.into_worker_parts(&self.replay)?;
        let custody = match self.prior_custody.take() {
            Some(mut prior) => {
                prior.append(custody);
                prior
            }
            None => custody,
        };
        Ok(PreparedAttachment {
            binding,
            switch_head,
            journal,
            keeper,
            custody,
        })
    }

    /// Attach previously checked storage without another blocking storage read.
    pub(crate) fn attach_prepared(
        self,
        attachment: PreparedAttachment,
    ) -> Result<Worker, PreparedAttachRefusal> {
        let binding = attachment.binding;
        if binding.scope != self.original_scope
            || binding.old_journal != self.original_journal
            || binding.old_keeper != self.original_keeper
            || binding.confirmed.retention != self.sink.retention()
            || self.verified_replay != Some((binding, attachment.switch_head))
            || self.prior_custody.is_some()
            || !(1..=100_000_000_000).contains(&self.work_limit)
            || self
                .replay
                .checkpoint("unifi-video-prepared-attach")
                .is_err()
        {
            return Err(PreparedAttachRefusal {
                resources: self,
                attachment,
            });
        }
        let parts = Parts {
            sink: self.sink,
            deployment: self.deployment,
            journal: attachment.journal,
            keeper: attachment.keeper,
            replay: self.replay,
            authority: self.authority,
            limits: self.limits,
            work_limit: self.work_limit,
        };
        Ok(Worker {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
                rollover_custody: Some(attachment.custody),
            })),
            running: None,
            fenced: false,
        })
    }

    /// Verify and replay the confirmed predecessor root without consuming the
    /// pending segment or trusting a caller-supplied graph.
    pub fn replay_confirmed_video(
        &mut self,
        active: &mut archive::journal::rollover::Active,
        read: &dyn archive::ReadAuthority,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
    ) -> Result<fss_publication::RootLedgerReceipt, archive::journal::rollover::VideoReplayError>
    {
        use archive::journal::rollover::AvReplayError;
        self.verified_replay = None;
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.sink.retention()
        {
            return Err(AvReplayError::History(archive::journal::Error::Invalid));
        }
        if let Some(prior) = &mut self.prior_custody {
            active
                .check_prior(prior, &self.replay)
                .map_err(AvReplayError::History)?;
        }
        let receipt = active.replay_confirmed_video(
            &mut self.deployment,
            read,
            self.authority.as_ref(),
            self.limits,
            object_limits,
            work,
            &self.replay,
        )?;
        self.verified_replay = Some((active.binding(), active.switch_head()));
        Ok(receipt)
    }

    /// Restore only the exact saved predecessor, without publishing anything.
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
                sink: self.sink,
                deployment: self.deployment,
                journal: previous.journal,
                keeper: previous.keeper,
                replay: self.replay,
                authority: self.authority,
                limits: self.limits,
                work_limit: self.work_limit,
            },
            report: None,
            fenced: false,
            rollover_custody: self.prior_custody,
        })
    }

    /// Attach the replayed successor while retaining all prior switch custody.
    pub fn attach(
        mut self,
        active: archive::journal::rollover::Active,
    ) -> Result<Worker, RolloverAttachRefusal> {
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.sink.retention()
            || self.verified_replay != Some((active.binding(), active.switch_head()))
            || !(1..=100_000_000_000).contains(&self.work_limit)
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
            sink: self.sink,
            deployment: self.deployment,
            journal,
            keeper,
            replay: self.replay,
            authority: self.authority,
            limits: self.limits,
            work_limit: self.work_limit,
        };
        Ok(Worker {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }
}

/// Nonblocking view of video archive custody, not a publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// No segment or attempt is held.
    Idle,
    /// A segment is held without a running attempt.
    Pending,
    /// An admitted attempt must be joined or drained.
    Running,
    /// An indeterminate result requires reconciliation.
    Fenced,
    /// The archive owner could not be inspected without waiting.
    Unavailable,
}

struct State {
    parts: Parts,
    report: Option<Publication>,
    rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One exclusive video archive and at most one region-owned blocking attempt.
#[must_use = "join any attempt and retire all source and storage owners"]
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
    /// Inspect the sink's source binding without waiting for an archive attempt.
    pub fn source_key(&self) -> Option<fss_container::flv_avc::SourceKey> {
        if self.running.is_some() || self.fenced {
            return None;
        }
        self.state
            .try_lock()
            .ok()
            .map(|state| state.parts.sink.source_key())
    }

    /// Inspect the exact retained candidate without waiting for storage work.
    pub fn pending_pin(&self) -> Option<archive::UnknownTimePin> {
        if self.running.is_some() || self.fenced {
            return None;
        }
        self.state
            .try_lock()
            .ok()
            .and_then(|state| state.parts.sink.pending_pin())
    }

    /// Whether an archive attempt still needs to be joined.
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Inspect source custody without waiting on the blocking worker.
    pub fn status(&self) -> Status {
        if self.fenced {
            return Status::Fenced;
        }
        if self.running.is_some() {
            return Status::Running;
        }
        match self.state.try_lock() {
            Ok(state) if state.report.is_some() => Status::Fenced,
            Ok(state) if state.parts.sink.has_pending() => Status::Pending,
            Ok(_) => Status::Idle,
            Err(_) => Status::Unavailable,
        }
    }

    /// Construct without I/O; invalid work limits return every owner.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if !(1..=100_000_000_000).contains(&parts.work_limit) {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
                rollover_custody: None,
            })),
            running: None,
            fenced: false,
        })
    }

    /// Reattach an already replayed rollover lineage to a fresh video sink.
    /// Refusal returns the original parts and the complete custody chain.
    pub fn from_recovered(
        parts: Parts,
        mut custody: archive::journal::rollover::WorkerCustody,
    ) -> Result<Self, (Parts, archive::journal::rollover::WorkerCustody)> {
        if !(1..=100_000_000_000).contains(&parts.work_limit)
            || parts.sink.has_pending()
            || parts
                .journal
                .confirmed()
                .is_none_or(|pin| pin.retention != parts.sink.retention())
            || custody
                .check(&parts.journal, &parts.keeper, &parts.replay)
                .is_err()
        {
            return Err((parts, custody));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }

    /// Admit one source without blocking on a running attempt.
    pub fn offer(&mut self, segment: recording::Segment) -> Result<(), OfferRefusal> {
        if self.fenced {
            return Err(OfferRefusal::Fenced(segment));
        }
        if self.running.is_some() {
            return Err(OfferRefusal::Busy(segment));
        }
        match self.state.try_lock() {
            Ok(mut state) => state.parts.sink.offer(segment).map_err(OfferRefusal::Sink),
            Err(TryLockError::WouldBlock) => Err(OfferRefusal::Busy(segment)),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                Err(OfferRefusal::Fenced(segment))
            }
        }
    }

    /// Admit one bounded blocking publication under task and runtime authority.
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
            Ok(state) if !state.parts.sink.has_pending() => return Err(StartError::Empty),
            Ok(state) if state.report.is_some() => return Err(StartError::Fenced),
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
                report,
                rollover_custody,
            } = &mut *state;
            if child.is_cancel_requested() {
                *report = Some(Publication::Refused {
                    pending: parts.sink.pending_pin(),
                    reason: Refusal::Cancelled,
                });
                return;
            }
            if let Some(custody) = rollover_custody {
                if let Err(error) = custody.check(&parts.journal, &parts.keeper, &parts.replay) {
                    *report = Some(Publication::Refused {
                        pending: parts.sink.pending_pin(),
                        reason: Refusal::BeforePublication(av_worker::journal_reason(error)),
                    });
                    return;
                }
            }
            let cancel = || child.is_cancel_requested();
            let mut budget = WorkBudget::with_cancellation_probe(parts.work_limit, &cancel);
            let charge = parts
                .sink
                .pending_work_bytes()
                .and_then(|bytes| bytes.checked_mul(2));
            if charge.is_none_or(|charge| budget.charge(charge).is_err()) {
                *report = Some(Publication::Refused {
                    pending: parts.sink.pending_pin(),
                    reason: Refusal::Work,
                });
                return;
            }
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            let result = parts.sink.flush(
                &mut parts.deployment,
                &access,
                parts.limits,
                &mut budget,
                &parts.replay,
                &mut parts.journal,
                &mut parts.keeper,
            );
            *report = Some(match result {
                Ok(published) => Publication::Published(published),
                Err(error) => {
                    let reason = match error {
                        video_owned_sink::FlushError::Empty
                        | video_owned_sink::FlushError::Candidate => Refusal::Candidate,
                        video_owned_sink::FlushError::Preparation(error) => {
                            Refusal::Preparation(error)
                        }
                        video_owned_sink::FlushError::Publication(error) => match error {
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
                        },
                    };
                    Publication::Refused {
                        pending: parts.sink.pending_pin(),
                        reason,
                    }
                }
            });
        });
        match drained_blocking::start(cx, work) {
            Ok(running) => {
                self.running = Some(running);
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Request cancellation; join must still drain the attempt.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether the coordinator observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Join the exact attempt, retaining its domain result even on runtime error.
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
                    Some(report) => Outcome::Publication(report),
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
        if receipt.runtime.is_err() {
            self.fenced = true;
        }
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover all owners only after the attempt has drained.
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
                let poisoned = state.is_poisoned();
                let state = state
                    .into_inner()
                    .unwrap_or_else(|error| error.into_inner());
                Ok(Retirement {
                    parts: state.parts,
                    report: state.report,
                    fenced: fenced || poisoned,
                    rollover_custody: state.rollover_custody,
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
