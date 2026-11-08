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

/// Exclusive storage and any unresolved original source returned at retirement.
#[must_use]
pub struct Retirement {
    /// Archive, journals, policy and replay owners.
    pub parts: Parts,
    /// Original source not released after a confirmed successful publication.
    pub pending: Option<Input>,
    /// Panic or uncertainty requires explicit reconciliation.
    pub fenced: bool,
}

struct State {
    parts: Parts,
    pending: Option<Input>,
    report: Option<Publication>,
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
    /// Construct without I/O; invalid limits return all owners unchanged.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if !(1..=100_000_000_000).contains(&parts.work_limit)
            || !(1..=64 * 1024 * 1024).contains(&parts.max_source_bytes)
            || parts.retention.algorithm() != DigestAlgorithm::Sha256
            || parts.retention.is_laboratory()
            || parts.retention.bytes() == [0; 32]
        {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                pending: None,
                report: None,
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
        let valid = match &input {
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
                state.parts.retention,
                state.parts.max_source_bytes,
            )
            .is_ok(),
            Input::Recovered(source) => {
                source.retention == state.parts.retention
                    && !source.bytes().is_empty()
                    && source.bytes().len() <= state.parts.max_source_bytes
            }
        };
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
            } = &mut *state;
            let Some(input) = pending.as_ref() else {
                return;
            };
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
