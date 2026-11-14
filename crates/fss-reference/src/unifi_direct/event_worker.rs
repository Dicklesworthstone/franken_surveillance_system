#![forbid(unsafe_code)]
//! Task-owned, cancellation-drained publication of one camera event source.
//!
//! This bounded worker does not drive a camera, authenticate its source,
//! establish physical capture time, provide a recorder or perform rollover.
//! A refused or uncertain attempt retains the original event for its owner.

use std::sync::{Arc, Mutex, TryLockError};

use asupersync::{Cx, runtime::JoinError};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, RuntimeGrant};
use fss_geometry::WorkBudget;
use fss_publication::RootLedgerReceipt;
use fss_runtime::{
    drained_blocking::{self, Drained, WorkOutcome},
    execution::TaskCx,
};

use super::{archive, av_worker::StartError, event_evidence, events::Frame, metered::MeteredClock};
use crate::{ReferenceDeployment, ReplayCx};

/// Original or previously recovered event and its unverified source claims.
pub enum Input {
    /// The exact event observed by a caller-owned controller session.
    Original {
        /// Source event, including its original bytes.
        frame: Frame,
        /// Caller-bound connection and generation.
        key: SourceKey,
        /// Caller-supplied camera claim, not authenticated identity.
        camera_claim: ContentDigest,
    },
    /// An event recovered through an authorized archive read.
    Recovered(archive::RecoveredEvent),
}
impl Input {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Original { frame, .. } => frame.source(),
            Self::Recovered(event) => event.frame().source(),
        }
    }
}

/// Exclusive storage, journal and policy owners for this event worker.
pub struct Parts {
    /// Dedicated archive deployment; no other owner may use it concurrently.
    pub deployment: ReferenceDeployment,
    /// Dedicated unknown-time publication-intent journal.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Separately retained journal-anchor history.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Explicit filesystem and cancellation authority.
    pub replay: ReplayCx,
    /// Current retention policy, rechecked during publication.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Retention decision claim; this digest is not itself authority.
    pub retention: ContentDigest,
    /// Archive limits.
    pub limits: archive::Limits,
    /// Maximum event bytes, no greater than the controller's message bound.
    pub max_event_bytes: usize,
    /// Maximum work per attempt, at most 100 billion units.
    pub work_limit: u64,
}

/// An offer was refused and returns the unchanged event.
#[must_use]
pub enum OfferRefusal {
    /// A source or publication attempt is already held.
    Busy(Input),
    /// Source claims or configured bounds were invalid.
    Invalid(Input),
    /// An indeterminate result or poisoned owner requires reconciliation.
    Fenced(Input),
}

/// Result of one completed archive closure, separate from runtime completion.
pub enum Publication {
    /// The archive and journal confirmed this exact candidate.
    Published {
        /// Candidate identity, not authority.
        pin: archive::UnknownTimePin,
        /// Actual root publication receipt.
        receipt: RootLedgerReceipt,
    },
    /// The source remains held and the result requires caller inspection.
    Refused {
        /// Candidate identity if preparation completed.
        pin: Option<archive::UnknownTimePin>,
        /// Payload-free failure classification and any retained receipt.
        reason: Refusal,
    },
}
/// Why an event was retained rather than confirmed as published.
pub enum Refusal {
    /// Event source preparation refused its claims.
    Preparation(event_evidence::Error),
    /// Work limit or cancellation stopped the attempt before publication.
    Work,
    /// The candidate conflicts with the journal's pending or replay pin.
    Candidate,
    /// Journal preparation or independent anchoring did not complete.
    BeforePublication(super::av_worker::FailureReason),
    /// Staging or root publication did not complete cleanly.
    Archive(super::av_worker::FailureReason),
    /// The root was published, but its confirmation needs reconciliation.
    AfterPublication {
        /// Payload-free journal failure classification.
        reason: super::av_worker::FailureReason,
        /// Actual ledger receipt retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
    },
}
/// Outcome of a fully drained blocking closure.
pub enum Outcome {
    /// The closure never started; the event remains pending.
    NotStarted,
    /// The closure returned a publication classification.
    Publication(Publication),
    /// The blocking closure panicked.
    Panicked,
    /// The closure's outcome cannot be determined.
    Indeterminate,
}
/// Runtime and archive outcomes after a worker has drained.
pub struct Completion {
    /// Runtime completion classification.
    pub runtime: Result<(), JoinError>,
    /// Archive classification and any retained receipt.
    pub outcome: Outcome,
}
/// Payload-free current worker state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// No event is held.
    Idle,
    /// An event is retained without a running attempt.
    Pending,
    /// A blocking attempt requires joining.
    Running,
    /// An indeterminate outcome requires reconciliation.
    Fenced,
    /// The source state cannot be inspected without waiting.
    Unavailable,
}
/// Exclusive storage and any event returned when the worker is retired.
#[must_use = "retain storage and reconcile any pending event"]
pub struct Retirement {
    /// All storage and policy owners.
    pub parts: Parts,
    /// Event not released after confirmed publication.
    pub pending: Option<Input>,
    /// Whether an indeterminate result needs reconciliation.
    pub fenced: bool,
}

struct State {
    parts: Parts,
    pending: Option<Input>,
    report: Option<Publication>,
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One owned event and at most one region-owned blocking attempt.
#[must_use = "join any running attempt and retire the event and storage owners"]
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
    /// Construct without I/O; invalid configuration returns all owners.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if !event_evidence::valid_digest(parts.retention)
            || !(1..=super::MAX_MESSAGE_BYTES).contains(&parts.max_event_bytes)
            || !(1..=100_000_000_000).contains(&parts.work_limit)
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

    /// Inspect custody without waiting on a blocking archive operation.
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

    /// Transfer an event into an idle worker, or recover it unchanged.
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
        let valid = !input.bytes().is_empty()
            && input.bytes().len() <= state.parts.max_event_bytes
            && match &input {
                Input::Original {
                    frame,
                    key,
                    camera_claim,
                } => {
                    key.connection != 0
                        && key.generation != 0
                        && event_evidence::valid_digest(*camera_claim)
                        && event_evidence::kind_code(frame.kind()).is_some()
                }
                Input::Recovered(event) => event.retention == state.parts.retention,
            };
        if !valid {
            return Err(OfferRefusal::Invalid(input));
        }
        state.pending = Some(input);
        Ok(())
    }

    /// Start a task-admitted archive operation without blocking the reactor.
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
        let shared = Arc::clone(&self.state);
        let work: Job = Box::new(move |child| {
            let Ok(mut state) = shared.lock() else {
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
            let Some(cost) = (input.bytes().len() as u64).checked_mul(2) else {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::Work,
                });
                return;
            };
            if child.is_cancel_requested() || budget.charge(cost).is_err() {
                *report = Some(Publication::Refused {
                    pin: None,
                    reason: Refusal::Work,
                });
                return;
            }
            let prepared = match input {
                Input::Original {
                    frame,
                    key,
                    camera_claim,
                } => event_evidence::Prepared::new(frame, *key, *camera_claim, parts.retention),
                Input::Recovered(event) => Ok(event_evidence::Prepared::from_recovered(event)),
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
            let pin = archive::UnknownTimePin::from_event_plan(&plan);
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            *report = Some(
                match archive::publish_unknown_time_event_anchored(
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
                                Refusal::BeforePublication(super::av_worker::journal_reason(error))
                            }
                            archive::UnknownTimePublishError::Archive(error) => {
                                Refusal::Archive(super::av_worker::archive_reason(
                                    error,
                                    child.is_cancel_requested(),
                                ))
                            }
                            archive::UnknownTimePublishError::AfterPublication {
                                receipt,
                                source,
                            } => Refusal::AfterPublication {
                                reason: super::av_worker::journal_reason(source),
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

    /// Request cancellation; join is still required before retiring owners.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether the blocking coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Join the exact attempt before releasing any event or storage owner.
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

    /// Return every owner only after any running work has drained.
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
                let (state, poisoned) = match state.into_inner() {
                    Ok(state) => (state, false),
                    Err(error) => (error.into_inner(), true),
                };
                Ok(Retirement {
                    parts: state.parts,
                    pending: state.pending,
                    fenced: fenced || poisoned,
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
