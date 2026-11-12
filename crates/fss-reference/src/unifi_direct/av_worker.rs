#![forbid(unsafe_code)]
//! Task-admitted, single-operation asynchronous A/V archive worker.
//!
//! The worker retains its owned source and storage owners across admission
//! refusal and cancellation. It must be joined before retirement. This does
//! not supervise a camera, infer capture time, or establish a production service.

use std::sync::{Arc, Mutex, TryLockError};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, RuntimeGrant};
use fss_geometry::WorkBudget;
use fss_publication::RootLedgerReceipt;
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    effect_journal::EffectJournalPin,
    execution::{ExecutionError, TaskCx},
};

use super::{archive, av_owned_sink, av_sink, metered::MeteredClock, recording};
use crate::{ReferenceDeployment, ReplayCx};

/// All exclusive storage and source owners transferred into the worker.
pub struct Parts {
    /// Owned source and muxer state.
    pub sink: av_owned_sink::OwnedSink,
    /// Exclusive local archive owner.
    pub deployment: ReferenceDeployment,
    /// Exact publication-intent journal.
    pub journal: archive::journal::Journal,
    /// Separately owned intent-anchor journal.
    pub keeper: archive::journal::AnchorKeeper,
    /// Explicit filesystem and cancellation authority.
    pub replay: ReplayCx,
    /// Revalidated original-byte retention decision.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Independent archive limits.
    pub limits: archive::Limits,
    /// Work allowance per attempt, at most 100 billion units.
    pub work_limit: u64,
}

/// Source returned to its caller when the worker cannot accept it.
#[must_use]
pub enum OfferRefusal {
    /// A job or another source remains pending.
    Busy {
        /// The unchanged caller-owned source.
        segment: recording::Segment,
        /// The caller's unchanged capture bounds.
        capture: CaptureInterval,
    },
    /// State requires explicit retirement after an indeterminate failure.
    Fenced {
        /// The unchanged caller-owned source.
        segment: recording::Segment,
        /// The caller's unchanged capture bounds.
        capture: CaptureInterval,
    },
    /// The sink retained its existing state and returned this source.
    Sink(av_sink::Refusal),
}

/// Stable, payload-free failure stage; an archive effect may be indeterminate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    /// AAC source binding or configuration refused.
    Audio,
    /// Media construction, provenance, or scope refused.
    Preparation,
    /// The proposed root disagreed with a pending root.
    PendingMismatch,
    /// Intent journal append failed or was uncertain.
    JournalBefore,
    /// Separate intent-anchor retention failed or was uncertain.
    AnchorBefore,
    /// Archive publication failed or was uncertain.
    Archive,
    /// A receipt exists but confirmation failed or was uncertain.
    JournalAfterCommit,
    /// A receipt exists but its confirmation anchor was uncertain.
    AnchorAfterCommit,
}

/// Payload-free cause class; this does not settle whether an effect occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// Owned AAC configuration could not be rebound or parsed.
    AudioConfiguration,
    /// Audio provenance does not match the muxer.
    Binding,
    /// Publication used a different journal scope.
    JournalScope,
    /// Exact payload-free A/V muxer refusal.
    Media(super::av_recording::Error),
    /// Exact video evidence preparation refusal.
    Video(super::evidence::Error),
    /// Exact A/V evidence preparation refusal.
    AudioVideo(super::av_evidence::Error),
    /// Current policy denied retention, with cancellation not observed.
    Denied,
    /// Cancellation and denial may both have contributed.
    CancelledOrDenied,
    /// The configured bounds or work allowance refused the operation.
    LimitOrWork,
    /// Capture bounds were not provided.
    UnknownCapture,
    /// A root, journal, or pending source requires reconciliation.
    Recovery,
    /// A deletion tombstone refused resurrection.
    Tombstoned,
    /// Source, scope, content, or media binding failed.
    Mismatch,
    /// A journal's configured capacity refused the operation. The stage and
    /// returned owners still determine whether reconciliation is required.
    JournalCapacity,
    /// Storage failed or its outcome may be indeterminate.
    Storage,
}

/// Actual archive outcome retained after a worker attempt.
pub enum Publication {
    /// The archive and both journals returned their receipts.
    Published(archive::PublishedAvSegment),
    /// Refusal, retaining both pending root identities and any actual receipt.
    Refused {
        /// Operation stage.
        stage: FailureStage,
        /// Coarse refusal cause, without sensitive payloads.
        reason: FailureReason,
        /// Root requiring reconciliation, when known.
        expected: Option<archive::Pin>,
        /// Conflicting proposed root, when present.
        proposed: Option<archive::Pin>,
        /// Actual archive receipt when the failure happened after commit.
        receipt: Option<Box<RootLedgerReceipt>>,
    },
    /// The sink held no source segment; a muxer fence may still require recovery.
    Empty,
}

struct State {
    parts: Parts,
    report: Option<Publication>,
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// Refusal before dispatch. Existing source and storage remain in the worker.
#[derive(Debug)]
pub enum StartError {
    /// An earlier task is still owned.
    Running,
    /// No source or muxer fence is pending.
    Empty,
    /// Prior panic or lock poisoning requires retirement.
    Fenced,
    /// The clock is not bound to this exact task and runtime context.
    Context,
    /// The bound task clock could not be observed.
    Clock,
    /// Task, grant, time, or budget admission failed.
    Task(ExecutionError),
    /// Runtime pool or region admission failed.
    Runtime(StartFailure),
}

/// Result after the blocking closure and its coordinator have both retired.
pub struct Completion {
    /// Runtime task classification, independent of the domain outcome.
    pub runtime: Result<(), JoinError>,
    /// Source/publication classification.
    pub outcome: Outcome,
}

/// Source and storage owners returned after the worker has drained.
#[must_use]
pub struct Retirement {
    /// Exclusive source and storage owners for reconciliation.
    pub parts: Parts,
    /// A panic or inconsistent completion requires explicit reconciliation.
    pub fenced: bool,
}

/// Worker outcome; source remains owned on every refusal or uncertain result.
pub enum Outcome {
    /// The closure did not start; its source remains pending.
    NotStarted,
    /// The closure returned an actual archive classification.
    Publication(Publication),
    /// The closure panicked; the worker is fenced for explicit recovery.
    Panicked,
    /// Completion could not be reconciled; the worker is fenced.
    Indeterminate,
}

/// One exclusive archive state and at most one region-owned blocking attempt.
#[must_use = "join any running attempt and retire its source and storage owners"]
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
    fn permits(&self, retention: fss_core::ContentDigest, root: fss_core::ContentDigest) -> bool {
        self.cx.checkpoint().is_ok() && self.inner.permits(retention, root)
    }
}

fn failure(
    stage: FailureStage,
    reason: FailureReason,
    expected: Option<archive::Pin>,
    proposed: Option<archive::Pin>,
    receipt: Option<Box<RootLedgerReceipt>>,
) -> Publication {
    Publication::Refused {
        stage,
        reason,
        expected,
        proposed,
        receipt,
    }
}

pub(super) fn journal_reason(error: archive::journal::Error) -> FailureReason {
    use archive::journal::Error;
    match error {
        Error::Storage(fss_runtime::effect_journal::EffectPersistenceError::Capacity) => {
            FailureReason::JournalCapacity
        }
        Error::Storage(_) => FailureReason::Storage,
        Error::Cancelled => FailureReason::CancelledOrDenied,
        Error::Invalid | Error::Fenced => FailureReason::Recovery,
    }
}

pub(super) fn archive_reason(error: archive::Error, cancelled: bool) -> FailureReason {
    use archive::Error;
    match error {
        Error::Denied if cancelled => FailureReason::CancelledOrDenied,
        Error::Denied => FailureReason::Denied,
        Error::Cancelled => FailureReason::CancelledOrDenied,
        Error::Limit | Error::Work(_) => FailureReason::LimitOrWork,
        Error::UnknownCapture => FailureReason::UnknownCapture,
        Error::NotCommitted | Error::RecoveryRequired => FailureReason::Recovery,
        Error::Tombstoned => FailureReason::Tombstoned,
        Error::Mismatch => FailureReason::Mismatch,
        Error::Storage(_) => FailureReason::Storage,
    }
}

fn classify(error: av_owned_sink::FlushError, cancelled: bool) -> Publication {
    use archive::AvSegmentPublishError as E;
    match error {
        av_owned_sink::FlushError::Audio => failure(
            FailureStage::Audio,
            FailureReason::AudioConfiguration,
            None,
            None,
            None,
        ),
        av_owned_sink::FlushError::Archive(error) => match error {
            E::Binding => failure(
                FailureStage::Preparation,
                FailureReason::Binding,
                None,
                None,
                None,
            ),
            E::JournalScope => failure(
                FailureStage::Preparation,
                FailureReason::JournalScope,
                None,
                None,
                None,
            ),
            E::Media(error) => failure(
                FailureStage::Preparation,
                FailureReason::Media(error),
                None,
                None,
                None,
            ),
            E::Video(error) => failure(
                FailureStage::Preparation,
                FailureReason::Video(error),
                None,
                None,
                None,
            ),
            E::AudioVideo(error) => failure(
                FailureStage::Preparation,
                FailureReason::AudioVideo(error),
                None,
                None,
                None,
            ),
            E::PendingMismatch { expected, proposed } => failure(
                FailureStage::PendingMismatch,
                FailureReason::Recovery,
                Some(expected),
                Some(proposed),
                None,
            ),
            E::JournalBefore { pin, source } => failure(
                FailureStage::JournalBefore,
                journal_reason(source),
                Some(pin),
                None,
                None,
            ),
            E::AnchorBefore { pin, source } => failure(
                FailureStage::AnchorBefore,
                journal_reason(source),
                Some(pin),
                None,
                None,
            ),
            E::Archive { pin, source } => failure(
                FailureStage::Archive,
                archive_reason(source, cancelled),
                Some(pin),
                None,
                None,
            ),
            E::JournalAfterCommit {
                pin,
                receipt,
                source,
            } => failure(
                FailureStage::JournalAfterCommit,
                journal_reason(source),
                Some(pin),
                None,
                Some(receipt),
            ),
            E::AnchorAfterCommit {
                pin,
                receipt,
                source,
            } => failure(
                FailureStage::AnchorAfterCommit,
                journal_reason(source),
                Some(pin),
                None,
                Some(receipt),
            ),
        },
    }
}

impl Worker {
    /// True only when this worker has no active job, pending source, or fence.
    /// Intended for transferring an idle worker into a supervising owner.
    pub(crate) fn is_idle(&self) -> bool {
        if self.fenced || self.running.is_some() {
            return false;
        }
        self.state
            .try_lock()
            .is_ok_and(|state| !state.parts.sink.has_pending())
    }

    /// Create an idle worker without starting a task or performing I/O. Invalid
    /// work bounds return every original part unchanged.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if !(1..=100_000_000_000).contains(&parts.work_limit) {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
            })),
            running: None,
            fenced: false,
        })
    }

    /// Admit a segment without blocking on a running worker.
    pub fn offer(
        &mut self,
        segment: recording::Segment,
        capture: CaptureInterval,
    ) -> Result<(), OfferRefusal> {
        if self.fenced {
            return Err(OfferRefusal::Fenced { segment, capture });
        }
        if self.running.is_some() {
            return Err(OfferRefusal::Busy { segment, capture });
        }
        match self.state.try_lock() {
            Ok(mut state) => state
                .parts
                .sink
                .offer(segment, capture)
                .map_err(OfferRefusal::Sink),
            Err(TryLockError::WouldBlock) => Err(OfferRefusal::Busy { segment, capture }),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                Err(OfferRefusal::Fenced { segment, capture })
            }
        }
    }

    /// Debit the caller's explicit task budget and start one region-owned,
    /// drained pool operation. Both object grants must cover `resource`.
    /// The caller must supply this task's own runtime context and a defensible
    /// cost reservation; an admission failure never releases the source.
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
            let State { parts, report } = &mut *state;
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            let cancel = || child.is_cancel_requested();
            let mut budget = WorkBudget::with_cancellation_probe(parts.work_limit, &cancel);
            *report = Some(
                match parts.sink.flush(
                    &mut parts.deployment,
                    &access,
                    parts.limits,
                    &mut budget,
                    &parts.replay,
                    &mut parts.journal,
                    &mut parts.keeper,
                ) {
                    Ok(Some(receipt)) => Publication::Published(receipt),
                    Ok(None) => Publication::Empty,
                    Err(error) => classify(error, child.is_cancel_requested()),
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

    /// Request cancellation; the source remains owned until `join` drains.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether the region-owned coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Wait for the exact blocking attempt to release its captures and retire.
    /// Dropping this borrowing wait leaves the worker and its source intact.
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
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Return all source and storage owners after any job is joined. Poisoned
    /// state is returned for explicit reconciliation, never silently retried.
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
            Ok(state) => Ok(Retirement {
                parts: state
                    .into_inner()
                    .unwrap_or_else(|error| error.into_inner())
                    .parts,
                fenced,
            }),
            Err(state) => Err(Self {
                state,
                running: None,
                fenced,
            }),
        }
    }
}

/// Exclusive owners transferred into an unknown-time archive worker.
pub struct UnknownTimeParts {
    /// Source, configuration and transactional muxer owners.
    pub sink: av_owned_sink::UnknownTimeOwnedSink,
    /// Exclusive archive deployment.
    pub deployment: ReferenceDeployment,
    /// Unknown-time publication intent history.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Independently stored intent-anchor history.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Explicit storage and cancellation authority.
    pub replay: ReplayCx,
    /// Revalidated original-byte retention decision.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Archive resource limits.
    pub limits: archive::Limits,
    /// Maximum work per publication attempt.
    pub work_limit: u64,
}

/// A source returned unchanged when an unknown-time worker refuses it.
#[must_use]
pub enum UnknownTimeOfferRefusal {
    /// A source or job is already outstanding.
    Busy(recording::Segment),
    /// State needs explicit retirement and reconciliation.
    Fenced(recording::Segment),
    /// The sink returned the original segment and a refusal reason.
    Sink(av_owned_sink::UnknownTimeOfferRefusal),
}

/// Coarse stage of an unknown-time publication refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownTimeFailureStage {
    /// Audio or source preparation failed.
    Preparation,
    /// Intent or its independent anchor was not confirmed.
    BeforePublication,
    /// Archive staging or publication did not complete cleanly.
    Archive,
    /// A receipt exists, but confirmation or its anchor is unresolved.
    AfterPublication,
}

/// Exact settled predecessor reported by a capacity preflight. This is a
/// scheduling hint, not authority to create or activate successor stores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RolloverNeed {
    /// Last confirmed archive root.
    pub confirmed: archive::UnknownTimePin,
    /// Current publication history head.
    pub journal: EffectJournalPin,
    /// Current anchor-keeper head.
    pub keeper: EffectJournalPin,
}

/// Actual publication outcome, independent of runtime task classification.
pub enum UnknownTimePublication {
    /// The archive and journal both returned receipts.
    Published(archive::PublishedUnknownTimeAvSegment),
    /// A refusal that leaves source and any pending candidate with the worker.
    Refused {
        /// Stage without sensitive source bytes.
        stage: UnknownTimeFailureStage,
        /// Payload-free cause classification.
        reason: FailureReason,
        /// Exact unknown-time root requiring reconciliation, if established.
        pending: Option<archive::UnknownTimePin>,
        /// Actual archive receipt, if failure occurred after publication.
        receipt: Option<Box<RootLedgerReceipt>>,
        /// Present only for the settled, pre-candidate capacity preflight.
        /// The caller must still validate, stage and replay a successor.
        rollover: Option<RolloverNeed>,
    },
    /// No segment was available to flush.
    Empty,
}

/// Joined blocking-attempt result for an unknown-time worker.
pub enum UnknownTimeOutcome {
    /// The closure did not start; its source remains pending.
    NotStarted,
    /// The closure returned a publication classification.
    Publication(UnknownTimePublication),
    /// The closure panicked; retirement and reconciliation are required.
    Panicked,
    /// Completion could not be reconciled; retirement is required.
    Indeterminate,
}

/// Runtime and publication outcomes after the attempt has drained.
pub struct UnknownTimeCompletion {
    /// Runtime task result, distinct from the archive outcome.
    pub runtime: Result<(), JoinError>,
    /// Actual source and publication classification.
    pub outcome: UnknownTimeOutcome,
}

/// Source and storage owners returned after all work has drained.
#[must_use]
pub struct UnknownTimeRetirement {
    /// All exclusive owners for reconciliation.
    pub parts: UnknownTimeParts,
    /// A panic or uncertain coordinator outcome requires reconciliation.
    pub fenced: bool,
    /// Retained predecessor and switch for an attached rollover.
    pub rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}

struct UnknownTimeState {
    parts: UnknownTimeParts,
    report: Option<UnknownTimePublication>,
    rollover_custody: Option<archive::journal::rollover::WorkerCustody>,
}

/// A/V sink, pending segment, archive, and policy held during rollover.
#[must_use = "restore the predecessor or attach a verified successor"]
pub struct UnknownTimeRolloverResources {
    sink: av_owned_sink::UnknownTimeOwnedSink,
    deployment: ReferenceDeployment,
    replay: ReplayCx,
    authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    limits: archive::Limits,
    work_limit: u64,
    original_scope: ContentDigest,
    original_journal: EffectJournalPin,
    original_keeper: EffectJournalPin,
    prior_custody: Option<archive::journal::rollover::WorkerCustody>,
}

/// Failed A/V attachment preserves the sink and active transition.
#[must_use = "reconcile or restore both owners"]
pub struct UnknownTimeRolloverAttachRefusal {
    /// A/V resources and pending segment.
    pub resources: UnknownTimeRolloverResources,
    /// Transition which could not be attached.
    pub active: archive::journal::rollover::Active,
}

/// Failed restoration preserves both owners.
#[must_use = "inspect the predecessor and resources"]
pub struct UnknownTimeRolloverRestoreRefusal {
    /// A/V resources and pending segment.
    pub resources: UnknownTimeRolloverResources,
    /// Nonmatching predecessor.
    pub previous: archive::journal::rollover::Previous,
}

/// Opaque successor and lineage whose storage checks have completed on the
/// rollover worker. It is an observation, not a durable reservation.
#[must_use = "attach to its original resources or retain for reconciliation"]
pub struct PreparedUnknownTimeAttachment {
    binding: archive::journal::rollover::Binding,
    journal: archive::journal::UnknownTimeJournal,
    keeper: archive::journal::UnknownTimeAnchorKeeper,
    custody: archive::journal::rollover::WorkerCustody,
}

impl PreparedUnknownTimeAttachment {
    /// The checked transition identity; this does not authenticate a camera.
    pub fn binding(&self) -> archive::journal::rollover::Binding {
        self.binding
    }
}

/// Failed attachment preserves both the original pending media and the
/// already checked successor.
#[must_use = "retain or reconcile both returned owners"]
pub struct PreparedUnknownTimeAttachRefusal {
    /// Original pending media and archive resources.
    pub resources: UnknownTimeRolloverResources,
    /// Prepared successor and custody.
    pub attachment: PreparedUnknownTimeAttachment,
}

/// Private, single-use observation that the exact retired predecessor and its
/// retained lineage were checked. This is not a durable storage reservation.
pub(crate) struct VerifiedRolloverPause {
    scope: ContentDigest,
    confirmed: archive::UnknownTimePin,
    journal: EffectJournalPin,
    keeper: EffectJournalPin,
    transitions: usize,
}

/// Why a retired worker cannot be prepared for rollover.
#[derive(Debug)]
pub enum RolloverPauseError {
    /// The worker is fenced, unsettled, or has incompatible pending media.
    NotReady,
    /// Existing switch custody could not be verified.
    Custody(archive::journal::Error),
    /// The lineage cannot retain another transition.
    Capacity,
}

impl UnknownTimeRetirement {
    /// Detach an unfenced A/V worker while retaining its sink and any pending
    /// segment and previous rollover custody. Unresolved muxer effects refuse.
    pub fn into_rollover(
        mut self,
    ) -> Result<
        (
            UnknownTimeRolloverResources,
            archive::journal::rollover::Previous,
        ),
        Self,
    > {
        let verified = match self.verify_rollover_pause() {
            Ok(verified) => verified,
            Err(_) => return Err(self),
        };
        self.into_rollover_verified(verified)
    }

    /// Verify custody while borrowing the original owner, so even a panic in
    /// a storage implementation leaves the pending segment in that owner.
    pub(crate) fn verify_rollover_pause(
        &mut self,
    ) -> Result<VerifiedRolloverPause, RolloverPauseError> {
        let Some(confirmed) = self.parts.journal.confirmed() else {
            return Err(RolloverPauseError::NotReady);
        };
        if self.fenced
            || !(1..=100_000_000_000).contains(&self.parts.work_limit)
            || self.parts.sink.pending_publication().is_some()
            || confirmed.retention != self.parts.sink.retention()
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

    /// Transfer a verified predecessor without another storage read.
    pub(crate) fn into_rollover_verified(
        self,
        verified: VerifiedRolloverPause,
    ) -> Result<
        (
            UnknownTimeRolloverResources,
            archive::journal::rollover::Previous,
        ),
        Self,
    > {
        if self.fenced
            || !(1..=100_000_000_000).contains(&self.parts.work_limit)
            || self.parts.sink.pending_publication().is_some()
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
        {
            return Err(self);
        }
        let UnknownTimeParts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = self.parts;
        let resources = UnknownTimeRolloverResources {
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
        };
        Ok((
            resources,
            archive::journal::rollover::Previous { journal, keeper },
        ))
    }
}

impl UnknownTimeRolloverResources {
    /// Scoped authority for staging the successor.
    pub fn replay(&self) -> &ReplayCx {
        &self.replay
    }
    /// Check the predecessor before an asynchronous transition can touch
    /// successor storage. This is an identity check, not authorization.
    pub(crate) fn matches_previous(&self, previous: &archive::journal::rollover::Previous) -> bool {
        previous.journal.scope() == self.original_scope
            && previous.journal.anchor() == self.original_journal
            && previous.keeper.anchor() == self.original_keeper
    }

    /// Whether the original sink still holds a source or fence.
    pub fn has_pending(&self) -> bool {
        self.sink.has_pending()
    }

    /// Perform all fallible custody reads before returning an opaque
    /// attachment. Pending media remains in `self` throughout the checks.
    pub(crate) fn prepare_attachment(
        &mut self,
        active: archive::journal::rollover::Active,
    ) -> Result<PreparedUnknownTimeAttachment, archive::journal::rollover::Active> {
        let binding = active.binding();
        if binding.scope != self.original_scope
            || binding.old_journal != self.original_journal
            || binding.old_keeper != self.original_keeper
            || binding.confirmed.retention != self.sink.retention()
            || self.sink.pending_publication().is_some()
            || !(1..=100_000_000_000).contains(&self.work_limit)
        {
            return Err(active);
        }
        if let Some(prior) = &mut self.prior_custody {
            if active.check_prior(prior, &self.replay).is_err() {
                return Err(active);
            }
        }
        let (journal, keeper, custody) = match active.into_worker_parts(&self.replay) {
            Ok(parts) => parts,
            Err(active) => return Err(active),
        };
        let custody = match self.prior_custody.take() {
            Some(mut prior) => {
                prior.append(custody);
                prior
            }
            None => custody,
        };
        Ok(PreparedUnknownTimeAttachment {
            binding,
            journal,
            keeper,
            custody,
        })
    }

    /// Attach a previously checked successor without reading its storage.
    /// A fresh in-memory cancellation checkpoint still applies.
    pub(crate) fn attach_prepared(
        self,
        attachment: PreparedUnknownTimeAttachment,
    ) -> Result<UnknownTimeWorker, PreparedUnknownTimeAttachRefusal> {
        let binding = attachment.binding;
        if binding.scope != self.original_scope
            || binding.old_journal != self.original_journal
            || binding.old_keeper != self.original_keeper
            || binding.confirmed.retention != self.sink.retention()
            || self.sink.pending_publication().is_some()
            || self.prior_custody.is_some()
            || !(1..=100_000_000_000).contains(&self.work_limit)
            || self.replay.checkpoint("unifi-av-prepared-attach").is_err()
        {
            return Err(PreparedUnknownTimeAttachRefusal {
                resources: self,
                attachment,
            });
        }
        let parts = UnknownTimeParts {
            sink: self.sink,
            deployment: self.deployment,
            journal: attachment.journal,
            keeper: attachment.keeper,
            replay: self.replay,
            authority: self.authority,
            limits: self.limits,
            work_limit: self.work_limit,
        };
        Ok(UnknownTimeWorker {
            state: Arc::new(Mutex::new(UnknownTimeState {
                parts,
                report: None,
                rollover_custody: Some(attachment.custody),
            })),
            running: None,
            fenced: false,
        })
    }

    /// Verify and replay this worker's exact ledgered A/V root.
    pub fn replay_confirmed_av(
        &mut self,
        active: &mut archive::journal::rollover::Active,
        read: &dyn archive::ReadAuthority,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
    ) -> Result<RootLedgerReceipt, archive::journal::rollover::AvReplayError> {
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.sink.retention()
        {
            return Err(archive::journal::rollover::AvReplayError::History(
                archive::journal::Error::Invalid,
            ));
        }
        if let Some(prior) = &mut self.prior_custody {
            active
                .check_prior(prior, &self.replay)
                .map_err(archive::journal::rollover::AvReplayError::History)?;
        }
        active.replay_confirmed_av(
            &mut self.deployment,
            read,
            self.authority.as_ref(),
            self.limits,
            object_limits,
            work,
            &self.replay,
        )
    }

    /// Restore the exact predecessor after an uncommitted transition.
    pub fn restore(
        self,
        previous: archive::journal::rollover::Previous,
    ) -> Result<UnknownTimeRetirement, UnknownTimeRolloverRestoreRefusal> {
        if previous.journal.scope() != self.original_scope
            || previous.journal.anchor() != self.original_journal
            || previous.keeper.anchor() != self.original_keeper
        {
            return Err(UnknownTimeRolloverRestoreRefusal {
                resources: self,
                previous,
            });
        }
        Ok(UnknownTimeRetirement {
            parts: UnknownTimeParts {
                sink: self.sink,
                deployment: self.deployment,
                journal: previous.journal,
                keeper: previous.keeper,
                replay: self.replay,
                authority: self.authority,
                limits: self.limits,
                work_limit: self.work_limit,
            },
            fenced: false,
            rollover_custody: self.prior_custody,
        })
    }

    /// Attach a replayed successor and retain predecessor/switch custody.
    pub fn attach(
        mut self,
        active: archive::journal::rollover::Active,
    ) -> Result<UnknownTimeWorker, UnknownTimeRolloverAttachRefusal> {
        if active.binding().scope != self.original_scope
            || active.binding().old_journal != self.original_journal
            || active.binding().old_keeper != self.original_keeper
            || active.binding().confirmed.retention != self.sink.retention()
            || self.sink.pending_publication().is_some()
            || !(1..=100_000_000_000).contains(&self.work_limit)
        {
            return Err(UnknownTimeRolloverAttachRefusal {
                resources: self,
                active,
            });
        }
        if let Some(prior) = &mut self.prior_custody {
            if active.check_prior(prior, &self.replay).is_err() {
                return Err(UnknownTimeRolloverAttachRefusal {
                    resources: self,
                    active,
                });
            }
        }
        let (journal, keeper, custody) = match active.into_worker_parts(&self.replay) {
            Ok(parts) => parts,
            Err(active) => {
                return Err(UnknownTimeRolloverAttachRefusal {
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
        let parts = UnknownTimeParts {
            sink: self.sink,
            deployment: self.deployment,
            journal,
            keeper,
            replay: self.replay,
            authority: self.authority,
            limits: self.limits,
            work_limit: self.work_limit,
        };
        Ok(UnknownTimeWorker {
            state: Arc::new(Mutex::new(UnknownTimeState {
                parts,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }
}

/// One region-owned, cancellation-drained unknown-time archive attempt.
/// This is a worker building block, not an unattended camera service.
#[must_use = "join any running attempt and retire its source and storage owners"]
pub struct UnknownTimeWorker {
    state: Arc<Mutex<UnknownTimeState>>,
    running: Option<Drained<Job, ()>>,
    fenced: bool,
}

/// Refusal to inspect or renew the worker's existing audio epoch.
#[derive(Debug)]
pub enum AudioAllowanceError {
    /// An archive operation is still running or owns the state lock.
    Busy,
    /// An uncertain operation or poisoned state requires reconciliation.
    Fenced,
    /// The muxer refused renewal, including an unresolved publication.
    Mux(super::av_recording::Error),
}

fn classify_unknown_time(
    error: av_owned_sink::UnknownTimeFlushError,
    cancelled: bool,
    pending: Option<archive::UnknownTimePin>,
) -> UnknownTimePublication {
    use archive::{UnknownTimePublishError as P, UnknownTimeSegmentError as S};
    let (stage, reason, receipt) = match error {
        av_owned_sink::UnknownTimeFlushError::Audio => (
            UnknownTimeFailureStage::Preparation,
            FailureReason::AudioConfiguration,
            None,
        ),
        av_owned_sink::UnknownTimeFlushError::Archive(error) => match error {
            S::Binding => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::Binding,
                None,
            ),
            S::JournalScope => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::JournalScope,
                None,
            ),
            S::PendingMismatch => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::Recovery,
                None,
            ),
            S::Media(error) => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::Media(error),
                None,
            ),
            S::Video(error) => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::Video(error),
                None,
            ),
            S::AudioVideo(error) => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::AudioVideo(error),
                None,
            ),
            S::Publication(P::Candidate) => (
                UnknownTimeFailureStage::Preparation,
                FailureReason::Recovery,
                None,
            ),
            S::Publication(P::BeforePublication(error)) => (
                UnknownTimeFailureStage::BeforePublication,
                journal_reason(error),
                None,
            ),
            S::Publication(P::Archive(error)) => (
                UnknownTimeFailureStage::Archive,
                archive_reason(error, cancelled),
                None,
            ),
            S::Publication(P::AfterPublication { receipt, source }) => (
                UnknownTimeFailureStage::AfterPublication,
                journal_reason(source),
                Some(receipt),
            ),
        },
    };
    UnknownTimePublication::Refused {
        stage,
        reason,
        pending,
        receipt,
        rollover: None,
    }
}

impl UnknownTimeWorker {
    /// Inspect the existing epoch allowance without blocking archive work.
    pub fn remaining_audio_frames(&mut self) -> Result<u64, AudioAllowanceError> {
        if self.fenced {
            return Err(AudioAllowanceError::Fenced);
        }
        if self.running.is_some() {
            return Err(AudioAllowanceError::Busy);
        }
        match self.state.try_lock() {
            Ok(state) => Ok(state.parts.sink.remaining_audio_frames()),
            Err(TryLockError::WouldBlock) => Err(AudioAllowanceError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                Err(AudioAllowanceError::Fenced)
            }
        }
    }

    /// Renew the existing AAC clock without consuming the queued source or
    /// granting permission to retry a prior archive refusal.
    pub fn extend_audio_limit(
        &mut self,
        additional_frames: u64,
    ) -> Result<u64, AudioAllowanceError> {
        if self.fenced {
            return Err(AudioAllowanceError::Fenced);
        }
        if self.running.is_some() {
            return Err(AudioAllowanceError::Busy);
        }
        match self.state.try_lock() {
            Ok(mut state) => {
                state
                    .parts
                    .sink
                    .extend_audio_limit(additional_frames)
                    .map_err(AudioAllowanceError::Mux)?;
                Ok(state.parts.sink.remaining_audio_frames())
            }
            Err(TryLockError::WouldBlock) => Err(AudioAllowanceError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                Err(AudioAllowanceError::Fenced)
            }
        }
    }

    /// Reconstitute an exact in-process retirement without changing its fence
    /// or granting retry authority. No task or I/O is started.
    pub(crate) fn from_retirement(retirement: UnknownTimeRetirement) -> Self {
        Self {
            state: Arc::new(Mutex::new(UnknownTimeState {
                parts: retirement.parts,
                report: None,
                rollover_custody: retirement.rollover_custody,
            })),
            running: None,
            fenced: retirement.fenced,
        }
    }
    /// Whether this owner has no running attempt, pending source or fence.
    pub(crate) fn is_idle(&self) -> bool {
        if self.fenced || self.running.is_some() {
            return false;
        }
        self.state
            .try_lock()
            .is_ok_and(|state| !state.parts.sink.has_pending())
    }

    /// Construct an idle worker or return every original owner unchanged.
    pub fn new(parts: UnknownTimeParts) -> Result<Self, UnknownTimeParts> {
        if !(1..=100_000_000_000).contains(&parts.work_limit) {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(UnknownTimeState {
                parts,
                report: None,
                rollover_custody: None,
            })),
            running: None,
            fenced: false,
        })
    }

    /// Reattach a replayed cold-recovered lineage to an A/V worker.
    /// The sink and all switch owners are returned if verification fails.
    pub fn from_recovered(
        parts: UnknownTimeParts,
        mut custody: archive::journal::rollover::WorkerCustody,
    ) -> Result<Self, (UnknownTimeParts, archive::journal::rollover::WorkerCustody)> {
        if !(1..=100_000_000_000).contains(&parts.work_limit)
            || parts.sink.pending_publication().is_some()
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
            state: Arc::new(Mutex::new(UnknownTimeState {
                parts,
                report: None,
                rollover_custody: Some(custody),
            })),
            running: None,
            fenced: false,
        })
    }

    /// Admit a single original segment; refusal returns it unchanged.
    pub fn offer(&mut self, segment: recording::Segment) -> Result<(), UnknownTimeOfferRefusal> {
        if self.fenced {
            return Err(UnknownTimeOfferRefusal::Fenced(segment));
        }
        if self.running.is_some() {
            return Err(UnknownTimeOfferRefusal::Busy(segment));
        }
        match self.state.try_lock() {
            Ok(mut state) => state
                .parts
                .sink
                .offer(segment)
                .map_err(UnknownTimeOfferRefusal::Sink),
            Err(TryLockError::WouldBlock) => Err(UnknownTimeOfferRefusal::Busy(segment)),
            Err(TryLockError::Poisoned(_)) => {
                self.fenced = true;
                Err(UnknownTimeOfferRefusal::Fenced(segment))
            }
        }
    }

    /// Admit one region-owned blocking operation under explicit task grants.
    /// Cancellation is requested and drained before source ownership is released.
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
            let UnknownTimeState {
                parts,
                report,
                rollover_custody,
            } = &mut *state;
            if child.is_cancel_requested() {
                *report = Some(UnknownTimePublication::Refused {
                    stage: UnknownTimeFailureStage::BeforePublication,
                    reason: FailureReason::CancelledOrDenied,
                    pending: parts.sink.pending_publication(),
                    receipt: None,
                    rollover: None,
                });
                return;
            }
            if let Some(custody) = rollover_custody {
                if let Err(error) = custody.check(&parts.journal, &parts.keeper, &parts.replay) {
                    *report = Some(UnknownTimePublication::Refused {
                        stage: UnknownTimeFailureStage::BeforePublication,
                        reason: journal_reason(error),
                        pending: parts.sink.pending_publication(),
                        receipt: None,
                        rollover: None,
                    });
                    return;
                }
            }
            if child.is_cancel_requested() {
                *report = Some(UnknownTimePublication::Refused {
                    stage: UnknownTimeFailureStage::BeforePublication,
                    reason: FailureReason::CancelledOrDenied,
                    pending: parts.sink.pending_publication(),
                    receipt: None,
                    rollover: None,
                });
                return;
            }
            // Capacity must be checked before flush installs a candidate fence.
            // Once a settled predecessor is old enough to rotate, a definite
            // refusal here preserves the pending segment and allows the caller
            // to stage a successor without guessing whether publication ran.
            if parts.sink.pending_publication().is_none()
                && parts.journal.confirmed().is_some()
                && parts.journal.pending().is_none()
                && parts.journal.replay_pin().is_none()
                && parts.journal.anchor().sequence > 3
            {
                if let Err(error) = parts
                    .journal
                    .preflight_next_publication(&mut parts.keeper, &parts.replay)
                {
                    let reason = journal_reason(error);
                    let rollover = if reason == FailureReason::JournalCapacity {
                        parts.journal.confirmed().map(|confirmed| RolloverNeed {
                            confirmed,
                            journal: parts.journal.anchor(),
                            keeper: parts.keeper.anchor(),
                        })
                    } else {
                        None
                    };
                    *report = Some(UnknownTimePublication::Refused {
                        stage: UnknownTimeFailureStage::BeforePublication,
                        reason,
                        pending: None,
                        receipt: None,
                        rollover,
                    });
                    return;
                }
                if child.is_cancel_requested() {
                    *report = Some(UnknownTimePublication::Refused {
                        stage: UnknownTimeFailureStage::BeforePublication,
                        reason: FailureReason::CancelledOrDenied,
                        pending: None,
                        receipt: None,
                        rollover: None,
                    });
                    return;
                }
            }
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            let cancel = || child.is_cancel_requested();
            let mut budget = WorkBudget::with_cancellation_probe(parts.work_limit, &cancel);
            let outcome = parts.sink.flush(
                &mut parts.deployment,
                &access,
                parts.limits,
                &mut budget,
                &parts.replay,
                &mut parts.journal,
                &mut parts.keeper,
            );
            *report = Some(match outcome {
                Ok(Some(receipt)) => UnknownTimePublication::Published(receipt),
                Ok(None) => UnknownTimePublication::Empty,
                Err(error) => classify_unknown_time(
                    error,
                    child.is_cancel_requested(),
                    parts.sink.pending_publication(),
                ),
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

    /// Request cancellation without claiming that the attempt has drained.
    pub fn abort(&self) {
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Whether the coordinator has observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.running
            .as_ref()
            .is_some_and(Drained::cancellation_observed)
    }

    /// Join the exact operation; dropping this wait leaves its owners intact.
    pub async fn join(&mut self) -> Option<UnknownTimeCompletion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(work) => {
                drop(work);
                UnknownTimeOutcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => match state.report.take() {
                    Some(report) => UnknownTimeOutcome::Publication(report),
                    None => {
                        self.fenced = true;
                        UnknownTimeOutcome::Indeterminate
                    }
                },
                Err(_) => {
                    self.fenced = true;
                    UnknownTimeOutcome::Indeterminate
                }
            },
            WorkOutcome::Panicked => {
                self.fenced = true;
                UnknownTimeOutcome::Panicked
            }
            WorkOutcome::Indeterminate => {
                self.fenced = true;
                UnknownTimeOutcome::Indeterminate
            }
        };
        Some(UnknownTimeCompletion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover every owner after a running attempt has been joined.
    pub fn retire(self) -> Result<UnknownTimeRetirement, Self> {
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
                Ok(UnknownTimeRetirement {
                    parts: state.parts,
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
