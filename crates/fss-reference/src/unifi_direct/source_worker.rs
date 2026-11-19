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
    retirement_source, source_batch, source_evidence,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Retained, still-inactive binding between two source stores.
pub mod cross_store;

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
    /// Bounded original records owned together until publication is confirmed.
    Batch {
        /// Exact original source records in connection order.
        batch: retirement_source::Batch,
        /// Caller-bound source connection and generation.
        key: SourceKey,
        /// Caller-bound camera claim, not authenticated identity.
        camera_claim: ContentDigest,
    },
}
impl Input {
    fn bytes_len(&self) -> usize {
        match self {
            Self::Original { record, .. } => record.bytes().len(),
            Self::Recovered(source) => source.bytes().len(),
            Self::Batch { batch, .. } => batch.bytes(),
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
    /// Source batch preparation refused while preserving its original records.
    BatchPreparation(source_batch::Error),
    /// Work allowance or cancellation stopped preparation.
    Work,
    /// The candidate conflicts with the journal's pending or replay pin.
    Candidate,
    /// A new root cannot fit in the currently owned source deployment. The
    /// observation precedes journal preparation and reserves no future space.
    RootCapacity {
        /// Visible roots in this exclusive local owner.
        visible: usize,
        /// Configured visible-root limit.
        maximum: usize,
    },
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

/// Evidence of one confirmed source root copied to a separate local store.
/// The predecessor, successor, pending input and any prior custody remain
/// caller-owned. This receipt does not activate a successor, bind stores for
/// crash recovery, authenticate a camera or establish physical independence.
#[must_use = "retain both stores and separately bind the transition before activation"]
pub struct FreshStoreCopy {
    /// Exact source root selected from the predecessor's confirmed journal.
    pub pin: archive::UnknownTimePin,
    /// Prior journal head observed before and after the copy.
    pub predecessor_journal: EffectJournalPin,
    /// Prior keeper head observed before and after the copy.
    pub predecessor_keeper: EffectJournalPin,
    /// Successor journal head observed after the copy and readback.
    pub successor_journal: EffectJournalPin,
    /// Successor keeper head observed after the copy and readback.
    pub successor_keeper: EffectJournalPin,
    /// Actual destination ledger receipt, not an independently retained switch.
    pub receipt: RootLedgerReceipt,
}

/// A refused or uncertain cross-store copy. Both storage owners remain with
/// the caller; after a publication attempt the destination requires inspection.
#[derive(Debug)]
pub enum FreshStoreCopyError {
    /// The local owners, policies, destination, or source state were unsuitable.
    Preconditions,
    /// An existing predecessor rollover lineage could not be verified.
    PriorLineage(archive::journal::Error),
    /// The predecessor's ledgered source could not be read and verified.
    Read(archive::Error),
    /// The source's caller-bound camera claim did not match.
    CameraClaim,
    /// Reconstructing the exact source candidate failed.
    Candidate,
    /// Destination publication failed or may have taken effect.
    Publication(archive::UnknownTimePublishError),
    /// A receipt exists but post-publication checks did not finish or match.
    AfterPublication {
        /// Actual destination receipt; retain it for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Payload-free classification of the failed verification.
        reason: FreshStoreVerification,
    },
}

/// Post-publication verification classification; it grants no retry authority.
#[derive(Debug)]
pub enum FreshStoreVerification {
    /// The destination source could not be re-read under current authority.
    Read(archive::Error),
    /// Journal heads, destination ledger, claims, or the reconstructed root differed.
    Mismatch,
}

impl std::fmt::Display for FreshStoreCopyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Preconditions => "source store copy preconditions refused",
            Self::PriorLineage(_) => "source store predecessor lineage refused",
            Self::Read(_) => "source store predecessor read refused",
            Self::CameraClaim => "source store camera claim did not match",
            Self::Candidate => "source store candidate could not be reconstructed",
            Self::Publication(_) => "source store publication requires reconciliation",
            Self::AfterPublication { .. } => "source store readback requires reconciliation",
        })
    }
}
impl std::error::Error for FreshStoreCopyError {}

/// Copy one last-confirmed source graph into an empty-ledger successor.
///
/// This performs bounded synchronous storage I/O and must be called from a
/// region-owned blocking task. It never transfers or releases either owner or
/// the pending source. Publication is journaled by the successor's own keeper;
/// a later independently retained cross-store binding is still required before
/// this successor can replace the predecessor. On any error, inspect both owners
/// and the returned classification before retrying; this is not automatic
/// rollover or crash recovery.
pub fn copy_confirmed_to_fresh_store(
    old: &mut Retirement,
    next: &mut Parts,
    expected_camera_claim: ContentDigest,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<FreshStoreCopy, FreshStoreCopyError> {
    use fss_publication::RootLedgerOutcome;

    let Some(pin) = old.parts.journal.confirmed() else { return Err(FreshStoreCopyError::Preconditions) };
    if old.fenced
        || !old.parts.journal.locally_settled(&old.parts.keeper)
        || !next.journal.locally_settled(&next.keeper)
        || next.journal.confirmed().is_some()
        || old.parts.journal.scope() != next.journal.scope()
        || old.parts.retention != next.retention || pin.retention != next.retention
        || old.parts.deployment.root() == next.deployment.root()
        || old.parts.deployment.site_lineage() != next.deployment.site_lineage()
        || next.deployment.publisher().is_poisoned()
        || next.deployment.publisher().visible_root_count() != 0
        || next.deployment.publisher().broken_slots().next().is_some()
        || next.deployment.publisher().orphaned_temps().next().is_some()
        || next.deployment.publisher().tombstones().next().is_some()
        || next.deployment.current_anchor() != &fss_core::LedgerAnchor::genesis(next.deployment.site_lineage())
        || old.pending.as_ref().is_some_and(|input| !valid_input(input, next))
        || !read.permits(pin.retention, pin.root)
        || !next.authority.permits(pin.retention, pin.root)
    {
        return Err(FreshStoreCopyError::Preconditions);
    }
    if let Some(custody) = &mut old.rollover_custody {
        custody.check(&old.parts.journal, &old.parts.keeper, &old.parts.replay)
            .map_err(FreshStoreCopyError::PriorLineage)?;
    }
    let predecessor_journal = old.parts.journal.anchor();
    let predecessor_keeper = old.parts.keeper.anchor();
    let predecessor_ledger = old.parts.deployment.current_anchor().clone();
    let recovered = archive::read_unknown_time_source_graph(
        &mut old.parts.deployment, pin, read, old.parts.limits, work, &old.parts.replay,
    ).map_err(FreshStoreCopyError::Read)?;
    let receipt = match recovered {
        archive::RecoveredSourceGraph::Single(source) => {
            if source.camera_claim() != expected_camera_claim { return Err(FreshStoreCopyError::CameraClaim); }
            let plan = source_evidence::Prepared::from_recovered(&source);
            if archive::UnknownTimePin::from_source_plan(&plan) != pin { return Err(FreshStoreCopyError::Candidate); }
            archive::publish_unknown_time_source_anchored(&plan, &mut next.deployment,
                next.authority.as_ref(), next.limits, work, &next.replay, &mut next.journal, &mut next.keeper)
        }
        archive::RecoveredSourceGraph::Batch(source) => {
            if source.camera_claim != expected_camera_claim { return Err(FreshStoreCopyError::CameraClaim); }
            let plan = source_batch::Prepared::from_recovered(source).map_err(|_| FreshStoreCopyError::Candidate)?;
            if archive::UnknownTimePin::from_source_batch(&plan) != pin { return Err(FreshStoreCopyError::Candidate); }
            archive::publish_unknown_time_source_batch_anchored(&plan, &mut next.deployment,
                next.authority.as_ref(), next.limits, work, &next.replay, &mut next.journal, &mut next.keeper)
        }
    }.map_err(FreshStoreCopyError::Publication)?;
    let verified = (|| -> Result<(), FreshStoreVerification> {
        if receipt.outcome != RootLedgerOutcome::Committed || receipt.root != pin.root
            || &receipt.anchor != next.deployment.current_anchor()
            || next.journal.confirmed() != Some(pin) || !next.journal.locally_settled(&next.keeper)
            || old.parts.journal.anchor() != predecessor_journal || old.parts.keeper.anchor() != predecessor_keeper
            || old.parts.deployment.current_anchor() != &predecessor_ledger
        { return Err(FreshStoreVerification::Mismatch); }
        let reread = archive::read_unknown_time_source_graph(
            &mut next.deployment, pin, read, next.limits, work, &next.replay,
        ).map_err(FreshStoreVerification::Read)?;
        let matches = match reread {
            archive::RecoveredSourceGraph::Single(source) => source.camera_claim() == expected_camera_claim
                && archive::UnknownTimePin::from_source_plan(&source_evidence::Prepared::from_recovered(&source)) == pin,
            archive::RecoveredSourceGraph::Batch(source) => source.camera_claim == expected_camera_claim
                && source_batch::Prepared::from_recovered(source).ok()
                    .is_some_and(|plan| archive::UnknownTimePin::from_source_batch(&plan) == pin),
        };
        if matches { Ok(()) } else { Err(FreshStoreVerification::Mismatch) }
    })();
    if let Err(reason) = verified {
        return Err(FreshStoreCopyError::AfterPublication { receipt: Box::new(receipt), reason });
    }
    Ok(FreshStoreCopy { pin, predecessor_journal, predecessor_keeper,
        successor_journal: next.journal.anchor(), successor_keeper: next.keeper.anchor(), receipt })
}

/// A held input published and read back in a seeded successor. The old input
/// and both storage owners remain held by the caller. This is not an active
/// cross-store switch, a recovery inventory, or permission to delete history.
#[must_use = "retain both stores and independently bind their transition"]
pub struct FreshStorePending {
    /// Previously copied and verified predecessor source root.
    pub seed: archive::UnknownTimePin,
    /// Exact source root derived from the still-held pending input.
    pub pending: archive::UnknownTimePin,
    /// The destination's actual ledger receipt.
    pub receipt: RootLedgerReceipt,
    /// Destination publication journal after confirmation.
    pub successor_journal: EffectJournalPin,
    /// Destination separately retained journal anchor after confirmation.
    pub successor_keeper: EffectJournalPin,
}

/// A held input could not be copied or independently read back.
#[derive(Debug)]
pub enum FreshStorePendingError {
    /// Store, copied seed, retained input, or authority preconditions failed.
    Preconditions,
    /// The pending input belongs to a different caller-bound camera claim.
    CameraClaim,
    /// Bounded work or cancellation refused the operation.
    Work,
    /// The pending source could not be prepared as the same bounded candidate.
    Candidate,
    /// The successor has no capacity for another visible root.
    Capacity,
    /// The exact pending root's staging slot already has an unresolved temp.
    CandidateOrphan,
    /// The seeded source could not be read or verified.
    Seed(archive::Error),
    /// Publication failed or may have taken effect; inspect the destination.
    Publication(archive::UnknownTimePublishError),
    /// Publication returned a receipt but verification did not complete.
    AfterPublication {
        /// Actual destination receipt, retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Bounded failure classification, not authority to retry.
        reason: FreshStoreVerification,
    },
}
impl std::fmt::Display for FreshStorePendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Preconditions => "pending source copy preconditions refused",
            Self::CameraClaim => "pending source camera claim did not match",
            Self::Work => "pending source copy work refused",
            Self::Candidate => "pending source candidate refused",
            Self::Capacity => "pending source successor is full",
            Self::CandidateOrphan => "pending source staging slot requires reconciliation",
            Self::Seed(_) => "pending source seed read refused",
            Self::Publication(_) => "pending source publication requires reconciliation",
            Self::AfterPublication { .. } => "pending source readback requires reconciliation",
        })
    }
}
impl std::error::Error for FreshStorePendingError {}

/// Publish a predecessor's still-held input in a verified seeded successor.
///
/// This bounded synchronous I/O belongs on a region-owned blocking worker.
/// It never consumes the original input, activates a successor, or resolves a
/// camera effect. A failure during publication may have changed the successor;
/// reconcile its journal and any returned receipt before attempting anything
/// else. Store IDs, physical independence, and crash recovery are not proven.
pub fn copy_pending_to_seeded_store(
    old: &mut Retirement,
    next: &mut Parts,
    copied: &FreshStoreCopy,
    expected_camera_claim: ContentDigest,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<FreshStorePending, FreshStorePendingError> {
    use fss_publication::RootLedgerOutcome;

    let input = old.pending.as_ref().ok_or(FreshStorePendingError::Preconditions)?;
    if old.fenced || !old.parts.journal.locally_settled(&old.parts.keeper)
        || !next.journal.locally_settled(&next.keeper)
        || old.parts.journal.confirmed() != Some(copied.pin)
        || old.parts.journal.anchor() != copied.predecessor_journal
        || old.parts.keeper.anchor() != copied.predecessor_keeper
        || next.journal.confirmed() != Some(copied.pin)
        || next.journal.anchor() != copied.successor_journal
        || next.keeper.anchor() != copied.successor_keeper
        || old.parts.journal.scope() != next.journal.scope()
        || old.parts.retention != next.retention || copied.pin.retention != next.retention
        || old.parts.deployment.root() == next.deployment.root()
        || old.parts.deployment.site_lineage() != next.deployment.site_lineage()
        || copied.receipt.outcome != RootLedgerOutcome::Committed
        || copied.receipt.root != copied.pin.root
        || &copied.receipt.anchor != next.deployment.current_anchor()
        || next.deployment.publisher().is_poisoned()
        || next.deployment.publisher().visible_root_count() != 1
        || next.deployment.publisher().broken_slots().next().is_some()
        || next.deployment.publisher().tombstones().next().is_some()
        || !valid_input(input, next)
        || !read.permits(copied.pin.retention, copied.pin.root)
        || !next.authority.permits(copied.pin.retention, copied.pin.root)
    {
        return Err(FreshStorePendingError::Preconditions);
    }
    let input_camera = match input {
        Input::Original { camera_claim, .. } | Input::Batch { camera_claim, .. } => *camera_claim,
        Input::Recovered(source) => source.camera_claim(),
    };
    if input_camera != expected_camera_claim { return Err(FreshStorePendingError::CameraClaim); }
    let cost = u64::try_from(input.bytes_len()).ok().and_then(|n| n.checked_mul(2))
        .ok_or(FreshStorePendingError::Work)?;
    work.charge(cost).map_err(|_| FreshStorePendingError::Work)?;
    if let Some(custody) = &mut old.rollover_custody {
        custody.check(&old.parts.journal, &old.parts.keeper, &old.parts.replay)
            .map_err(|_| FreshStorePendingError::Preconditions)?;
    }
    let seed = archive::read_unknown_time_source_graph(
        &mut next.deployment, copied.pin, read, next.limits, work, &next.replay,
    ).map_err(FreshStorePendingError::Seed)?;
    let seed_camera = match seed {
        archive::RecoveredSourceGraph::Single(source) => source.camera_claim(),
        archive::RecoveredSourceGraph::Batch(source) => source.camera_claim,
    };
    if seed_camera != expected_camera_claim { return Err(FreshStorePendingError::CameraClaim); }
    enum Candidate<'a> { Source(source_evidence::Prepared<'a>), Batch(source_batch::Prepared) }
    let candidate = match input {
        Input::Original { record, key, disposition, camera_claim } => source_evidence::Prepared::new(
            record, *key, *disposition, *camera_claim, next.retention, next.max_source_bytes,
        ).map(Candidate::Source).map_err(|_| FreshStorePendingError::Candidate)?,
        Input::Recovered(source) => Candidate::Source(source_evidence::Prepared::from_recovered(source)),
        Input::Batch { batch, key, camera_claim } => Candidate::Batch(source_batch::Prepared::from_items(
            batch.items(), *key, *camera_claim, next.retention, batch.bytes(),
        ).map_err(|_| FreshStorePendingError::Candidate)?),
    };
    let pin = match &candidate {
        Candidate::Source(plan) => archive::UnknownTimePin::from_source_plan(plan),
        Candidate::Batch(plan) => archive::UnknownTimePin::from_source_batch(plan),
    };
    if pin == copied.pin { return Err(FreshStorePendingError::Candidate); }
    if archive::source_root_capacity(pin, &next.deployment).is_some() {
        return Err(FreshStorePendingError::Capacity);
    }
    // A retained temp for the already verified seed can coexist with the new
    // candidate, but an orphan at the candidate's exact slot must be resolved
    // before preparing its journal intent. The publisher enforces this same
    // slot check at commit; this earlier check preserves a clean journal.
    let candidate_slot = archive::slot_for_root(pin.root).map_err(|_| FreshStorePendingError::Candidate)?;
    let candidate_temp = fss_publication::LocalRootPublisher::root_temp_path(&candidate_slot);
    if next.deployment.publisher().orphaned_temps().any(|path| path == candidate_temp.as_path()) {
        return Err(FreshStorePendingError::CandidateOrphan);
    }
    if !read.permits(pin.retention, pin.root) || !next.authority.permits(pin.retention, pin.root) {
        return Err(FreshStorePendingError::Preconditions);
    }
    let old_ledger = old.parts.deployment.current_anchor().clone();
    let receipt = match &candidate {
        Candidate::Source(plan) => archive::publish_unknown_time_source_anchored(
            plan, &mut next.deployment, next.authority.as_ref(), next.limits, work,
            &next.replay, &mut next.journal, &mut next.keeper,
        ),
        Candidate::Batch(plan) => archive::publish_unknown_time_source_batch_anchored(
            plan, &mut next.deployment, next.authority.as_ref(), next.limits, work,
            &next.replay, &mut next.journal, &mut next.keeper,
        ),
    }.map_err(FreshStorePendingError::Publication)?;
    let verified = (|| -> Result<(), FreshStoreVerification> {
        if receipt.outcome != RootLedgerOutcome::Committed || receipt.root != pin.root
            || &receipt.anchor != next.deployment.current_anchor()
            || next.journal.confirmed() != Some(pin) || !next.journal.locally_settled(&next.keeper)
            || old.parts.journal.anchor() != copied.predecessor_journal
            || old.parts.keeper.anchor() != copied.predecessor_keeper
            || old.parts.deployment.current_anchor() != &old_ledger
        { return Err(FreshStoreVerification::Mismatch); }
        let recovered = archive::read_unknown_time_source_graph(
            &mut next.deployment, pin, read, next.limits, work, &next.replay,
        ).map_err(FreshStoreVerification::Read)?;
        let matches = match recovered {
            archive::RecoveredSourceGraph::Single(source) => source.camera_claim() == expected_camera_claim
                && archive::UnknownTimePin::from_source_plan(&source_evidence::Prepared::from_recovered(&source)) == pin,
            archive::RecoveredSourceGraph::Batch(source) => source.camera_claim == expected_camera_claim
                && source_batch::Prepared::from_recovered(source).ok()
                    .is_some_and(|plan| archive::UnknownTimePin::from_source_batch(&plan) == pin),
        };
        if matches { Ok(()) } else { Err(FreshStoreVerification::Mismatch) }
    })();
    if let Err(reason) = verified {
        return Err(FreshStorePendingError::AfterPublication { receipt: Box::new(receipt), reason });
    }
    Ok(FreshStorePending { seed: copied.pin, pending: pin, receipt,
        successor_journal: next.journal.anchor(), successor_keeper: next.keeper.anchor() })
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
        Input::Batch { batch, key, camera_claim } => {
            !batch.items().is_empty()
                && batch.items().len() <= source_batch::MAX_RECORDS
                && batch.bytes() <= source_batch::MAX_BYTES
                && batch.bytes() <= parts.limits.maximum_spool_object_bytes
                && batch.bytes() <= parts.deployment.publisher().limits().spool.max_object_bytes
                && batch.items().iter().all(|item| source_evidence::validate_input(
                    &item.record, *key, item.disposition, *camera_claim,
                    parts.retention, parts.max_source_bytes,
                ).is_ok())
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
    /// Compare the retained source policy without acquiring or granting authority.
    pub(crate) fn matches_retention(&self, retention: ContentDigest) -> bool {
        if self.fenced || self.running.is_some() {
            return false;
        }
        self.state.try_lock().is_ok_and(|state| state.parts.retention == retention)
    }

    /// Inspect immediately available custody without reading or changing storage.
    pub(crate) fn ready_for_start(&self) -> bool {
        if self.fenced || self.running.is_some() {
            return false;
        }
        self.state.try_lock().is_ok_and(|state| {
            state.pending.is_none()
                && state.parts.journal.pending().is_none()
                && state.parts.journal.replay_pin().is_none()
                && state.parts.keeper.target() == state.parts.journal.anchor()
                && state.parts.journal.confirmed().is_none_or(|pin| pin.retention == state.parts.retention)
                && !state.parts.deployment.publisher().is_poisoned()
                && (1024..=64 * 1024 * 1024).contains(&state.parts.limits.maximum_spool_object_bytes)
                && (1..=262_144).contains(&state.parts.limits.maximum_ledger_deltas)
                && state.parts.deployment.publisher().limits().spool.max_object_bytes <= state.parts.limits.maximum_spool_object_bytes
        })
    }

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
            let Some(preparation_cost) = (input.bytes_len() as u64).checked_mul(2) else {
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
            enum Candidate<'a> {
                Source(source_evidence::Prepared<'a>),
                Batch(source_batch::Prepared),
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
                ).map(Candidate::Source).map_err(Refusal::Preparation),
                Input::Recovered(source) => Ok(Candidate::Source(source_evidence::Prepared::from_recovered(source))),
                Input::Batch { batch, key, camera_claim } => source_batch::Prepared::from_items(
                    batch.items(), *key, *camera_claim, parts.retention, batch.bytes(),
                ).map(Candidate::Batch).map_err(Refusal::BatchPreparation),
            };
            let plan = match prepared {
                Ok(plan) => plan,
                Err(error) => {
                    *report = Some(Publication::Refused {
                        pin: None,
                        reason: error,
                    });
                    return;
                }
            };
            let pin = match &plan {
                Candidate::Source(plan) => archive::UnknownTimePin::from_source_plan(plan),
                Candidate::Batch(plan) => archive::UnknownTimePin::from_source_batch(plan),
            };
            let access = CurrentRetention {
                cx: &child,
                inner: parts.authority.as_ref(),
            };
            if parts.journal.locally_settled(&parts.keeper)
                && let Some((visible, maximum)) = archive::source_root_capacity(pin, &parts.deployment)
                && archive::RetainAuthority::permits(&access, parts.retention, pin.root)
                && !child.is_cancel_requested()
            {
                *report = Some(Publication::Refused {
                    pin: Some(pin),
                    reason: Refusal::RootCapacity { visible, maximum },
                });
                return;
            }
            *report = Some(
                match match &plan {
                    Candidate::Source(plan) => archive::publish_unknown_time_source_anchored(
                        plan, &mut parts.deployment, &access, parts.limits, &mut budget,
                        &parts.replay, &mut parts.journal, &mut parts.keeper),
                    Candidate::Batch(plan) => archive::publish_unknown_time_source_batch_anchored(
                        plan, &mut parts.deployment, &access, parts.limits, &mut budget,
                        &parts.replay, &mut parts.journal, &mut parts.keeper),
                } {
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
