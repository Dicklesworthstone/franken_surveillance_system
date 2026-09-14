//! Commitment of durable local root reachability to the canonical ledger (FSS-018, plan §13.4
//! step 9).
//!
//! [`LedgeredRootPublisher`] composes a [`LocalRootPublisher`] with a [`DurableReferenceLedger`]
//! through [`AuthorityPublisher`], so every commit re-proves child custody in the staging spool
//! immediately before the ledger's durable commit boundary.
//!
//! # Linkage encoding (existing `fss-core` types only)
//!
//! The reachability of the root durable in slot `<slot>` is exactly one [`EvidenceDelta`] in one
//! [`EvidenceDeltaBatch`]:
//!
//! | Field | Value |
//! |---|---|
//! | `batch_id` | `batch:local-root:<slot>` (deterministic, so a retry can never mint a second identity) |
//! | `delta_id` | `delta:local-root:<slot>` |
//! | `family` | [`ROOT_REACHABILITY_FAMILY`] |
//! | `object_id` | `object:local-root:<slot>` |
//! | `prior_generation` / `new_generation` | `None` / `1` (a slot holds at most one root) |
//! | `validity` | caller-supplied; this crate reads no ambient clock |
//! | `plane` | [`Plane::Authority`] |
//! | `payload_digest` | the manifest root |
//! | `witness_digest` / `operation_id` | `None` / `None` |
//! | batch `children` | the closure summary: every object reachable from the root except the root itself |
//!
//! Slot names longer than [`MAX_LEDGERED_SLOT_BYTES`] do not fit the 128-byte stable identifier
//! bound and are refused with [`RootLedgerError::SlotNotLedgerable`] before any disk mutation.
//!
//! # Ordering
//!
//! Disk-durable first, ledger second:
//!
//! 1. Refuse before any mutation when the slot has no ledger identity, a ledger append is
//!    unreconciled, or the ledger already claims a different root for the slot.
//! 2. Publish root-last through [`LocalRootPublisher::publish`] until the root is `Durable` (its
//!    roots-directory fsync was observed). A `Visible`-only root is never ledgered.
//! 3. Re-read the on-disk root record and require its observed digest.
//! 4. Prepare and append the reachability batch through [`AuthorityPublisher`], which re-proves
//!    the root body and every closure object verified in the spool before journal I/O.
//!
//! The ledger therefore never claims a root that was not durable at its commit. The reverse gap,
//! a durable root the ledger does not yet name, is not stored anywhere: it is recomputed from the
//! two durable owners by [`LedgeredRootPublisher::state`] and [`LedgeredRootPublisher::reconcile`]
//! as the explicit [`RootLedgerState::PendingLedger`] state, so there is no third record that a
//! crash could tear.
//!
//! | Crash or failure point | Disk | Ledger | After reopen |
//! |---|---|---|---|
//! | before the root rename | nothing visible | unchanged | `Absent` |
//! | after the rename, before the directory fsync | `Visible` | unchanged | `PendingLedger` (reopen admits and fsyncs) |
//! | after the root is `Durable`, before the append | `Durable` | unchanged | `PendingLedger` |
//! | ledger refuses the batch (stale anchor, reused identity, lost custody) | `Durable` | unchanged | `PendingLedger`; the call returns [`RootLedgerError::DurableUnledgered`] |
//! | append indeterminate | `Durable` | committed or not | `Ledgered` or `PendingLedger`; in process, [`RootLedgerError::LedgerIndeterminate`] until reconciled |
//! | after the append | `Durable` | committed | `Ledgered` |
//!
//! Retries are idempotent without relying on the ledger's duplicate classification: every commit
//! path first classifies the slot, and a root that is already `Ledgered` returns
//! [`RootLedgerOutcome::AlreadyLedgered`] without preparing or appending anything. A
//! never-committed batch identity is free, so the retry's fresh batch (at the current head) cannot
//! collide with it.
//!
//! External damage after a commit (a root record that no longer verifies) is surfaced as an
//! [`UnbackedLedgerClaim`], never hidden; the ledger is append-only and is not rewritten.
//!
//! Classification scans the committed batches once, `O(total deltas)`, and is bounded by the
//! history the durable ledger already retains.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    LedgerAnchor, ObjectId, ObjectRevision, Plane,
};
use fss_ledger::{
    DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy,
    JournalError, LedgerInspection,
};
use fss_object::ObjectManifest;

use crate::local::{
    LocalInspection, LocalPublicationError, LocalPublicationGuidance, LocalPublicationState,
    LocalRootPublisher, SlotName, VisibleRoot,
};
use crate::{AuthorityPublisher, PublicationError};

/// Semantic family of a root reachability delta.
pub const ROOT_REACHABILITY_FAMILY: &str = "local_root_reachability";
/// Prefix of the ledger object identity of a slot's root reachability.
pub const ROOT_REACHABILITY_OBJECT_PREFIX: &str = "object:local-root:";
/// Prefix of the deterministic batch identity of a slot's root reachability.
pub const ROOT_REACHABILITY_BATCH_PREFIX: &str = "batch:local-root:";
/// Prefix of the delta identity of a slot's root reachability.
pub const ROOT_REACHABILITY_DELTA_PREFIX: &str = "delta:local-root:";

/// Byte bound of an `fss_core` stable identifier (`ObjectId`, `BatchId`).
const STABLE_ID_MAX_BYTES: usize = 128;

/// Longest slot name whose ledger object and batch identities fit the stable identifier bound.
pub const MAX_LEDGERED_SLOT_BYTES: usize =
    STABLE_ID_MAX_BYTES - ROOT_REACHABILITY_OBJECT_PREFIX.len();

/// Every stable error identity a [`RootLedgerError`] can carry besides the nested
/// [`RootLedgerError::Local`] codes, which are listed in
/// [`crate::LOCAL_PUBLICATION_ERROR_CODES`].
pub const ROOT_LEDGER_ERROR_CODES: &[&str] = &[
    "ERR-PUBLICATION-LEDGER-SLOT-IDENTITY-001",
    "ERR-PUBLICATION-LEDGER-NOT-DURABLE-001",
    "ERR-PUBLICATION-LEDGER-CONFLICT-001",
    "ERR-PUBLICATION-LEDGER-PREPARED-MISMATCH-001",
    "ERR-PUBLICATION-LEDGER-ALREADY-LEDGERED-001",
    "ERR-PUBLICATION-LEDGER-UNLEDGERED-001",
    "ERR-PUBLICATION-LEDGER-INDETERMINATE-001",
    "ERR-PUBLICATION-LEDGER-RECONCILIATION-REQUIRED-001",
    "ERR-PUBLICATION-LEDGER-RECONCILE-001",
    "ERR-PUBLICATION-LEDGER-INJECTED-CRASH-001",
];

/// Ledger object identity of the root reachability of `slot`.
pub fn root_reachability_object_id(slot: &SlotName) -> Result<ObjectId, RootLedgerError> {
    check_ledgerable(slot)?;
    ObjectId::parse(format!("{ROOT_REACHABILITY_OBJECT_PREFIX}{slot}")).map_err(|error| {
        RootLedgerError::LedgerIdentity {
            slot: slot.clone(),
            error,
        }
    })
}

/// Deterministic batch identity of the root reachability of `slot`.
pub fn root_reachability_batch_id(slot: &SlotName) -> Result<BatchId, RootLedgerError> {
    check_ledgerable(slot)?;
    BatchId::parse(format!("{ROOT_REACHABILITY_BATCH_PREFIX}{slot}")).map_err(|error| {
        RootLedgerError::LedgerIdentity {
            slot: slot.clone(),
            error,
        }
    })
}

fn check_ledgerable(slot: &SlotName) -> Result<(), RootLedgerError> {
    let length = slot.as_str().len();
    if length > MAX_LEDGERED_SLOT_BYTES {
        return Err(RootLedgerError::SlotNotLedgerable {
            slot: slot.clone(),
            length,
            maximum: MAX_LEDGERED_SLOT_BYTES,
        });
    }
    Ok(())
}

fn slot_of(object_id: &ObjectId) -> Option<SlotName> {
    object_id
        .as_str()
        .strip_prefix(ROOT_REACHABILITY_OBJECT_PREFIX)
        .and_then(|slot| SlotName::parse(slot).ok())
}

/// Fault-injection cut points of the ledger linkage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LedgerCutPoint {
    /// The root is `Durable` on disk; its reachability batch has not been prepared.
    AfterRootDurable,
}

impl fmt::Display for LedgerCutPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AfterRootDurable => "after_root_durable",
        })
    }
}

/// Whether a commit call appended a batch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RootLedgerOutcome {
    /// This call appended the reachability batch.
    Committed,
    /// The ledger already named this root; nothing was prepared or appended.
    AlreadyLedgered,
}

/// A durable root the canonical ledger does not name yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLedgerRoot {
    /// Slot holding the durable root.
    pub slot: SlotName,
    /// Manifest root.
    pub root: ContentDigest,
    /// Unique objects in the root's closure, including the manifest body.
    pub closure_object_count: usize,
}

/// Receipt of a successful commit call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootLedgerReceipt {
    /// Slot holding the durable root.
    pub slot: SlotName,
    /// Manifest root.
    pub root: ContentDigest,
    /// Identity of the batch that made the reachability canonical.
    pub batch_id: BatchId,
    /// Anchor at which the reachability is visible.
    pub anchor: LedgerAnchor,
    /// Unique objects in the root's closure, including the manifest body.
    pub closure_object_count: usize,
    /// Whether this call appended the batch.
    pub outcome: RootLedgerOutcome,
}

/// Joint disk and ledger classification of one slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootLedgerState {
    /// No root is visible in the slot and the ledger names none.
    Absent,
    /// No root is admitted in the slot because its local root record failed verification or its
    /// root visibility is indeterminate, and the ledger names none. Never reported as `Absent`.
    BrokenLocalRoot,
    /// A manifest is staged in the spool for the slot, but not yet visible.
    Staged {
        /// Manifest root.
        root: ContentDigest,
    },
    /// The root is visible but its durability was never observed; it is never ledgered.
    VisibleNotDurable {
        /// Manifest root.
        root: ContentDigest,
    },
    /// The root is durable and the ledger does not name it.
    PendingLedger(PendingLedgerRoot),
    /// The root is durable and the ledger names exactly it.
    Ledgered {
        /// Manifest root.
        root: ContentDigest,
        /// Anchor of the batch that named it.
        anchor: LedgerAnchor,
        /// Identity of that batch.
        batch_id: BatchId,
    },
    /// The root is durable but the ledger names a different root or family for the slot.
    LedgerConflict {
        /// Root durable on disk.
        durable_root: ContentDigest,
        /// Payload the ledger names.
        ledgered_root: ContentDigest,
        /// Family the ledger names.
        ledgered_family: String,
    },
    /// The ledger names a root for the slot but no durable root backs it.
    LedgerWithoutDurableRoot {
        /// Payload the ledger names.
        ledgered_root: ContentDigest,
    },
}

/// A root that is durable and ledgered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgeredRoot {
    /// Slot holding the root.
    pub slot: SlotName,
    /// Manifest root.
    pub root: ContentDigest,
    /// Anchor of the batch that named it.
    pub anchor: LedgerAnchor,
    /// Identity of that batch.
    pub batch_id: BatchId,
}

/// A durable root whose slot the ledger assigns to something else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSlotConflict {
    /// Affected slot.
    pub slot: SlotName,
    /// Root durable on disk.
    pub durable_root: ContentDigest,
    /// Payload the ledger names.
    pub ledgered_root: ContentDigest,
    /// Family the ledger names.
    pub ledgered_family: String,
}

/// A ledger reachability claim that no durable local root backs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnbackedLedgerClaim {
    /// Ledger object identity.
    pub object_id: ObjectId,
    /// Slot named by the identity, when it parses.
    pub slot: Option<SlotName>,
    /// Payload the ledger names.
    pub ledgered_root: ContentDigest,
    /// Anchor of the batch that last wrote the claim.
    pub anchor: LedgerAnchor,
}

/// Deterministic joint classification of every visible root and every ledger claim.
///
/// Lists follow slot order for local roots and object-identity order for ledger claims.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RootLedgerReconciliation {
    /// Durable roots the ledger names exactly.
    pub ledgered: Vec<LedgeredRoot>,
    /// Durable roots the ledger does not name yet.
    pub pending: Vec<PendingLedgerRoot>,
    /// Visible roots whose durability was never observed.
    pub not_durable: Vec<SlotName>,
    /// Durable roots whose slot the ledger assigns to something else.
    pub conflicts: Vec<LedgerSlotConflict>,
    /// Visible roots whose slot has no ledger identity.
    pub unledgerable: Vec<SlotName>,
    /// Ledger claims that no durable root backs.
    pub unbacked_ledger_claims: Vec<UnbackedLedgerClaim>,
    /// Slots whose local root record failed verification or whose root visibility is
    /// indeterminate; none of them is admitted or ledgered.
    pub broken: Vec<SlotName>,
    /// First byte offset of an incomplete ledger tail, if present. Only [`inspect_linkage`] sets
    /// it: [`LedgeredRootPublisher::reconcile`] runs on a ledger opened without one.
    pub ledger_tail_incomplete: Option<u64>,
    /// Set only by [`inspect_linkage`]: the local roots were classified as durable because their
    /// records were observed on disk, without the directory fsync the open performs. It never
    /// makes a reconciliation unclean by itself.
    pub durability_not_resynced: bool,
}

impl RootLedgerReconciliation {
    /// True when every visible root is durable and ledgered and every claim is backed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.pending.is_empty()
            && self.not_durable.is_empty()
            && self.conflicts.is_empty()
            && self.unledgerable.is_empty()
            && self.unbacked_ledger_claims.is_empty()
            && self.broken.is_empty()
            && self.ledger_tail_incomplete.is_none()
    }
}

/// Safe next action for a rejected root-ledger operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootLedgerGuidance {
    /// The input is malformed or does not match durable state; do not retry as-is.
    RejectInput,
    /// Publish the root until it is durable, then commit.
    PublishDurablyFirst,
    /// Drop this instance and reopen both owners to reconcile.
    ReopenAndReconcile,
    /// The ledger identity is occupied by other content; resolve it explicitly.
    RepairLedgerIdentity,
    /// The reachability is already canonical; do not retry.
    AlreadyCommitted,
    /// The ledger head moved; retry the idempotent commit against the current head.
    RetryLedgerCommit,
    /// Closure custody was lost; repair or restage it, then retry.
    RepairCustody,
    /// Ledger storage failed before any ambiguity; repair storage, then retry.
    RepairStorage,
    /// Reconcile the indeterminate ledger append first.
    ReconcileLedgerAppend,
    /// Follow the nested local publication guidance.
    Local(LocalPublicationGuidance),
}

/// Failure of a root-ledger operation.
#[derive(Debug)]
pub enum RootLedgerError {
    /// The slot is longer than [`MAX_LEDGERED_SLOT_BYTES`].
    SlotNotLedgerable {
        /// Refused slot.
        slot: SlotName,
        /// Slot byte length.
        length: usize,
        /// Maximum ledgerable byte length.
        maximum: usize,
    },
    /// The slot's ledger identity failed stable-identifier validation.
    LedgerIdentity {
        /// Refused slot.
        slot: SlotName,
        /// Identifier contract failure.
        error: ContractError,
    },
    /// Local root-last publication failed; see the nested error for what is visible.
    Local(LocalPublicationError),
    /// The slot holds no durable root, so its reachability is never committed.
    NotDurable {
        /// Affected slot.
        slot: SlotName,
        /// Local state if a root is visible.
        state: Option<LocalPublicationState>,
    },
    /// The ledger already names a different root or family for the slot; nothing was appended.
    LedgerConflict {
        /// Affected slot.
        slot: SlotName,
        /// Root on disk or requested for publication.
        local_root: ContentDigest,
        /// Payload the ledger names.
        ledgered_root: ContentDigest,
    },
    /// A prepared batch is not the reachability batch of the slot's durable root.
    PreparedBatchMismatch {
        /// Affected slot.
        slot: SlotName,
        /// Identity carried by the offered batch.
        batch_id: BatchId,
    },
    /// The reachability is already canonical; there is nothing to prepare.
    AlreadyLedgered {
        /// Affected slot.
        slot: SlotName,
        /// Manifest root.
        root: ContentDigest,
        /// Anchor of the batch that named it.
        anchor: Box<LedgerAnchor>,
    },
    /// The root is durable but the ledger refused or could not prepare its batch.
    ///
    /// The root remains in the explicit [`RootLedgerState::PendingLedger`] state.
    DurableUnledgered {
        /// The durable, unledgered root.
        pending: PendingLedgerRoot,
        /// Ledger or custody failure.
        cause: Box<PublicationError>,
    },
    /// The root is durable and its reachability append is indeterminate.
    LedgerIndeterminate {
        /// The durable root whose append is unresolved.
        pending: PendingLedgerRoot,
        /// Journal sequence of the unresolved append.
        sequence: u64,
    },
    /// An indeterminate ledger append must be reconciled before any root-ledger work.
    LedgerReconciliationRequired {
        /// Journal sequence of the unresolved append.
        sequence: u64,
    },
    /// Reconciling an indeterminate ledger append failed.
    LedgerReconcile(PublicationError),
    /// A fault-injection cut point fired; the local publisher behaves as a dead process.
    InjectedCrash {
        /// Cut point that fired.
        point: LedgerCutPoint,
    },
}

impl RootLedgerError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SlotNotLedgerable { .. } | Self::LedgerIdentity { .. } => {
                "ERR-PUBLICATION-LEDGER-SLOT-IDENTITY-001"
            }
            Self::Local(error) => error.code(),
            Self::NotDurable { .. } => "ERR-PUBLICATION-LEDGER-NOT-DURABLE-001",
            Self::LedgerConflict { .. } => "ERR-PUBLICATION-LEDGER-CONFLICT-001",
            Self::PreparedBatchMismatch { .. } => "ERR-PUBLICATION-LEDGER-PREPARED-MISMATCH-001",
            Self::AlreadyLedgered { .. } => "ERR-PUBLICATION-LEDGER-ALREADY-LEDGERED-001",
            Self::DurableUnledgered { .. } => "ERR-PUBLICATION-LEDGER-UNLEDGERED-001",
            Self::LedgerIndeterminate { .. } => "ERR-PUBLICATION-LEDGER-INDETERMINATE-001",
            Self::LedgerReconciliationRequired { .. } => {
                "ERR-PUBLICATION-LEDGER-RECONCILIATION-REQUIRED-001"
            }
            Self::LedgerReconcile(_) => "ERR-PUBLICATION-LEDGER-RECONCILE-001",
            Self::InjectedCrash { .. } => "ERR-PUBLICATION-LEDGER-INJECTED-CRASH-001",
        }
    }

    /// Safe next action for this failure.
    #[must_use]
    pub fn guidance(&self) -> RootLedgerGuidance {
        match self {
            Self::SlotNotLedgerable { .. }
            | Self::LedgerIdentity { .. }
            | Self::PreparedBatchMismatch { .. } => RootLedgerGuidance::RejectInput,
            Self::Local(error) => RootLedgerGuidance::Local(error.guidance()),
            Self::NotDurable { state: None, .. } => RootLedgerGuidance::PublishDurablyFirst,
            Self::NotDurable { state: Some(_), .. } | Self::InjectedCrash { .. } => {
                RootLedgerGuidance::ReopenAndReconcile
            }
            Self::LedgerConflict { .. } => RootLedgerGuidance::RepairLedgerIdentity,
            Self::AlreadyLedgered { .. } => RootLedgerGuidance::AlreadyCommitted,
            Self::DurableUnledgered { cause, .. } => match cause.as_ref() {
                PublicationError::Object(_) => RootLedgerGuidance::RepairCustody,
                PublicationError::DuplicateBatchId(_)
                | PublicationError::Ledger(DurableLedgerError::BatchIdConflict { .. }) => {
                    RootLedgerGuidance::RepairLedgerIdentity
                }
                PublicationError::Ledger(DurableLedgerError::Contract(
                    ContractError::StaleAnchor,
                )) => RootLedgerGuidance::RetryLedgerCommit,
                PublicationError::Ledger(DurableLedgerError::Journal(_)) => {
                    RootLedgerGuidance::RepairStorage
                }
                PublicationError::Ledger(_) => RootLedgerGuidance::RejectInput,
            },
            Self::LedgerIndeterminate { .. } | Self::LedgerReconciliationRequired { .. } => {
                RootLedgerGuidance::ReconcileLedgerAppend
            }
            Self::LedgerReconcile(_) => RootLedgerGuidance::RepairStorage,
        }
    }
}

impl fmt::Display for RootLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Local(error) = self {
            return write!(formatter, "{error}");
        }
        write!(formatter, "{}: ", self.code())?;
        match self {
            Self::SlotNotLedgerable {
                slot,
                length,
                maximum,
            } => write!(
                formatter,
                "slot {slot} has {length} bytes; ledgerable maximum is {maximum}"
            ),
            Self::LedgerIdentity { slot, error } => {
                write!(formatter, "slot {slot} has no ledger identity: {error}")
            }
            Self::Local(_) => Ok(()),
            Self::NotDurable { slot, state } => {
                write!(formatter, "slot {slot} holds no durable root ({state:?})")
            }
            Self::LedgerConflict {
                slot,
                local_root,
                ledgered_root,
            } => write!(
                formatter,
                "ledger names {ledgered_root} for slot {slot}; local root is {local_root}"
            ),
            Self::PreparedBatchMismatch { slot, batch_id } => write!(
                formatter,
                "batch {batch_id} is not the reachability batch of slot {slot}"
            ),
            Self::AlreadyLedgered { slot, root, anchor } => write!(
                formatter,
                "root {root} of slot {slot} is ledgered at sequence {}",
                anchor.commit_sequence
            ),
            Self::DurableUnledgered { pending, cause } => write!(
                formatter,
                "root {} of slot {} is durable but unledgered: {cause}",
                pending.root, pending.slot
            ),
            Self::LedgerIndeterminate { pending, sequence } => write!(
                formatter,
                "root {} of slot {} is durable; ledger append {sequence} is indeterminate",
                pending.root, pending.slot
            ),
            Self::LedgerReconciliationRequired { sequence } => write!(
                formatter,
                "ledger append {sequence} must be reconciled first"
            ),
            Self::LedgerReconcile(cause) => {
                write!(formatter, "ledger reconciliation failed: {cause}")
            }
            Self::InjectedCrash { point } => write!(formatter, "injected crash {point}"),
        }
    }
}

impl Error for RootLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LedgerIdentity { error, .. } => Some(error),
            Self::Local(error) => Some(error),
            Self::DurableUnledgered { cause, .. } => Some(cause.as_ref()),
            Self::LedgerReconcile(cause) => Some(cause),
            _ => None,
        }
    }
}

/// The current ledger revision of one root reachability object.
#[derive(Clone, Debug)]
pub(crate) struct LedgerClaim {
    root: ContentDigest,
    family: String,
    plane: Plane,
    anchor: LedgerAnchor,
    batch_id: BatchId,
}

impl LedgerClaim {
    fn matches(&self, root: ContentDigest) -> bool {
        self.root == root
            && self.family == ROOT_REACHABILITY_FAMILY
            && self.plane == Plane::Authority
    }
}

/// Every ledger object in the root reachability namespace from views of batches and objects.
pub(crate) fn ledger_claims_from_views(
    batches: &[EvidenceDeltaBatch],
    objects: &BTreeMap<ObjectId, ObjectRevision>,
) -> BTreeMap<ObjectId, LedgerClaim> {
    let mut last_writer: BTreeMap<&ObjectId, &EvidenceDeltaBatch> = BTreeMap::new();
    for batch in batches {
        for delta in &batch.deltas {
            if delta
                .object_id
                .as_str()
                .starts_with(ROOT_REACHABILITY_OBJECT_PREFIX)
            {
                last_writer.insert(&delta.object_id, batch);
            }
        }
    }
    last_writer
        .into_iter()
        .filter_map(|(object_id, batch)| {
            objects.get(object_id).map(|revision| {
                (
                    object_id.clone(),
                    LedgerClaim {
                        root: revision.payload_digest,
                        family: revision.family.clone(),
                        plane: revision.plane,
                        anchor: batch.new_anchor.clone(),
                        batch_id: batch.batch_id.clone(),
                    },
                )
            })
        })
        .collect()
}

/// Every ledger object in the root reachability namespace, with the batch that last wrote it.
fn ledger_claims(ledger: &DurableReferenceLedger) -> BTreeMap<ObjectId, LedgerClaim> {
    ledger_claims_from_views(ledger.batches(), &ledger.current().objects)
}

/// Everything needed to commit the reachability of one durable root.
struct Target {
    pending: PendingLedgerRoot,
    object_id: ObjectId,
    batch_id: BatchId,
    delta_id: String,
    children: Vec<ContentDigest>,
    claim: Option<LedgerClaim>,
}

impl Target {
    fn delta(&self, validity: CaptureInterval) -> EvidenceDelta {
        EvidenceDelta {
            delta_id: self.delta_id.clone(),
            family: ROOT_REACHABILITY_FAMILY.to_owned(),
            object_id: self.object_id.clone(),
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: self.pending.root,
            witness_digest: None,
            operation_id: None,
        }
    }

    fn receipt(
        &self,
        batch_id: BatchId,
        anchor: LedgerAnchor,
        outcome: RootLedgerOutcome,
    ) -> RootLedgerReceipt {
        RootLedgerReceipt {
            slot: self.pending.slot.clone(),
            root: self.pending.root,
            batch_id,
            anchor,
            closure_object_count: self.pending.closure_object_count,
            outcome,
        }
    }
}

/// Classifies a failed prepare or append of a durable root's reachability batch.
fn commit_failure(pending: PendingLedgerRoot, cause: PublicationError) -> RootLedgerError {
    match cause {
        PublicationError::Ledger(DurableLedgerError::Journal(
            JournalError::AppendIndeterminate { sequence, .. },
        )) => RootLedgerError::LedgerIndeterminate { pending, sequence },
        PublicationError::Ledger(DurableLedgerError::Journal(
            JournalError::ReconciliationRequired { sequence },
        )) => RootLedgerError::LedgerReconciliationRequired { sequence },
        cause => RootLedgerError::DurableUnledgered {
            pending,
            cause: Box::new(cause),
        },
    }
}

/// Borrow-scoped coordinator that commits durable local root reachability to the canonical
/// ledger, disk-durable first. See the module documentation for the ordering contract.
pub struct LedgeredRootPublisher<'a> {
    local: &'a mut LocalRootPublisher,
    ledger: &'a mut DurableReferenceLedger,
    injected_crash: Option<LedgerCutPoint>,
}

impl<'a> LedgeredRootPublisher<'a> {
    /// Creates a coordinator over explicit local-publication and authority owners.
    #[must_use]
    pub fn new(local: &'a mut LocalRootPublisher, ledger: &'a mut DurableReferenceLedger) -> Self {
        Self {
            local,
            ledger,
            injected_crash: None,
        }
    }

    /// Arms a one-shot crash after the root is `Durable` and before its batch is prepared.
    ///
    /// When it fires, the call returns [`RootLedgerError::InjectedCrash`] and poisons the local
    /// publisher, leaving disk and ledger exactly as a process death at that point would.
    #[doc(hidden)]
    pub fn inject_crash_at(&mut self, point: LedgerCutPoint) {
        self.injected_crash = Some(point);
    }

    /// Publishes `manifest` into `slot` root-last until durable, then commits its reachability.
    ///
    /// A slot without a ledger identity, an unreconciled ledger append, or a ledger that already
    /// names a different root for the slot is refused before any disk mutation. Once the root is
    /// durable, every failure leaves it in the explicit [`RootLedgerState::PendingLedger`] state.
    pub fn publish_and_commit(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        validity: CaptureInterval,
    ) -> Result<RootLedgerReceipt, RootLedgerError> {
        self.require_no_pending_append()?;
        let object_id = root_reachability_object_id(slot)?;
        root_reachability_batch_id(slot)?;
        let claims = ledger_claims(self.ledger);
        if let Some(claim) = claims.get(&object_id)
            && !claim.matches(manifest.root())
        {
            return Err(RootLedgerError::LedgerConflict {
                slot: slot.clone(),
                local_root: manifest.root(),
                ledgered_root: claim.root,
            });
        }
        self.local
            .publish(slot, manifest)
            .map_err(RootLedgerError::Local)?;
        if self.injected_crash == Some(LedgerCutPoint::AfterRootDurable) {
            self.injected_crash = None;
            self.local.poison();
            return Err(RootLedgerError::InjectedCrash {
                point: LedgerCutPoint::AfterRootDurable,
            });
        }
        self.commit_root(slot, validity)
    }

    /// Commits the reachability of the root already durable in `slot`.
    ///
    /// Idempotent: a root the ledger already names returns [`RootLedgerOutcome::AlreadyLedgered`]
    /// without preparing or appending a batch.
    pub fn commit_root(
        &mut self,
        slot: &SlotName,
        validity: CaptureInterval,
    ) -> Result<RootLedgerReceipt, RootLedgerError> {
        let target = self.target(slot)?;
        if let Some(claim) = &target.claim {
            return Ok(target.receipt(
                claim.batch_id.clone(),
                claim.anchor.clone(),
                RootLedgerOutcome::AlreadyLedgered,
            ));
        }
        let batch = self.prepare(&target, validity)?;
        self.append(&target, batch)
    }

    /// Prepares, without appending, the reachability batch of the root durable in `slot`.
    ///
    /// Child custody is proven through [`AuthorityPublisher::prepare_batch`]. A prepare failure
    /// leaves the root in the explicit pending state.
    pub fn prepare_root_batch(
        &mut self,
        slot: &SlotName,
        validity: CaptureInterval,
    ) -> Result<EvidenceDeltaBatch, RootLedgerError> {
        let target = self.target(slot)?;
        if let Some(claim) = &target.claim {
            return Err(RootLedgerError::AlreadyLedgered {
                slot: slot.clone(),
                root: target.pending.root,
                anchor: Box::new(claim.anchor.clone()),
            });
        }
        self.prepare(&target, validity)
    }

    /// Commits a batch from [`Self::prepare_root_batch`] after proving it is exactly the
    /// reachability batch of the root durable in `slot`.
    ///
    /// A batch prepared against an anchor the ledger has since moved past is refused by the
    /// ledger and reported as [`RootLedgerError::DurableUnledgered`].
    pub fn commit_prepared(
        &mut self,
        slot: &SlotName,
        batch: EvidenceDeltaBatch,
    ) -> Result<RootLedgerReceipt, RootLedgerError> {
        let target = self.target(slot)?;
        let expected = batch
            .deltas
            .first()
            .map(|delta| target.delta(delta.validity));
        if batch.batch_id != target.batch_id
            || batch.deltas.len() != 1
            || expected.as_ref() != batch.deltas.first()
            || batch.children != target.children
        {
            return Err(RootLedgerError::PreparedBatchMismatch {
                slot: slot.clone(),
                batch_id: batch.batch_id,
            });
        }
        if let Some(claim) = &target.claim {
            return Ok(target.receipt(
                claim.batch_id.clone(),
                claim.anchor.clone(),
                RootLedgerOutcome::AlreadyLedgered,
            ));
        }
        self.append(&target, batch)
    }

    /// Joint disk and ledger classification of `slot`.
    ///
    /// Readable on a poisoned local publisher, so a crash is reported rather than hidden.
    pub fn state(&self, slot: &SlotName) -> Result<RootLedgerState, RootLedgerError> {
        self.require_no_pending_append()?;
        let object_id = root_reachability_object_id(slot)?;
        let claims = ledger_claims(self.ledger);
        Ok(self.classify(slot, claims.get(&object_id)))
    }

    /// Classifies every visible root and every ledger reachability claim.
    pub fn reconcile(&self) -> Result<RootLedgerReconciliation, RootLedgerError> {
        self.require_no_pending_append()?;
        let claims = ledger_claims(self.ledger);
        let report = reconcile_views(
            self.local.visible_roots(),
            self.local.broken_slots(),
            &claims,
            |slot, object_id| self.classify(slot, claims.get(object_id)),
        );
        Ok(report)
    }

    /// Reconciles an indeterminate ledger append through [`AuthorityPublisher::reconcile_pending`].
    pub fn reconcile_ledger_append(
        &mut self,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<DurableAppendReconciliation, RootLedgerError> {
        let mut authority = AuthorityPublisher::new(self.local.spool(), &mut *self.ledger);
        authority
            .reconcile_pending(tail_policy)
            .map_err(RootLedgerError::LedgerReconcile)
    }

    fn require_no_pending_append(&self) -> Result<(), RootLedgerError> {
        match self.ledger.pending_append_sequence() {
            Some(sequence) => Err(RootLedgerError::LedgerReconciliationRequired { sequence }),
            None => Ok(()),
        }
    }

    fn classify(&self, slot: &SlotName, claim: Option<&LedgerClaim>) -> RootLedgerState {
        classify_view(
            self.local.root(slot),
            self.local.root_closure(slot).map(|c| c.len()),
            self.local.is_broken_slot(slot),
            slot,
            claim,
        )
    }

    /// Requires a live local publisher, no unreconciled append, a durable root, and no
    /// conflicting ledger claim.
    fn target(&self, slot: &SlotName) -> Result<Target, RootLedgerError> {
        self.require_no_pending_append()?;
        if self.local.is_poisoned() {
            return Err(RootLedgerError::Local(LocalPublicationError::Poisoned));
        }
        let object_id = root_reachability_object_id(slot)?;
        let batch_id = root_reachability_batch_id(slot)?;
        let claim = ledger_claims(self.ledger).remove(&object_id);
        let not_durable = |state| RootLedgerError::NotDurable {
            slot: slot.clone(),
            state,
        };
        let (visible, closure) = self
            .local
            .root(slot)
            .zip(self.local.root_closure(slot))
            .ok_or_else(|| not_durable(None))?;
        if visible.state != LocalPublicationState::Durable {
            return Err(not_durable(Some(visible.state)));
        }
        let root = visible.root;
        if let Some(claim) = &claim
            && !claim.matches(root)
        {
            return Err(RootLedgerError::LedgerConflict {
                slot: slot.clone(),
                local_root: root,
                ledgered_root: claim.root,
            });
        }
        let closure_object_count = closure.len();
        let children = closure
            .into_iter()
            .filter(|digest| *digest != root)
            .collect();
        Ok(Target {
            pending: PendingLedgerRoot {
                slot: slot.clone(),
                root,
                closure_object_count,
            },
            object_id,
            batch_id,
            delta_id: format!("{ROOT_REACHABILITY_DELTA_PREFIX}{slot}"),
            children,
            claim,
        })
    }

    fn prepare(
        &mut self,
        target: &Target,
        validity: CaptureInterval,
    ) -> Result<EvidenceDeltaBatch, RootLedgerError> {
        let authority = AuthorityPublisher::new(self.local.spool(), &mut *self.ledger);
        authority
            .prepare_batch(
                target.batch_id.clone(),
                vec![target.delta(validity)],
                target.children.iter().copied(),
            )
            .map_err(|cause| commit_failure(target.pending.clone(), cause))
    }

    fn append(
        &mut self,
        target: &Target,
        batch: EvidenceDeltaBatch,
    ) -> Result<RootLedgerReceipt, RootLedgerError> {
        self.local
            .require_durable_record(&target.pending.slot)
            .map_err(RootLedgerError::Local)?;
        let batch_id = batch.batch_id.clone();
        let mut authority = AuthorityPublisher::new(self.local.spool(), &mut *self.ledger);
        match authority.append(batch) {
            Ok(anchor) => Ok(target.receipt(batch_id, anchor, RootLedgerOutcome::Committed)),
            Err(cause) => Err(commit_failure(target.pending.clone(), cause)),
        }
    }
}

/// Classifies a slot given views of local publication and ledger state.
pub(crate) fn classify_view(
    visible_root: Option<&VisibleRoot>,
    closure_len: Option<usize>,
    is_broken: bool,
    slot: &SlotName,
    claim: Option<&LedgerClaim>,
) -> RootLedgerState {
    let Some(visible) = visible_root else {
        return match claim {
            Some(claim) => RootLedgerState::LedgerWithoutDurableRoot {
                ledgered_root: claim.root,
            },
            None if is_broken => RootLedgerState::BrokenLocalRoot,
            None => RootLedgerState::Absent,
        };
    };
    if visible.state == LocalPublicationState::Staged {
        return RootLedgerState::Staged { root: visible.root };
    }
    if visible.state != LocalPublicationState::Durable {
        return RootLedgerState::VisibleNotDurable { root: visible.root };
    }
    let Some(closure_count) = closure_len else {
        return RootLedgerState::VisibleNotDurable { root: visible.root };
    };
    match claim {
        None => RootLedgerState::PendingLedger(PendingLedgerRoot {
            slot: slot.clone(),
            root: visible.root,
            closure_object_count: closure_count,
        }),
        Some(claim) if claim.matches(visible.root) => RootLedgerState::Ledgered {
            root: visible.root,
            anchor: claim.anchor.clone(),
            batch_id: claim.batch_id.clone(),
        },
        Some(claim) => RootLedgerState::LedgerConflict {
            durable_root: visible.root,
            ledgered_root: claim.root,
            ledgered_family: claim.family.clone(),
        },
    }
}

fn reconcile_views<'a>(
    visible_roots: impl Iterator<Item = &'a VisibleRoot>,
    broken_slots: impl Iterator<Item = &'a SlotName>,
    claims: &BTreeMap<ObjectId, LedgerClaim>,
    mut classify_fn: impl FnMut(&SlotName, &ObjectId) -> RootLedgerState,
) -> RootLedgerReconciliation {
    let mut report = RootLedgerReconciliation::default();
    let mut durable_ids = BTreeSet::new();

    for visible in visible_roots {
        let slot = &visible.slot;
        let Ok(object_id) = root_reachability_object_id(slot) else {
            report.unledgerable.push(slot.clone());
            continue;
        };
        if visible.state == LocalPublicationState::Durable {
            durable_ids.insert(object_id.clone());
        }
        match classify_fn(slot, &object_id) {
            RootLedgerState::Ledgered {
                root,
                anchor,
                batch_id,
            } => report.ledgered.push(LedgeredRoot {
                slot: slot.clone(),
                root,
                anchor,
                batch_id,
            }),
            RootLedgerState::PendingLedger(pending) => report.pending.push(pending),
            RootLedgerState::VisibleNotDurable { .. } => report.not_durable.push(slot.clone()),
            RootLedgerState::LedgerConflict {
                durable_root,
                ledgered_root,
                ledgered_family,
            } => report.conflicts.push(LedgerSlotConflict {
                slot: slot.clone(),
                durable_root,
                ledgered_root,
                ledgered_family,
            }),
            RootLedgerState::Absent
            | RootLedgerState::BrokenLocalRoot
            | RootLedgerState::Staged { .. }
            | RootLedgerState::LedgerWithoutDurableRoot { .. } => {}
        }
    }

    for (object_id, claim) in claims {
        if !durable_ids.contains(object_id) {
            report.unbacked_ledger_claims.push(UnbackedLedgerClaim {
                object_id: object_id.clone(),
                slot: slot_of(object_id),
                ledgered_root: claim.root,
                anchor: claim.anchor.clone(),
            });
        }
    }

    report.broken = broken_slots.cloned().collect();
    report
}

/// Classifies the relationship between local roots and canonical ledger claims without
/// acquiring locks or modifying state, through the same loop and per-slot classification as
/// [`LedgeredRootPublisher::reconcile`].
///
/// Inspection never fsyncs, so its admitted roots are `Visible`. When the inspection reports
/// `durability_not_resynced`, each such root is classified on its observed-on-disk basis, as the
/// open would classify it after its fsync, and the result carries `durability_not_resynced`. The
/// ledger side is its committed prefix; an incomplete tail is `ledger_tail_incomplete`, never
/// [`RootLedgerError::LedgerReconciliationRequired`].
#[must_use]
pub fn inspect_linkage(
    local: &LocalInspection,
    ledger: &LedgerInspection,
) -> RootLedgerReconciliation {
    let claims = ledger_claims_from_views(&ledger.batches, &ledger.snapshot.objects);
    let observed: Vec<VisibleRoot> = local
        .visible_roots()
        .map(|visible| observed_on_disk(visible, local.durability_not_resynced))
        .collect();
    let mut report = reconcile_views(
        observed.iter(),
        local.broken_slots(),
        &claims,
        |slot, object_id| {
            let visible = observed.iter().find(|root| &root.slot == slot);
            let closure_len = local.root_closure(slot).map(BTreeSet::len);
            let is_broken = local.is_broken_slot(slot);
            classify_view(visible, closure_len, is_broken, slot, claims.get(object_id))
        },
    );
    report.ledger_tail_incomplete = ledger.incomplete_tail;
    report.durability_not_resynced = local.durability_not_resynced;
    report
}

/// A `Visible` root whose record was observed on disk without a resync is classified with the
/// durability the open would confirm by fsync; any other state is kept.
fn observed_on_disk(visible: &VisibleRoot, not_resynced: bool) -> VisibleRoot {
    let mut root = visible.clone();
    if not_resynced && root.state == LocalPublicationState::Visible {
        root.state = LocalPublicationState::Durable;
    }
    root
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use fss_core::{BatchId, ContentDigest, ContractError, LedgerAnchor, ObjectId};

    use super::{
        LedgerCutPoint, MAX_LEDGERED_SLOT_BYTES, PendingLedgerRoot, ROOT_LEDGER_ERROR_CODES,
        ROOT_REACHABILITY_BATCH_PREFIX, ROOT_REACHABILITY_OBJECT_PREFIX, RootLedgerError,
        STABLE_ID_MAX_BYTES, root_reachability_batch_id, root_reachability_object_id,
    };
    use crate::PublicationError;
    use crate::local::{LocalPublicationError, SlotName};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn identity_bound_matches_core_stable_identifier_bound() -> TestResult {
        assert!(ObjectId::parse("a".repeat(STABLE_ID_MAX_BYTES)).is_ok());
        assert!(ObjectId::parse("a".repeat(STABLE_ID_MAX_BYTES + 1)).is_err());
        assert!(BatchId::parse("a".repeat(STABLE_ID_MAX_BYTES)).is_ok());
        assert!(BatchId::parse("a".repeat(STABLE_ID_MAX_BYTES + 1)).is_err());
        assert!(ROOT_REACHABILITY_BATCH_PREFIX.len() <= ROOT_REACHABILITY_OBJECT_PREFIX.len());
        let longest = SlotName::parse(&"z".repeat(MAX_LEDGERED_SLOT_BYTES))?;
        assert_eq!(
            root_reachability_object_id(&longest)?.len(),
            STABLE_ID_MAX_BYTES
        );
        assert!(root_reachability_batch_id(&longest)?.len() <= STABLE_ID_MAX_BYTES);
        Ok(())
    }

    #[test]
    fn every_variant_code_is_listed_exactly_once() -> TestResult {
        let slot = SlotName::parse("slot")?;
        let digest = ContentDigest::sha256(b"root");
        let pending = PendingLedgerRoot {
            slot: slot.clone(),
            root: digest,
            closure_object_count: 1,
        };
        let batch_id = BatchId::parse("batch:x")?;
        let errors = vec![
            RootLedgerError::SlotNotLedgerable {
                slot: slot.clone(),
                length: 2,
                maximum: 1,
            },
            RootLedgerError::LedgerIdentity {
                slot: slot.clone(),
                error: ContractError::InvalidIdentifier,
            },
            RootLedgerError::NotDurable {
                slot: slot.clone(),
                state: None,
            },
            RootLedgerError::LedgerConflict {
                slot: slot.clone(),
                local_root: digest,
                ledgered_root: digest,
            },
            RootLedgerError::PreparedBatchMismatch {
                slot: slot.clone(),
                batch_id: batch_id.clone(),
            },
            RootLedgerError::AlreadyLedgered {
                slot,
                root: digest,
                anchor: Box::new(LedgerAnchor::genesis("site:one")),
            },
            RootLedgerError::DurableUnledgered {
                pending: pending.clone(),
                cause: Box::new(PublicationError::DuplicateBatchId(batch_id.clone())),
            },
            RootLedgerError::LedgerIndeterminate {
                pending,
                sequence: 1,
            },
            RootLedgerError::LedgerReconciliationRequired { sequence: 1 },
            RootLedgerError::LedgerReconcile(PublicationError::DuplicateBatchId(batch_id)),
            RootLedgerError::InjectedCrash {
                point: LedgerCutPoint::AfterRootDurable,
            },
        ];
        let mut seen = BTreeSet::new();
        for error in &errors {
            assert!(
                ROOT_LEDGER_ERROR_CODES.contains(&error.code()),
                "{} is not listed",
                error.code()
            );
            assert!(error.to_string().starts_with(error.code()));
            seen.insert(error.code());
        }
        assert_eq!(seen.len(), ROOT_LEDGER_ERROR_CODES.len());

        let local = RootLedgerError::Local(LocalPublicationError::Poisoned);
        assert_eq!(local.code(), LocalPublicationError::Poisoned.code());
        assert!(local.to_string().starts_with(local.code()));
        Ok(())
    }
}
