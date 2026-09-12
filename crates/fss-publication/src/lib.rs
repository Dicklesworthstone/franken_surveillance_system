#![forbid(unsafe_code)]
//! Root-last coordination between immutable child custody and canonical authority history.
//!
//! This crate is the semantic narrow waist between `fss-object` and `fss-ledger`: object custody
//! never imports authority, and the ledger never learns how objects are stored. The coordinator
//! proves every exact child root verified immediately before the authority batch is allowed to
//! cross the durable commit boundary.
//!
//! [`LocalRootPublisher`] (FSS-018) is the root-last local manifest publisher over
//! `fss_object::StagingSpool`: children and the manifest body are staged and verified first, the
//! root record is renamed into place last, and staged, visible, and durable states stay distinct.
//!
//! [`LedgeredRootPublisher`] (FSS-018, plan §13.4 step 9) commits a durable local root's
//! reachability to the canonical ledger as one `EvidenceDeltaBatch`, disk-durable first. A durable
//! root the ledger does not name yet is the explicit [`RootLedgerState::PendingLedger`] state.

mod error;
mod ledger;
mod local;
mod publisher;

#[cfg(test)]
mod tests;

pub use error::PublicationError;
pub use ledger::{
    LedgerCutPoint, LedgerSlotConflict, LedgeredRoot, LedgeredRootPublisher,
    MAX_LEDGERED_SLOT_BYTES, PendingLedgerRoot, ROOT_LEDGER_ERROR_CODES,
    ROOT_REACHABILITY_BATCH_PREFIX, ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY,
    ROOT_REACHABILITY_OBJECT_PREFIX, RootLedgerError, RootLedgerGuidance, RootLedgerOutcome,
    RootLedgerReceipt, RootLedgerReconciliation, RootLedgerState, UnbackedLedgerClaim,
    root_reachability_batch_id, root_reachability_object_id,
};
pub use local::{
    BlockReason, BrokenRoot, BrokenRootReason, CapacityResource, ClaimStatus, InjectedIoFault,
    IoFaultPoint, LOCAL_LOCK_FILE, LOCAL_PUBLICATION_ERROR_CODES, LOCAL_ROOT_RECORD_DOMAIN,
    LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR,
    LOCAL_TOMBSTONE_RECORD_DOMAIN, LOCAL_TOMBSTONES_DIR, LocalIoOperation, LocalLimitViolation,
    LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits,
    LocalPublicationReceipt, LocalPublicationState, LocalRecoveryReport, LocalRootPublisher,
    MAX_LOCAL_ROOTS, MAX_LOCAL_TOMBSTONES, MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES,
    MAX_TOMBSTONE_RECORD_BYTES, PublicationClaims, PublicationTransition, PublishCancellation,
    PublishCutPoint, PublishOutcome, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole, SlotName,
    SlotViolation, TOMBSTONE_RECORD_SUFFIX, TombstoneOutcome, VisibleRoot, root_record_bytes,
};
pub use publisher::AuthorityPublisher;
