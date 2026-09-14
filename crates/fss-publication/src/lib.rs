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
mod replay;

#[cfg(test)]
mod tests;

pub use error::PublicationError;
pub use ledger::{
    LedgerCutPoint, LedgerSlotConflict, LedgeredRoot, LedgeredRootPublisher,
    MAX_LEDGERED_SLOT_BYTES, PendingLedgerRoot, ROOT_LEDGER_ERROR_CODES,
    ROOT_REACHABILITY_BATCH_PREFIX, ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY,
    ROOT_REACHABILITY_OBJECT_PREFIX, RootLedgerError, RootLedgerGuidance, RootLedgerOutcome,
    RootLedgerReceipt, RootLedgerReconciliation, RootLedgerState, UnbackedLedgerClaim,
    inspect_linkage, root_reachability_batch_id, root_reachability_object_id,
};
pub use local::{
    BlockReason, BrokenRoot, BrokenRootReason, CapacityResource, ClaimStatus, HostLockTableSource,
    InjectedIoFault, IoFaultPoint, LOCAL_LOCK_FILE, LOCAL_PUBLICATION_ERROR_CODES,
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR,
    LOCAL_TOMBSTONE_RECORD_DOMAIN, LOCAL_TOMBSTONES_DIR, LocalInspection, LocalIoOperation,
    LocalLimitViolation, LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits,
    LocalPublicationReceipt, LocalPublicationState, LocalRecoveryReport, LocalRootPublisher,
    LockTableSource, MAX_LOCAL_ROOTS, MAX_LOCAL_TOMBSTONES, MAX_LOCK_TABLE_BYTES,
    MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, MAX_TOMBSTONE_RECORD_BYTES, PublicationClaims,
    PublicationTransition, PublishCancellation, PublishCutPoint, PublishOutcome,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole, SlotName,
    SlotViolation, StringLockTableSource, TOMBSTONE_RECORD_SUFFIX, TombstoneOutcome,
    UnknownLockReason, VisibleRoot, WriterDetectionOptions, WriterLockBasis, WriterState,
    decode_st_dev, detect_writers, inspect, inspect_with_io, inspect_with_ledger_journal,
    inspect_with_options, probe_shared_lock, read_verified, read_verified_with_io,
    root_record_bytes, tombstone_record_bytes,
};
pub use publisher::AuthorityPublisher;
pub use replay::{
    MAX_REPLAY_BATCHES, MAX_REPLAY_FAULT_DIRECTIVES, MAX_REPLAY_FAULT_REORDER_WINDOW,
    MAX_REPLAY_OBJECT_BYTES, MAX_REPLAY_OBJECTS, MAX_REPLAY_TEMP_ATTEMPTS, MAX_REPLAY_TEXT_BYTES,
    MAX_REPLAY_TOTAL_BYTES, REPLAY_BUNDLE_DOMAIN, REPLAY_BUNDLE_FORMAT_VERSION,
    REPLAY_BUNDLE_MAGIC, REPLAY_TRAILER_LEN, ReplayBundle, ReplayBundleError, ReplayBundleLimits,
    ReplayBundleReader, ReplayBundleReceipt, ReplayBundleWriter, ReplayFaultAction,
    ReplayFaultDirective, ReplayFaultSchedule, ReplayMetadata, ReplayObject, ReplayWriteRollback,
    replay_bundle_digest, replay_object_set_manifest, replay_temp_path_for,
};
