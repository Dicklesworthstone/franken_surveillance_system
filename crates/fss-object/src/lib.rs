#![forbid(unsafe_code)]
//! Immutable child-object custody and root-last publication reference semantics.
//!
//! The crate intentionally owns no network, async runtime, database, or remote archive behavior.
//! It is the deterministic oracle that later FrankenFS/ATP/provider adapters must match.
//! [`StagingSpool`] retains content-addressed staged and verified bytes. The optional
//! [`upload_journal`] composes it into bounded multipart restart custody; neither backend
//! alone claims archive visibility, replication or retrievability.

pub mod belief_verification;
/// Bounded local custody of the runtime effect coordinator's canonical history.
pub mod effect_journal;
/// Encryption-context manifest (FSS-065).
pub mod encryption;
mod error;
mod manifest;
mod memory;
pub mod model_license_policy;
pub mod model_manifest;
pub mod model_package;
/// Focused S3-compatible multipart/conditional protocol (FSS-130).
pub mod multipart;
/// Archive cost/chunk planner (FSS-067).
pub mod planner;
pub mod provider;
/// Graph-aware local retention, evidence holds, and bounded expiry execution.
pub mod retention;
mod spool;
/// Durable, bounded multipart restart journal with an independently pinned history.
pub mod upload_journal;
/// Asupersync-owned staged uploader (FSS-063).
pub mod uploader;

#[cfg(test)]
mod tests;

pub use error::ObjectError;
pub use fss_core::TombstoneRecord;
pub use manifest::ObjectManifest;
pub use memory::{InMemoryObjectStore, ObjectLimits};
pub use model_license_policy::*;
pub use model_manifest::*;
pub use model_package::*;
pub use spool::{
    CorruptObject, CorruptionKind, DeletionRemoval, DiscardReceipt, FaultInjectingSpoolIo,
    ForeignEntry, ForeignReason, HostSpoolIo, MAX_INTERRUPTED_ATTEMPTS, MAX_STAGING_NAME_ATTEMPTS,
    OrphanedStaging, RecordingSpoolIo, SPOOL_HOLDS_DIR, SPOOL_HOLDS_MIGRATION_DIR, SPOOL_LOCK_FILE,
    SPOOL_OBJECT_FORMAT_VERSION, SPOOL_OBJECT_HEADER_LEN, SPOOL_OBJECT_MAGIC, SPOOL_OBJECTS_DIR,
    SPOOL_STAGING_DIR, SpoolError, SpoolFaultPlan, SpoolInspection, SpoolIo, SpoolIoCall,
    SpoolIoOperation, SpoolLimitViolation, SpoolLimits, SpoolLock, SpoolObjectState,
    SpoolReadBudgetUsage, SpoolRecoveryReport, StageOutcome, StagePhase, StageReceipt,
    StagingSpool, encode_spool_object, inspect, inspect_with_io, read_verified_payload,
};

mod contracts;
pub use contracts::*;
