#![forbid(unsafe_code)]
//! Immutable child-object custody and root-last publication reference semantics.
//!
//! The crate intentionally owns no network, async runtime, database, or remote archive behavior.
//! It is the deterministic oracle that later FrankenFS/ATP/provider adapters must match.
//! [`StagingSpool`] retains content-addressed staged and verified bytes. The optional
//! [`upload_journal`] composes it into bounded multipart restart custody; neither backend
//! alone claims archive visibility, replication or retrievability.

/// Archive Decision Cards for path, repair, and object sizing (`FSS-134`, `fss-x4a.13.18`).
pub mod archive_decision_card;
/// Canonical ATP transfer, path, and archive lifecycles (`fss-x4a.13.31`).
pub mod atp_lifecycle;
pub mod belief_verification;
/// Deterministic ATP object-graph closure verifier (`FSS-127`, `fss-x4a.13.11`).
pub mod closure;
/// Graph-complete archive deletion traversal (`FSS-133`, `fss-x4a.13.17`).
pub mod deletion_closure;
/// Bounded local custody of the runtime effect coordinator's canonical history.
pub mod effect_journal;
/// Encryption-context manifest (FSS-065).
pub mod encryption;
mod error;
/// Independent manifest-only archive root reconstruction (`FSS-135`, `fss-x4a.13.19`).
pub mod independent_reconstruct;
mod manifest;
mod memory;
/// Model package RaptorQ/GF(256) protection and root-last ATP activation (`FSS-147`, `fss-x4a.14.18`).
pub mod model_atp_activation;
pub mod model_license_policy;
pub mod model_manifest;
pub mod model_package;
/// Focused S3-compatible multipart/conditional protocol (FSS-130).
pub mod multipart;
/// Multipath transfer race and loser-drain protocol (`FSS-129`, `fss-x4a.13.13`).
pub mod multipath;
/// Archive cost/chunk planner (FSS-067).
pub mod planner;
pub mod provider;
/// RaptorQ / systematic GF(256) post-repair canonical digest gate (`FSS-128`, `fss-x4a.13.12`).
pub mod repair_gate;
/// Archive replication-state and retrievability challenge ledger (`FSS-131`, `fss-x4a.13.15`).
pub mod replication;
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
