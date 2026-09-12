#![forbid(unsafe_code)]
//! Immutable child-object custody and root-last publication reference semantics.
//!
//! The crate intentionally owns no network, async runtime, database, or remote archive behavior.
//! It is the deterministic oracle that later FrankenFS/ATP/provider adapters must match.
//! [`StagingSpool`] is its one local-filesystem backend: a crash-safe content-addressed staging
//! spool that holds staged and verified bytes and never claims visibility or durability.

mod error;
mod manifest;
mod memory;
pub mod model_license_policy;
pub mod model_manifest;
pub mod model_package;
mod spool;

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
    CorruptObject, CorruptionKind, DiscardReceipt, FaultInjectingSpoolIo, ForeignEntry,
    ForeignReason, HostSpoolIo, MAX_INTERRUPTED_ATTEMPTS, MAX_STAGING_NAME_ATTEMPTS,
    OrphanedStaging, SPOOL_HOLDS_DIR, SPOOL_HOLDS_MIGRATION_DIR, SPOOL_LOCK_FILE,
    SPOOL_OBJECT_FORMAT_VERSION, SPOOL_OBJECT_HEADER_LEN, SPOOL_OBJECT_MAGIC, SPOOL_OBJECTS_DIR,
    SPOOL_STAGING_DIR, SpoolError, SpoolFaultPlan, SpoolIo, SpoolIoCall, SpoolIoOperation,
    SpoolLimitViolation, SpoolLimits, SpoolObjectState, SpoolRecoveryReport, StageOutcome,
    StagePhase, StageReceipt, StagingSpool, encode_spool_object,
};

use fss_core::ContentDigest;

/// Maximum bytes admitted for one reference object.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum unique children in one canonical manifest.
pub const MAX_MANIFEST_CHILDREN: usize = 16_384;
/// Maximum UTF-8 bytes in a manifest kind.
pub const MAX_MANIFEST_KIND_BYTES: usize = 256;

/// Local custody state for immutable object bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectState {
    /// Bytes exist but have not passed a digest re-read.
    Staged,
    /// Exact bytes have been rehashed and match their content identity.
    Verified,
    /// Object has been tombstoned: payload bytes and quota released, record retained.
    Tombstoned,
}

/// Receipt emitted only after a manifest root is visible and its closure verifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    /// Published canonical manifest root.
    pub root: ContentDigest,
    /// Unique direct child roots named by the manifest.
    pub child_count: usize,
    /// Unique verified objects reachable from the root, including manifest objects.
    pub closure_object_count: usize,
}

/// Read-only capability for proving child-object availability before authority publication.
pub trait VerifiedObjectCatalog {
    /// Requires one exact object to exist, be verified, and still match its digest.
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError>;

    /// Requires every exact child root to be verified.
    fn require_all_verified(&self, digests: &[ContentDigest]) -> Result<(), ObjectError> {
        for digest in digests {
            self.require_verified(*digest)?;
        }
        Ok(())
    }
}
