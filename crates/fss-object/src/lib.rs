#![forbid(unsafe_code)]
//! Immutable child-object custody and root-last publication reference semantics.
//!
//! The crate intentionally owns no network, async runtime, database, or remote archive behavior.
//! It is the deterministic oracle that later FrankenFS/ATP/provider adapters must match.

mod error;
mod manifest;
mod memory;

#[cfg(test)]
mod tests;

pub use error::ObjectError;
pub use manifest::ObjectManifest;
pub use memory::{InMemoryObjectStore, ObjectLimits};

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
