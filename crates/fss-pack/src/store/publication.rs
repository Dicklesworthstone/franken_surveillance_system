#![forbid(unsafe_code)]
//! Current byte-custody checks at the virtual-root publication boundary.

use fss_core::ContentDigest;

use super::PackStore;
use crate::catalog::VirtualRootRecord;
use crate::compaction::ReaderEpochGuard;
use crate::error::PackError;

/// Held through catalog publication, not just until an index lookup succeeds.
///
/// Callers acquire the existing catalog write lock first. Object-deletion paths retain
/// that lock through tombstone commitment, so deletion cannot commit between verification
/// and publication. The epoch prevents concurrent compaction from unlinking a verified pack.
/// This checks the descriptor's direct root and metadata references; graph owners retain
/// responsibility for validating their format-specific child closure and effect authority.
pub(super) struct PublicationCustody<'a> {
    store: &'a PackStore,
    _epoch: ReaderEpochGuard,
}

impl<'a> PublicationCustody<'a> {
    pub(super) fn new(store: &'a PackStore) -> Result<Self, PackError> {
        let epoch = store.reader_epochs.pin()?;
        Ok(Self {
            store,
            _epoch: epoch,
        })
    }

    pub(super) fn verify_root(&self, record: &VirtualRootRecord) -> Result<(), PackError> {
        self.verify_object(record.root_digest)?;
        if let Some(metadata) = record.metadata_digest
            && metadata != record.root_digest
        {
            self.verify_object(metadata)?;
        }
        Ok(())
    }

    fn verify_object(&self, digest: ContentDigest) -> Result<(), PackError> {
        // Use the bounded tombstone/CRC/SHA-256 reader. Drop each payload before the next
        // read; publication retains no media buffers or additional index/tombstone locks.
        let _ = self.store.read_verified(&digest)?;
        Ok(())
    }
}
