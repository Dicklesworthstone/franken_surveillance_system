#![forbid(unsafe_code)]
//! Lock-free concurrent [`PackReader`] and cumulative [`PackReadBudget`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{ObjectError, VerifiedObjectCatalog};

use crate::compaction::{ReaderEpochGuard, ReaderEpochTracker};
use crate::error::PackError;
use crate::fd_pool::FdPool;
use crate::format::PackLocation;
use crate::index::PackIndex;
use crate::packfile::read_verified_location;
use crate::retention::ObjectTombstoneLog;

/// Cumulative non-refillable read byte budget for bounded verified pack reads.
#[derive(Debug)]
pub struct PackReadBudget {
    maximum_bytes: u64,
    used_bytes: AtomicU64,
}

impl PackReadBudget {
    /// Creates a cumulative read budget permitting at most `maximum_bytes` read bytes.
    #[must_use]
    pub const fn new(maximum_bytes: u64) -> Self {
        Self {
            maximum_bytes,
            used_bytes: AtomicU64::new(0),
        }
    }

    /// Returns bytes consumed so far.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    /// Returns remaining byte allowance.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        self.maximum_bytes.saturating_sub(self.used_bytes())
    }

    /// Atomically reserves `requested` bytes or fails closed with [`PackError::ReadLimitExceeded`].
    pub fn reserve(&self, requested: u64) -> Result<(), PackError> {
        self.used_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current
                    .checked_add(requested)
                    .filter(|&next| next <= self.maximum_bytes)
            })
            .map(|_| ())
            .map_err(|current| PackError::ReadLimitExceeded {
                current,
                requested,
                maximum: self.maximum_bytes,
            })
    }
}

/// Cloneable, lock-free concurrent reader handle over a [`crate::PackStore`].
///
/// Readers never acquire the [`crate::PackWriter`] mutex, so sealed pack reads run fully
/// concurrently with active pack appends, pack rotations, and online compaction while pinning a
/// [`ReaderEpochGuard`] so no referenced packfile can be unlinked mid-read.
#[derive(Clone, Debug)]
pub struct PackReader {
    pub(crate) index: Arc<RwLock<PackIndex>>,
    pub(crate) fd_pool: Arc<FdPool>,
    pub(crate) reader_epochs: Arc<ReaderEpochTracker>,
    pub(crate) tombstones: Arc<RwLock<ObjectTombstoneLog>>,
    pub(crate) max_object_bytes: u64,
    pub(crate) max_read_bytes: u64,
}

impl PackReader {
    /// Pins the current reader epoch until the returned [`ReaderEpochGuard`] is dropped.
    pub fn pin_epoch(&self) -> Result<ReaderEpochGuard, PackError> {
        self.reader_epochs.pin()
    }

    /// Looks up an object's [`PackLocation`] in O(1) time without touching disk.
    pub fn lookup(&self, digest: &ContentDigest) -> Result<Option<PackLocation>, PackError> {
        let guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(guard.get(digest))
    }

    /// Reads and cryptographically verifies an object by SHA-256 [`ContentDigest`].
    pub fn read_verified(&self, digest: &ContentDigest) -> Result<Vec<u8>, PackError> {
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(digest.algorithm()));
        }
        let _epoch_guard = self.reader_epochs.pin()?;
        {
            let tomb_guard = self
                .tombstones
                .read()
                .map_err(|_| PackError::LockPoisoned)?;
            if let Some(reason_digest) = tomb_guard.get(digest) {
                return Err(PackError::EvidenceDeleted {
                    digest: *digest,
                    reason_digest,
                });
            }
        }
        let location = {
            let guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
            guard.get(digest).ok_or(PackError::MissingObject(*digest))?
        };
        read_verified_location(
            &self.fd_pool,
            *digest,
            location,
            self.max_object_bytes,
            self.max_read_bytes,
        )
    }

    /// Reads and verifies an object while charging a cumulative [`PackReadBudget`].
    pub fn read_verified_with_budget(
        &self,
        digest: &ContentDigest,
        budget: &PackReadBudget,
    ) -> Result<Vec<u8>, PackError> {
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(digest.algorithm()));
        }
        let _epoch_guard = self.reader_epochs.pin()?;
        {
            let tomb_guard = self
                .tombstones
                .read()
                .map_err(|_| PackError::LockPoisoned)?;
            if let Some(reason_digest) = tomb_guard.get(digest) {
                return Err(PackError::EvidenceDeleted {
                    digest: *digest,
                    reason_digest,
                });
            }
        }
        let location = {
            let guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
            guard.get(digest).ok_or(PackError::MissingObject(*digest))?
        };
        let record_len = location.record_len()?;
        budget.reserve(record_len)?;
        read_verified_location(
            &self.fd_pool,
            *digest,
            location,
            self.max_object_bytes,
            self.max_read_bytes,
        )
    }

    /// Returns a reference to the shared bounded open-FD pool.
    #[must_use]
    pub fn fd_pool(&self) -> &FdPool {
        &self.fd_pool
    }
}

impl VerifiedObjectCatalog for PackReader {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        self.read_verified(&digest)
            .map(|_| ())
            .map_err(|err| err.to_object_error(digest))
    }
}
