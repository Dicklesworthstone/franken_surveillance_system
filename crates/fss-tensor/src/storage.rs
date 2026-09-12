//! Bounded backing byte storage for immutable and shared tensor buffers.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::Generation;

use crate::error::TensorError;

/// Maximum allowable single tensor storage allocation (256 MiB) to defend against hostile OOM.
pub const MAX_STORAGE_BYTES: usize = 256 * 1024 * 1024;

static NEXT_STORAGE_ID: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for an allocated tensor storage buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageId(pub u64);

impl StorageId {
    /// Generates a new unique monotonic storage identifier.
    #[must_use]
    pub fn next_id() -> Self {
        Self(NEXT_STORAGE_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for StorageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage-{}", self.0)
    }
}

/// Backing byte storage for tensors, bound to an explicit immutable generation.
#[derive(Debug, Clone)]
pub struct TensorStorage {
    id: StorageId,
    bytes: Arc<Vec<u8>>,
    generation: Generation,
}

impl TensorStorage {
    /// Creates storage from a vector of raw bytes and an explicit generation.
    ///
    /// # Errors
    /// Returns [`TensorError::AllocationLimitExceeded`] if `bytes.len() > MAX_STORAGE_BYTES`.
    pub fn from_vec(bytes: Vec<u8>, generation: Generation) -> Result<Self, TensorError> {
        if bytes.len() > MAX_STORAGE_BYTES {
            return Err(TensorError::AllocationLimitExceeded {
                requested_bytes: bytes.len(),
                max_bytes: MAX_STORAGE_BYTES,
            });
        }
        Ok(Self {
            id: StorageId::next_id(),
            bytes: Arc::new(bytes),
            generation,
        })
    }

    /// Allocates zero-initialized storage of specified byte size bound to an explicit generation.
    ///
    /// # Errors
    /// Returns [`TensorError::AllocationLimitExceeded`] if `size_bytes > MAX_STORAGE_BYTES`.
    pub fn zeros(size_bytes: usize, generation: Generation) -> Result<Self, TensorError> {
        if size_bytes > MAX_STORAGE_BYTES {
            return Err(TensorError::AllocationLimitExceeded {
                requested_bytes: size_bytes,
                max_bytes: MAX_STORAGE_BYTES,
            });
        }
        Ok(Self {
            id: StorageId::next_id(),
            bytes: Arc::new(vec![0u8; size_bytes]),
            generation,
        })
    }

    /// Returns the storage identifier.
    #[must_use]
    pub const fn id(&self) -> StorageId {
        self.id
    }

    /// Returns the total capacity in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the storage buffer is empty (0 bytes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the immutable generation to which this storage is pinned.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns a slice view of the entire underlying byte buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Extracts a subslice of bytes within the storage buffer.
    ///
    /// # Errors
    /// Returns [`TensorError::StorageOutOfBounds`] if `offset + len` exceeds storage size.
    pub fn slice_range(&self, offset: usize, len: usize) -> Result<&[u8], TensorError> {
        let end = offset
            .checked_add(len)
            .ok_or(TensorError::ArithmeticOverflow {
                operation: "storage subslice end calculation",
            })?;
        if end > self.bytes.len() {
            return Err(TensorError::StorageOutOfBounds {
                required_bytes: end,
                storage_bytes: self.bytes.len(),
            });
        }
        Ok(&self.bytes[offset..end])
    }
}
