#![forbid(unsafe_code)]
//! Content-addressed [`PayloadResolver`] trait and built-in packfile / in-memory resolvers.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use fss_core::ContentDigest;
use fss_pack::{PackError, PackReader, PackStore};

use crate::error::ProjectionError;
use crate::payloads::{ProjectionRecordPayload, decode_delta_payload};

/// Resolves immutable content-addressed object payloads by [`ContentDigest`].
pub trait PayloadResolver: Send + Sync {
    /// Returns verified canonical bytes for `digest`, or `Ok(None)` when absent.
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError>;

    /// Resolves and cryptographically verifies a [`ProjectionRecordPayload`] for `delta`.
    ///
    /// The default implementation calls [`Self::resolve`] on `delta.payload_digest`, enforces
    /// `SHA-256(bytes) == delta.payload_digest`, and decodes `FSPP` v1 / `fss-core` bytes.
    /// Bridges over legacy v1 multi-family manifests (where e.g. `event_revision` and
    /// `sensor_tamper_status` share one manifest root digest) override this method while
    /// preserving full cryptographic verification of every underlying object.
    fn resolve_record_for_delta(
        &self,
        delta: &fss_core::EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let Some(raw_bytes) = self.resolve(&delta.payload_digest)? else {
            return Ok(None);
        };
        let actual_digest = ContentDigest::sha256(&raw_bytes);
        if actual_digest != delta.payload_digest {
            return Err(ProjectionError::PayloadDigestMismatch {
                expected: delta.payload_digest,
                actual: actual_digest,
            });
        }
        let payload_bytes = raw_bytes.len() as u64;
        let payload = decode_delta_payload(
            &delta.family,
            &delta.object_id,
            delta.validity,
            delta.payload_digest,
            &raw_bytes,
        )?;
        Ok(Some((payload, payload_bytes)))
    }
}

/// [`PayloadResolver`] backed by a lock-free concurrent [`PackReader`].
#[derive(Clone, Debug)]
pub struct PackReaderPayloadResolver {
    reader: PackReader,
}

impl PackReaderPayloadResolver {
    /// Wraps a [`PackReader`].
    #[must_use]
    pub const fn new(reader: PackReader) -> Self {
        Self { reader }
    }
}

impl PayloadResolver for PackReaderPayloadResolver {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        match self.reader.read_verified(digest) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(PackError::MissingObject(_)) => Ok(None),
            Err(err) => Err(ProjectionError::Pack(err)),
        }
    }
}

/// [`PayloadResolver`] borrowing a [`PackStore`] directly.
pub struct PackStorePayloadResolver<'a> {
    store: &'a PackStore,
}

impl<'a> PackStorePayloadResolver<'a> {
    /// Wraps a borrowed [`PackStore`].
    #[must_use]
    pub const fn new(store: &'a PackStore) -> Self {
        Self { store }
    }
}

impl PayloadResolver for PackStorePayloadResolver<'_> {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        match self.store.read_verified(digest) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(PackError::MissingObject(_)) => Ok(None),
            Err(err) => Err(ProjectionError::Pack(err)),
        }
    }
}

/// Thread-safe in-memory [`PayloadResolver`] for deterministic replay oracles and tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPayloadResolver {
    blobs: Arc<RwLock<BTreeMap<ContentDigest, Vec<u8>>>>,
}

impl InMemoryPayloadResolver {
    /// Creates an empty in-memory payload store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts immutable bytes and returns their canonical SHA-256 [`ContentDigest`].
    pub fn insert(&self, bytes: Vec<u8>) -> Result<ContentDigest, ProjectionError> {
        let digest = ContentDigest::sha256(&bytes);
        let mut guard = self
            .blobs
            .write()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        guard.insert(digest, bytes);
        Ok(digest)
    }

    /// Encodes and inserts a [`ProjectionRecordPayload`], returning `(digest, encoded_bytes)`.
    pub fn insert_payload(
        &self,
        payload: &ProjectionRecordPayload,
    ) -> Result<(ContentDigest, Vec<u8>), ProjectionError> {
        let bytes = payload.encode_bytes()?;
        let digest = self.insert(bytes.clone())?;
        Ok((digest, bytes))
    }
}

impl PayloadResolver for InMemoryPayloadResolver {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        let guard = self
            .blobs
            .read()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        Ok(guard.get(digest).cloned())
    }
}

/// Resolver that always returns `Ok(None)` when only metadata-only auxiliary families are present.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopPayloadResolver;

impl PayloadResolver for NoopPayloadResolver {
    fn resolve(&self, _digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        Ok(None)
    }
}
