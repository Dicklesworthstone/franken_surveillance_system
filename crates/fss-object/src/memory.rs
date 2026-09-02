//! Bounded deterministic in-memory object-custody oracle.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncode, ContentDigest};

use crate::{ObjectError, ObjectManifest, ObjectState, PublicationReceipt, VerifiedObjectCatalog};

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredObject {
    bytes: Vec<u8>,
    state: ObjectState,
}

/// Resource limits for one deterministic object store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLimits {
    /// Maximum unique object count.
    pub max_objects: usize,
    /// Maximum aggregate bytes across unique staged objects.
    pub max_total_bytes: u64,
}

impl ObjectLimits {
    /// Creates explicit object-count and byte bounds.
    #[must_use]
    pub const fn new(max_objects: usize, max_total_bytes: u64) -> Self {
        Self {
            max_objects,
            max_total_bytes,
        }
    }
}

impl Default for ObjectLimits {
    fn default() -> Self {
        Self {
            max_objects: 65_536,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Deterministic reference object store.
///
/// Staged bytes are not readable through `read_verified`. Verification rehashes the exact bytes.
/// Publishing a manifest first proves every child verified, then stages/verifies the canonical
/// manifest object, and only then adds its root to the visible-root set.
#[derive(Clone, Debug)]
pub struct InMemoryObjectStore {
    limits: ObjectLimits,
    objects: BTreeMap<ContentDigest, StoredObject>,
    visible_manifests: BTreeMap<ContentDigest, ObjectManifest>,
    total_bytes: u64,
}

impl InMemoryObjectStore {
    /// Creates an empty store with explicit resource limits.
    #[must_use]
    pub fn new(limits: ObjectLimits) -> Self {
        Self {
            limits,
            objects: BTreeMap::new(),
            visible_manifests: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    /// Configured resource limits.
    #[must_use]
    pub const fn limits(&self) -> ObjectLimits {
        self.limits
    }

    /// Number of unique staged objects, including manifest objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Aggregate bytes across unique staged objects.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of root-last published manifests.
    #[must_use]
    pub fn published_manifest_count(&self) -> usize {
        self.visible_manifests.len()
    }

    /// Stages immutable bytes by SHA-256 content identity.
    ///
    /// All quota arithmetic and allocation for the candidate byte vector happen before map or
    /// accounting mutation. Restaging identical bytes is idempotent and consumes no new quota.
    pub fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, ObjectError> {
        if bytes.len() > crate::MAX_OBJECT_BYTES {
            return Err(ObjectError::ObjectTooLarge {
                length: bytes.len(),
                maximum: crate::MAX_OBJECT_BYTES,
            });
        }
        let digest = ContentDigest::sha256(bytes);
        if let Some(existing) = self.objects.get(&digest) {
            if existing.bytes == bytes {
                return Ok(digest);
            }
            return Err(ObjectError::DigestCollision(digest));
        }

        if self.objects.len() >= self.limits.max_objects {
            return Err(ObjectError::ObjectCountLimit {
                current: self.objects.len(),
                maximum: self.limits.max_objects,
            });
        }
        let requested =
            u64::try_from(bytes.len()).map_err(|_| ObjectError::ObjectTooLarge {
                length: bytes.len(),
                maximum: crate::MAX_OBJECT_BYTES,
            })?;
        let next_total =
            self.total_bytes
                .checked_add(requested)
                .ok_or(ObjectError::ByteQuotaExceeded {
                    current: self.total_bytes,
                    requested,
                    maximum: self.limits.max_total_bytes,
                })?;
        if next_total > self.limits.max_total_bytes {
            return Err(ObjectError::ByteQuotaExceeded {
                current: self.total_bytes,
                requested,
                maximum: self.limits.max_total_bytes,
            });
        }
        let owned = bytes.to_vec();
        self.objects.insert(
            digest,
            StoredObject {
                bytes: owned,
                state: ObjectState::Staged,
            },
        );
        self.total_bytes = next_total;
        Ok(digest)
    }

    /// Rehashes exact staged bytes and marks the object verified.
    pub fn verify(&mut self, digest: ContentDigest) -> Result<(), ObjectError> {
        let object = self
            .objects
            .get_mut(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        if ContentDigest::sha256(&object.bytes) != digest {
            return Err(ObjectError::Corrupt(digest));
        }
        object.state = ObjectState::Verified;
        Ok(())
    }

    /// Stages and verifies one immutable object.
    pub fn put_verified(&mut self, bytes: &[u8]) -> Result<ContentDigest, ObjectError> {
        let digest = self.stage(bytes)?;
        self.verify(digest)?;
        Ok(digest)
    }

    /// Returns exact bytes only after verification and rechecks integrity on every read.
    pub fn read_verified(&self, digest: ContentDigest) -> Result<&[u8], ObjectError> {
        let object = self
            .objects
            .get(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        if object.state != ObjectState::Verified {
            return Err(ObjectError::NotVerified(digest));
        }
        if ContentDigest::sha256(&object.bytes) != digest {
            return Err(ObjectError::Corrupt(digest));
        }
        Ok(&object.bytes)
    }

    /// Returns the local object state, if present.
    #[must_use]
    pub fn state(&self, digest: ContentDigest) -> Option<ObjectState> {
        self.objects.get(&digest).map(|object| object.state)
    }

    /// Publishes a manifest root after proving all referenced children verified.
    ///
    /// The manifest object is staged and verified before its root enters `visible_manifests`.
    /// Re-publication of the same canonical manifest is idempotent.
    pub fn publish_manifest(
        &mut self,
        manifest: ObjectManifest,
    ) -> Result<PublicationReceipt, ObjectError> {
        if manifest.computed_root() != manifest.root() {
            return Err(ObjectError::Corrupt(manifest.root()));
        }
        self.require_all_verified(manifest.children())?;
        let manifest_bytes = manifest.canonical_bytes();
        let root = self.stage(&manifest_bytes)?;
        if root != manifest.root() {
            return Err(ObjectError::Corrupt(manifest.root()));
        }
        self.verify(root)?;

        if let Some(existing) = self.visible_manifests.get(&root) {
            if existing == &manifest {
                return Ok(PublicationReceipt {
                    root,
                    child_count: manifest.children().len(),
                    closure_object_count: self.verify_closure(root)?,
                });
            }
            return Err(ObjectError::DigestCollision(root));
        }

        self.visible_manifests.insert(root, manifest);
        let closure_object_count = match self.verify_closure(root) {
            Ok(count) => count,
            Err(error) => {
                self.visible_manifests.remove(&root);
                return Err(error);
            }
        };
        Ok(PublicationReceipt {
            root,
            child_count: self
                .visible_manifests
                .get(&root)
                .map_or(0, |visible| visible.children().len()),
            closure_object_count,
        })
    }

    /// Returns a published manifest by exact root.
    pub fn published_manifest(
        &self,
        root: ContentDigest,
    ) -> Result<&ObjectManifest, ObjectError> {
        self.visible_manifests
            .get(&root)
            .ok_or(ObjectError::ManifestNotPublished(root))
    }

    /// Verifies the complete reachable closure and returns unique object count including roots.
    pub fn verify_closure(&self, root: ContentDigest) -> Result<usize, ObjectError> {
        if !self.visible_manifests.contains_key(&root) {
            return Err(ObjectError::ManifestNotPublished(root));
        }
        let mut seen = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(digest) = pending.pop() {
            if !seen.insert(digest) {
                continue;
            }
            self.require_verified(digest)?;
            if let Some(manifest) = self.visible_manifests.get(&digest) {
                for child in manifest.children().iter().rev() {
                    self.require_verified(*child)?;
                    pending.push(*child);
                }
            }
        }
        Ok(seen.len())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_for_test(&mut self, digest: ContentDigest) -> Result<(), ObjectError> {
        let object = self
            .objects
            .get_mut(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        if object.bytes.is_empty() {
            object.bytes.push(1);
        } else {
            object.bytes[0] ^= 1;
        }
        Ok(())
    }
}

impl VerifiedObjectCatalog for InMemoryObjectStore {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        let object = self
            .objects
            .get(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        if object.state != ObjectState::Verified {
            return Err(ObjectError::NotVerified(digest));
        }
        if ContentDigest::sha256(&object.bytes) != digest {
            return Err(ObjectError::Corrupt(digest));
        }
        Ok(())
    }
}
