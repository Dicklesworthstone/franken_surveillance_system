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
        let requested = u64::try_from(bytes.len()).map_err(|_| ObjectError::ObjectTooLarge {
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
        let quota_exceeded = if self.limits.max_total_bytes == 0 {
            next_total >= self.limits.max_total_bytes
        } else {
            next_total > self.limits.max_total_bytes
        };
        if quota_exceeded {
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
    /// # Root-Last Publication and Bottom-Up Ordering
    /// Manifests must be published bottom-up: every referenced sub-manifest must be published
    /// before any parent manifest that references it. `verify_closure` descends ONLY into children
    /// present in `visible_manifests`; a child not present in `visible_manifests` is treated
    /// strictly as an opaque leaf. An opaque leaf whose payload bytes happen to parse as an
    /// `ObjectManifest` does not trigger closure descent unless it was explicitly published.
    ///
    /// The manifest object is staged and verified before its root enters `visible_manifests`.
    /// Re-publication of the same canonical manifest is idempotent.
    /// On any failure during staging, verification, collision check, or closure verification,
    /// any newly staged object and allocated quota are rolled back cleanly, and any pre-existing
    /// object state (such as [`ObjectState::Staged`]) is preserved and restored.
    pub fn publish_manifest(
        &mut self,
        manifest: ObjectManifest,
    ) -> Result<PublicationReceipt, ObjectError> {
        if manifest.computed_root() != manifest.root() {
            return Err(ObjectError::Corrupt(manifest.root()));
        }
        self.require_all_verified(manifest.children())?;
        let root = manifest.root();
        let manifest_bytes = manifest.canonical_bytes();
        let prior_state = self.objects.get(&root).map(|object| object.state);
        let was_visible = self.visible_manifests.contains_key(&root);

        let stage_and_publish = |store: &mut Self| -> Result<PublicationReceipt, ObjectError> {
            let staged_root = store.stage(&manifest_bytes)?;
            if staged_root != root {
                return Err(ObjectError::Corrupt(root));
            }
            store.verify(root)?;

            if let Some(existing) = store.visible_manifests.get(&root) {
                if existing == &manifest {
                    return Ok(PublicationReceipt {
                        root,
                        child_count: manifest.children().len(),
                        closure_object_count: store.verify_closure(root)?,
                    });
                }
                return Err(ObjectError::DigestCollision(root));
            }

            store.visible_manifests.insert(root, manifest.clone());
            let closure_object_count = store.verify_closure(root)?;

            Ok(PublicationReceipt {
                root,
                child_count: manifest.children().len(),
                closure_object_count,
            })
        };

        match stage_and_publish(self) {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                if !was_visible {
                    self.visible_manifests.remove(&root);
                }
                match prior_state {
                    None => {
                        if self.objects.remove(&root).is_some() {
                            self.total_bytes =
                                self.total_bytes.saturating_sub(manifest_bytes.len() as u64);
                        }
                    }
                    Some(state) => {
                        if let Some(object) = self.objects.get_mut(&root) {
                            object.state = state;
                        }
                    }
                }
                Err(error)
            }
        }
    }

    /// Returns a published manifest by exact root, re-verifying content identity and custody.
    pub fn published_manifest(&self, root: ContentDigest) -> Result<&ObjectManifest, ObjectError> {
        let manifest = self
            .visible_manifests
            .get(&root)
            .ok_or(ObjectError::ManifestNotPublished(root))?;
        if manifest.computed_root() != root {
            return Err(ObjectError::Corrupt(root));
        }
        self.require_verified(root)?;
        Ok(manifest)
    }

    /// Verifies the complete reachable closure and returns unique object count including roots.
    ///
    /// Descends ONLY into children present in `visible_manifests`. A child not present in
    /// `visible_manifests` is an opaque leaf; opaque leaf bytes are never trial-parsed as manifests.
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

    /// Corrupts an object's stored bytes for fault-injection testing.
    pub fn corrupt_for_test(&mut self, digest: ContentDigest) -> Result<(), ObjectError> {
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
