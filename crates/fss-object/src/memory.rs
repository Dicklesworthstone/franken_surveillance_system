//! Bounded deterministic in-memory object-custody oracle.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncode, ContentDigest, TombstoneRecord};

use crate::{ObjectError, ObjectManifest, ObjectState, PublicationReceipt, VerifiedObjectCatalog};

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredObject {
    bytes: Option<Vec<u8>>,
    state: ObjectState,
    tombstone: Option<TombstoneRecord>,
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
            if existing.state == ObjectState::Tombstoned {
                return Err(ObjectError::Tombstoned(digest));
            }
            if existing.bytes.as_deref() == Some(bytes) {
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
                bytes: Some(owned),
                state: ObjectState::Staged,
                tombstone: None,
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
        if object.state == ObjectState::Tombstoned {
            return Err(ObjectError::Tombstoned(digest));
        }
        let bytes = object.bytes.as_ref().ok_or(ObjectError::Corrupt(digest))?;
        if ContentDigest::sha256(bytes) != digest {
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
        if object.state == ObjectState::Tombstoned {
            return Err(ObjectError::Tombstoned(digest));
        }
        if object.state != ObjectState::Verified {
            return Err(ObjectError::NotVerified(digest));
        }
        let bytes = object.bytes.as_ref().ok_or(ObjectError::Corrupt(digest))?;
        if ContentDigest::sha256(bytes) != digest {
            return Err(ObjectError::Corrupt(digest));
        }
        Ok(bytes.as_slice())
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
        if object.state == ObjectState::Tombstoned {
            return Err(ObjectError::Tombstoned(digest));
        }
        let bytes = object.bytes.as_mut().ok_or(ObjectError::Corrupt(digest))?;
        if bytes.is_empty() {
            bytes.push(1);
        } else {
            bytes[0] ^= 1;
        }
        Ok(())
    }

    /// Transitions a verified object to a permanent tombstone state.
    ///
    /// Keeps the tombstone record and content digest, but releases payload bytes and quota.
    /// If the object was a published manifest root, it is removed from visible manifests.
    /// Fails with [`ObjectError::TombstoneDigestMismatch`] if the record payload digest does not match,
    /// [`ObjectError::Missing`] or [`ObjectError::NotVerified`] if a present witness digest is unverified,
    /// [`ObjectError::Missing`] if the object is absent,
    /// [`ObjectError::NotVerified`] if the object is staged,
    /// or [`ObjectError::TombstoneConflict`] if a different tombstone record was already applied.
    /// Idempotent if called with an identical tombstone record.
    pub fn tombstone(
        &mut self,
        digest: ContentDigest,
        record: TombstoneRecord,
    ) -> Result<(), ObjectError> {
        if record.payload_digest != digest {
            return Err(ObjectError::TombstoneDigestMismatch {
                expected: digest,
                actual: record.payload_digest,
            });
        }
        if let Some(witness) = record.witness_digest {
            self.require_verified(witness)?;
        }
        let object = self
            .objects
            .get_mut(&digest)
            .ok_or(ObjectError::Missing(digest))?;

        match object.state {
            ObjectState::Staged => Err(ObjectError::NotVerified(digest)),
            ObjectState::Tombstoned => {
                if object.tombstone.as_ref() == Some(&record) {
                    self.visible_manifests.remove(&digest);
                    Ok(())
                } else {
                    Err(ObjectError::TombstoneConflict(digest))
                }
            }
            ObjectState::Verified => {
                let released_bytes = object.bytes.as_ref().map_or(0, |b| b.len() as u64);
                object.bytes = None;
                object.state = ObjectState::Tombstoned;
                object.tombstone = Some(record);
                self.total_bytes = self.total_bytes.saturating_sub(released_bytes);
                self.visible_manifests.remove(&digest);
                Ok(())
            }
        }
    }

    /// Returns the tombstone record for an object, if tombstoned.
    #[must_use]
    pub fn tombstone_record(&self, digest: ContentDigest) -> Option<&TombstoneRecord> {
        self.objects
            .get(&digest)
            .and_then(|obj| obj.tombstone.as_ref())
    }

    /// Returns true if the object is in tombstoned state.
    #[must_use]
    pub fn is_tombstoned(&self, digest: ContentDigest) -> bool {
        self.state(digest) == Some(ObjectState::Tombstoned)
    }

    /// Returns all published manifest roots whose reachable closure contains at least one tombstoned object.
    ///
    /// Descends into published sub-manifests bottom-up, following the same closure rules as
    /// [`verify_closure`]. Returns manifest roots sorted in canonical order.
    #[must_use]
    pub fn published_manifests_with_tombstoned_closure(&self) -> Vec<ContentDigest> {
        let mut result = Vec::new();
        for &root in self.visible_manifests.keys() {
            if self.closure_contains_tombstone(root) {
                result.push(root);
            }
        }
        result
    }

    /// Returns true if the reachable closure from `root` contains at least one tombstoned object.
    ///
    /// If `root` itself is tombstoned, returns true. Descends only into published sub-manifests.
    #[must_use]
    pub fn closure_contains_tombstone(&self, root: ContentDigest) -> bool {
        if self.state(root) == Some(ObjectState::Tombstoned) {
            return true;
        }
        let mut seen = BTreeSet::new();
        seen.insert(root);
        let mut pending = vec![root];
        while let Some(digest) = pending.pop() {
            if let Some(manifest) = self.visible_manifests.get(&digest) {
                for &child in manifest.children() {
                    if self.state(child) == Some(ObjectState::Tombstoned) {
                        return true;
                    }
                    if seen.insert(child) && self.visible_manifests.contains_key(&child) {
                        pending.push(child);
                    }
                }
            }
        }
        false
    }

    /// Alias for [`published_manifests_with_tombstoned_closure`].
    #[must_use]
    pub fn manifests_with_tombstoned_closure(&self) -> Vec<ContentDigest> {
        self.published_manifests_with_tombstoned_closure()
    }

    /// Alias for [`published_manifests_with_tombstoned_closure`].
    #[must_use]
    pub fn published_manifests_with_tombstoned_children(&self) -> Vec<ContentDigest> {
        self.published_manifests_with_tombstoned_closure()
    }
}

impl VerifiedObjectCatalog for InMemoryObjectStore {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        let object = self
            .objects
            .get(&digest)
            .ok_or(ObjectError::Missing(digest))?;
        if object.state == ObjectState::Tombstoned {
            return Err(ObjectError::Tombstoned(digest));
        }
        if object.state != ObjectState::Verified {
            return Err(ObjectError::NotVerified(digest));
        }
        let bytes = object.bytes.as_ref().ok_or(ObjectError::Corrupt(digest))?;
        if ContentDigest::sha256(bytes) != digest {
            return Err(ObjectError::Corrupt(digest));
        }
        Ok(())
    }
}
