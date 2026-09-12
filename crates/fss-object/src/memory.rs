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
    invalidated_manifests: BTreeMap<ContentDigest, ObjectManifest>,
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
            invalidated_manifests: BTreeMap::new(),
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
    ///
    /// When different bytes are already stored under the digest, the stored copy is rehashed
    /// first: if it no longer matches its content identity it is corrupt and the result is
    /// [`ObjectError::Corrupt`], exactly as `verify` and `read_verified` classify it. Only a
    /// stored copy that still hashes to the digest while differing from `bytes` is a
    /// [`ObjectError::DigestCollision`]. Neither case overwrites or re-accounts the stored copy.
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
            let stored = existing
                .bytes
                .as_deref()
                .ok_or(ObjectError::Corrupt(digest))?;
            if stored == bytes {
                return Ok(digest);
            }
            if ContentDigest::sha256(stored) != digest {
                return Err(ObjectError::Corrupt(digest));
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
    /// Re-publication of the same canonical manifest is idempotent. Re-publication over a stored
    /// manifest body whose bytes no longer match the root fails with [`ObjectError::Corrupt`];
    /// [`ObjectError::DigestCollision`] is reserved for distinct content under the same root.
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
    /// A verified deletion authority witness is mandatory; if `witness_digest` is `None`,
    /// fails with [`ObjectError::MissingDeletionAuthority`].
    /// Any published manifest whose reachable closure contains the tombstoned object is
    /// unpublished from visible manifests.
    /// Fails with [`ObjectError::TombstoneDigestMismatch`] if the record payload digest does not match,
    /// [`ObjectError::Missing`] if the object is absent,
    /// [`ObjectError::NotVerified`] if the object is staged,
    /// [`ObjectError::Missing`] or [`ObjectError::NotVerified`] if the witness digest is unverified,
    /// or [`ObjectError::TombstoneConflict`] if a different tombstone record was already applied.
    /// Idempotent if called with an identical tombstone record (even if the witness is later tombstoned).
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
        let (current_state, current_tombstone) = {
            let obj = self
                .objects
                .get(&digest)
                .ok_or(ObjectError::Missing(digest))?;
            (obj.state, obj.tombstone.clone())
        };

        if current_state == ObjectState::Tombstoned {
            if current_tombstone.as_ref() == Some(&record) {
                return Ok(());
            }
            return Err(ObjectError::TombstoneConflict(digest));
        }

        if current_state != ObjectState::Verified {
            return Err(ObjectError::NotVerified(digest));
        }

        let witness = record
            .witness_digest
            .ok_or(ObjectError::MissingDeletionAuthority(digest))?;
        self.require_verified(witness)?;

        let object = self
            .objects
            .get_mut(&digest)
            .ok_or(ObjectError::Missing(digest))?;

        let released_bytes = object.bytes.as_ref().map_or(0, |b| b.len() as u64);
        object.bytes = None;
        object.state = ObjectState::Tombstoned;
        object.tombstone = Some(record);
        self.total_bytes = self.total_bytes.saturating_sub(released_bytes);

        self.visible_manifests.remove(&digest);

        // Cascade unpublish all published parent manifests whose closure now contains a tombstoned object:
        let mut newly_invalidated = BTreeMap::new();
        let mut changed = true;
        while changed {
            changed = false;
            let mut to_remove = Vec::new();
            for (&root, manifest) in &self.visible_manifests {
                let mut has_tombstone = false;
                for &child in manifest.children() {
                    if self.is_tombstoned(child)
                        || newly_invalidated.contains_key(&child)
                        || self.invalidated_manifests.contains_key(&child)
                    {
                        has_tombstone = true;
                        break;
                    }
                }
                if has_tombstone {
                    to_remove.push(root);
                }
            }
            if !to_remove.is_empty() {
                changed = true;
                for root in to_remove {
                    if let Some(m) = self.visible_manifests.remove(&root) {
                        newly_invalidated.insert(root, m);
                    }
                }
            }
        }
        self.invalidated_manifests.extend(newly_invalidated);

        Ok(())
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

    /// Returns all manifest roots whose reachable closure contains at least one tombstoned object.
    ///
    /// Descends into published or invalidated sub-manifests, following the same closure rules as
    /// [`verify_closure`]. Returns manifest roots sorted in canonical order.
    #[must_use]
    pub fn published_manifests_with_tombstoned_closure(&self) -> Vec<ContentDigest> {
        let mut result = BTreeSet::new();
        for &root in self.invalidated_manifests.keys() {
            if !self.is_tombstoned(root) {
                result.insert(root);
            }
        }
        for &root in self.visible_manifests.keys() {
            if !self.is_tombstoned(root) && self.closure_contains_tombstone(root) {
                result.insert(root);
            }
        }
        result.into_iter().collect()
    }

    /// Returns true if the reachable closure from `root` contains at least one tombstoned object.
    ///
    /// If `root` itself is tombstoned, returns true. Descends into published and invalidated manifests.
    #[must_use]
    pub fn closure_contains_tombstone(&self, root: ContentDigest) -> bool {
        if self.is_tombstoned(root) || self.invalidated_manifests.contains_key(&root) {
            return true;
        }
        let mut seen = BTreeSet::new();
        seen.insert(root);
        let mut pending = vec![root];
        while let Some(digest) = pending.pop() {
            let manifest_opt = self
                .visible_manifests
                .get(&digest)
                .or_else(|| self.invalidated_manifests.get(&digest));
            if let Some(manifest) = manifest_opt {
                for &child in manifest.children() {
                    if self.is_tombstoned(child) || self.invalidated_manifests.contains_key(&child)
                    {
                        return true;
                    }
                    if seen.insert(child) {
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
