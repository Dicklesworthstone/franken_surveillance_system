#![forbid(unsafe_code)]
//! Deterministic in-memory reference provider for the FSS-061 protocol.
//!
//! Wraps [`crate::InMemoryObjectStore`] for byte custody and adds the
//! publication lattice, active-root registry, and replica accounting. No
//! threads, no clock: all time is caller-supplied; determinism is total.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, TimestampNs};

use crate::{InMemoryObjectStore, MAX_MANIFEST_CHILDREN, ObjectManifest};
use crate::provider::{
    ObjectStoreProvider, ProviderError, PublicationState, RetrievabilityWitness,
};

/// One object's provider-side record.
#[derive(Clone, Debug)]
struct LatticeRecord {
    state: PublicationState,
    replicas: u32,
}

/// Reference provider: custody store + lattice + active roots.
#[derive(Debug)]
pub struct InMemoryObjectStoreProvider {
    custody: InMemoryObjectStore,
    records: BTreeMap<ContentDigest, LatticeRecord>,
    /// Immutable graph bindings survive deactivation while their bodies remain retained.
    /// Retirement reclaims edges only after the terminal state and tombstone prevent reuse.
    manifests: BTreeMap<ContentDigest, ObjectManifest>,
    /// Independently active root pins; their transitive manifest closures remain protected.
    active_roots: BTreeSet<ContentDigest>,
    /// Replicas claimed once an object reaches `Replicated`.
    required_replicas: u32,
}

impl InMemoryObjectStoreProvider {
    /// Opens a provider over a custody store with the given replica floor
    /// (at least 1).
    #[must_use]
    pub fn new(custody: InMemoryObjectStore, required_replicas: u32) -> Self {
        Self {
            custody,
            records: BTreeMap::new(),
            manifests: BTreeMap::new(),
            active_roots: BTreeSet::new(),
            required_replicas: required_replicas.max(1),
        }
    }

    /// Number of objects the provider tracks (any lattice state).
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.records.len()
    }

    fn record(&self, digest: ContentDigest) -> Result<&LatticeRecord, ProviderError> {
        self.records
            .get(&digest)
            .ok_or(ProviderError::UnknownObject(digest))
    }

    fn record_mut(&mut self, digest: ContentDigest) -> Result<&mut LatticeRecord, ProviderError> {
        self.records
            .get_mut(&digest)
            .ok_or(ProviderError::UnknownObject(digest))
    }

    /// One iterative walk across the union of active closures, including inactive nested roots.
    /// Each identity is enqueued at most once, so shared subgraphs do not amplify memory/work.
    fn pinning_root(&self, target: ContentDigest) -> Option<ContentDigest> {
        let mut seen = BTreeSet::new();
        let mut pending = Vec::new();
        for &root in self.active_roots.iter().rev() {
            seen.insert(root);
            pending.push((root, root));
        }
        while let Some((digest, root)) = pending.pop() {
            if digest == target {
                return Some(root);
            }
            if let Some(manifest) = self.manifests.get(&digest) {
                for &child in manifest.children().iter().rev() {
                    if seen.insert(child) {
                        pending.push((child, root));
                    }
                }
            }
        }
        None
    }

    /// Validate the prospective graph without publishing a binding or advancing custody.
    fn verify_activation_closure(&self, manifest: &ObjectManifest) -> Result<(), ProviderError> {
        let root = manifest.root();
        let mut seen = BTreeSet::from([root]);
        let mut pending = Vec::new();
        for &child in manifest.children().iter().rev() {
            if child == root {
                return Err(ProviderError::RootCycle { root });
            }
            if seen.insert(child) {
                pending.push(child);
            }
        }
        while let Some(child) = pending.pop() {
            let child_state = self.record(child)?.state;
            if child_state.rank() < PublicationState::Durable.rank() {
                return Err(ProviderError::RootBeforeDurableChildren {
                    root,
                    child,
                    child_state,
                });
            }
            self.custody
                .read_verified(child)
                .map_err(|error| ProviderError::Custody(error.to_string()))?;
            if let Some(nested) = self.manifests.get(&child) {
                if nested.root() != child || nested.computed_root() != child {
                    return Err(ProviderError::InvalidRootManifest { root: child });
                }
                for &descendant in nested.children().iter().rev() {
                    if descendant == root {
                        return Err(ProviderError::RootCycle { root });
                    }
                    if seen.insert(descendant) {
                        pending.push(descendant);
                    }
                }
            }
        }
        Ok(())
    }

    /// Authority-carrying retirement: no active root may reference the
    /// object, and the custody tombstone requires the caller's
    /// deletion-authority witness (the digest of the owner-authorized
    /// deletion record). Bytes are genuinely released; the record stays for
    /// audit.
    fn retire_with_witness(
        &mut self,
        digest: ContentDigest,
        witness: ContentDigest,
    ) -> Result<(), ProviderError> {
        // The constructor may receive pre-populated custody. Membership must be checked before
        // any mutation: an unregistered payload must not be deleted and then return UnknownObject.
        self.record(digest)?;
        if let Some(root) = self.pinning_root(digest) {
            return Err(ProviderError::ActiveRootReference { digest, root });
        }
        if witness == digest {
            return Err(ProviderError::Custody(
                "deletion witness must remain retained separately".to_owned(),
            ));
        }
        // Refused retirement cannot promote staged custody to verified. Check all independent
        // preconditions and construct the tombstone before verify() changes the target state.
        self.custody
            .read_verified(witness)
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        let object_id = fss_core::ObjectId::parse(format!("object:{digest}"))
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        let record = fss_core::TombstoneRecord::new(
            object_id,
            fss_core::Generation::from_u64(2),
            fss_core::Generation::GENESIS,
            fss_core::TombstoneReason::Deleted,
            Some(witness),
            digest,
        )
        .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        // Borrow the already-admitted lattice entry before the first custody mutation.
        let entry = self
            .records
            .get_mut(&digest)
            .ok_or(ProviderError::UnknownObject(digest))?;
        self.custody
            .verify(digest)
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        self.custody
            .tombstone(digest, record)
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        entry.state = PublicationState::Retired;
        entry.replicas = 0;
        // No active ancestor can reach this body. Its terminal lattice record and custody
        // tombstone reject direct or nested reuse before graph lookup, so retained edges
        // can now be released together with the payload's byte quota.
        self.manifests.remove(&digest);
        Ok(())
    }
}

impl ObjectStoreProvider for InMemoryObjectStoreProvider {
    fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, ProviderError> {
        // Custody stage: bytes land, digest computed, bounds enforced.
        let digest = self
            .custody
            .stage(bytes)
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        self.records.entry(digest).or_insert(LatticeRecord {
            state: PublicationState::Staged,
            replicas: 0,
        });
        Ok(digest)
    }

    fn advance(
        &mut self,
        digest: ContentDigest,
        to: PublicationState,
    ) -> Result<PublicationState, ProviderError> {
        let record = self.record(digest)?;
        let from = record.state;
        if !from.can_advance_to(to) {
            return Err(ProviderError::IllegalTransition { digest, from, to });
        }
        // Retirement is not a ladder move: it carries deletion authority and
        // must go through `retire`, which takes the authority witness.
        if to == PublicationState::Retired {
            return Err(ProviderError::IllegalTransition { digest, from, to });
        }
        // Visibility and durability both re-verify bytes against their
        // identity (idempotent re-hash): a readable object is a verified
        // object at every ladder position from Visible up.
        if to == PublicationState::Visible || to == PublicationState::Durable {
            self.custody
                .verify(digest)
                .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        }
        if to == PublicationState::Replicated {
            let required = self.required_replicas;
            let record = self.record_mut(digest)?;
            record.replicas = required;
        }
        let record = self.record_mut(digest)?;
        record.state = to;
        Ok(to)
    }

    fn activate_root(
        &mut self,
        root: ContentDigest,
        children: &[ContentDigest],
    ) -> Result<(), ProviderError> {
        // Reject oversized input before allocation. Opaque aliases are not roots:
        // the actual durable manifest bytes must bind the exact supplied closure.
        if children.is_empty() {
            return Err(ProviderError::EmptyRoot { root });
        }
        if children.len() > MAX_MANIFEST_CHILDREN || children.contains(&root) {
            return Err(ProviderError::RootChildrenMismatch { root });
        }
        let state = self.record(root)?.state;
        if state.rank() < PublicationState::Durable.rank() {
            return Err(ProviderError::RootNotDurable { root, state });
        }
        let bytes = self
            .custody
            .read_verified(root)
            .map_err(|error| ProviderError::Custody(error.to_string()))?;
        let manifest = ObjectManifest::from_canonical_bytes(bytes)
            .map_err(|_| ProviderError::InvalidRootManifest { root })?;
        if manifest.root() != root {
            return Err(ProviderError::InvalidRootManifest { root });
        }
        let supplied: BTreeSet<_> = children.iter().copied().collect();
        if supplied.len() != children.len()
            || !supplied.iter().copied().eq(manifest.children().iter().copied())
            || self.manifests.get(&root).is_some_and(|prior| prior != &manifest)
        {
            return Err(ProviderError::RootChildrenMismatch { root });
        }
        self.verify_activation_closure(&manifest)?;
        // All checks precede publication. Bindings have at most MAX_MANIFEST_CHILDREN edges
        // and exist only for retained manifest bodies. Deactivation preserves their edges;
        // successful body retirement releases graph metadata together with payload quota.
        self.manifests.entry(root).or_insert(manifest);
        self.active_roots.insert(root);
        Ok(())
    }

    fn deactivate_root(&mut self, root: ContentDigest) -> Result<(), ProviderError> {
        self.active_roots.remove(&root);
        Ok(())
    }

    fn retire(
        &mut self,
        digest: ContentDigest,
        deletion_authority_witness: ContentDigest,
    ) -> Result<(), ProviderError> {
        self.retire_with_witness(digest, deletion_authority_witness)
    }

    fn verify_retrievable(
        &mut self,
        digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<RetrievabilityWitness, ProviderError> {
        // Pre-populated custody can already contain verified bytes before this provider stages
        // them. Its private verified state must never bypass the provider's visible-state gate.
        let record = self.record(digest).map_err(|_| ProviderError::NotRetrievable {
            digest,
            reason: "object is not registered with this provider".to_owned(),
        })?;
        if record.state.rank() < PublicationState::Visible.rank() {
            return Err(ProviderError::NotRetrievable {
                digest,
                reason: "object is not visible".to_owned(),
            });
        }
        let readable =
            self.custody
                .read_verified(digest)
                .map_err(|e| ProviderError::NotRetrievable {
                    digest,
                    reason: format!("{e}"),
                })?;
        // Re-hash: retrievability is witnessed against the identity, not
        // assumed from the store's bookkeeping.
        if ContentDigest::sha256(readable) != digest {
            return Err(ProviderError::NotRetrievable {
                digest,
                reason: "re-hash mismatch".to_string(),
            });
        }
        Ok(RetrievabilityWitness {
            digest,
            state: record.state,
            readable_copies: record.replicas.max(1),
            probed_at: now,
        })
    }

    fn state(&self, digest: ContentDigest) -> Result<PublicationState, ProviderError> {
        Ok(self.record(digest)?.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::CanonicalEncode;

    fn durable(
        provider: &mut InMemoryObjectStoreProvider,
        bytes: &[u8],
    ) -> Result<ContentDigest, ProviderError> {
        let digest = provider.stage(bytes)?;
        provider.advance(digest, PublicationState::Visible)?;
        provider.advance(digest, PublicationState::Durable)?;
        Ok(digest)
    }

    #[test]
    fn activation_reverifies_root_and_children_before_publishing_any_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        for corrupt_root in [true, false] {
            let mut provider = InMemoryObjectStoreProvider::new(
                InMemoryObjectStore::new(crate::ObjectLimits::new(8, 4096)),
                1,
            );
            let child = durable(&mut provider, b"fault-tested source")?;
            let manifest = ObjectManifest::new("fault-tested-root", [child], None)?;
            let root = durable(&mut provider, &manifest.try_canonical_bytes()?)?;
            provider
                .custody
                .corrupt_for_test(if corrupt_root { root } else { child })?;
            assert!(matches!(
                provider.activate_root(root, &[child]),
                Err(ProviderError::Custody(_))
            ));
            assert!(provider.active_roots.is_empty());
            assert!(provider.manifests.is_empty());
            assert_eq!(provider.state(root)?, PublicationState::Durable);
            assert_eq!(provider.state(child)?, PublicationState::Durable);
            assert_eq!(provider.object_count(), 2);
        }
        Ok(())
    }

    #[test]
    fn invalid_deletion_witness_does_not_advance_private_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = InMemoryObjectStoreProvider::new(
            InMemoryObjectStore::new(crate::ObjectLimits::new(8, 4096)),
            1,
        );
        let target = provider.stage(b"staged private source")?;
        let witness = provider.stage(b"staged witness")?;
        assert!(provider.retire(target, witness).is_err());
        assert_eq!(provider.custody.state(target), Some(crate::ObjectState::Staged));
        assert_eq!(provider.state(target)?, PublicationState::Staged);
        Ok(())
    }

    #[test]
    fn retiring_manifest_reclaims_edges_without_erasing_retirement_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = InMemoryObjectStoreProvider::new(
            InMemoryObjectStore::new(crate::ObjectLimits::new(8, 4096)),
            1,
        );
        let leaf = durable(&mut provider, b"metadata-reclamation source")?;
        let witness = durable(&mut provider, b"metadata-reclamation witness")?;
        let manifest = ObjectManifest::new("retired-binding", [leaf], None)?;
        let bytes = manifest.try_canonical_bytes()?;
        let root = durable(&mut provider, &bytes)?;
        provider.activate_root(root, manifest.children())?;
        provider.deactivate_root(root)?;
        assert!(provider.manifests.contains_key(&root));
        provider.retire(root, witness)?;
        assert!(!provider.manifests.contains_key(&root));
        assert_eq!(provider.state(root)?, PublicationState::Retired);
        assert!(matches!(
            provider.activate_root(root, manifest.children()),
            Err(ProviderError::RootNotDurable {
                state: PublicationState::Retired,
                ..
            })
        ));
        assert!(provider.stage(&bytes).is_err());

        let wrapper = ObjectManifest::new("retired-binding-wrapper", [root], None)?;
        let wrapper_root = durable(&mut provider, &wrapper.try_canonical_bytes()?)?;
        assert!(matches!(
            provider.activate_root(wrapper_root, wrapper.children()),
            Err(ProviderError::RootBeforeDurableChildren {
                child,
                child_state: PublicationState::Retired,
                ..
            }) if child == root
        ));
        assert!(provider.manifests.is_empty());
        provider.retire(leaf, witness)?;
        Ok(())
    }
}
