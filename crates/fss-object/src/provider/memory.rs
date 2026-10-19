#![forbid(unsafe_code)]
//! Deterministic in-memory reference provider for the FSS-061 protocol.
//!
//! Wraps [`crate::InMemoryObjectStore`] for byte custody and adds the
//! publication lattice, active-root registry, and replica accounting. No
//! threads, no clock: all time is caller-supplied; determinism is total.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, TimestampNs};

use crate::InMemoryObjectStore;
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
    /// Roots whose child references currently pin objects.
    active_roots: BTreeMap<ContentDigest, BTreeSet<ContentDigest>>,
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
            active_roots: BTreeMap::new(),
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
        // Deletion closure (R3): no active root may reference it.
        if let Some((root, _)) = self
            .active_roots
            .iter()
            .find(|(_, children)| children.contains(&digest))
        {
            return Err(ProviderError::ActiveRootReference {
                digest,
                root: *root,
            });
        }
        self.custody
            .verify(digest)
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
        self.custody
            .tombstone(digest, record)
            .map_err(|e| ProviderError::Custody(format!("{e}")))?;
        let entry = self.record_mut(digest)?;
        entry.state = PublicationState::Retired;
        entry.replicas = 0;
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
        // Durable admission re-verifies bytes against their identity.
        if to == PublicationState::Durable {
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
        // Root-last (R1): every child must be at least Durable, and a root
        // with no children is meaningless.
        if children.is_empty() {
            return Err(ProviderError::RootBeforeDurableChildren {
                root,
                child: root,
                child_state: PublicationState::Retired,
            });
        }
        for &child in children {
            let child_state = self.record(child)?.state;
            if child_state.rank() < PublicationState::Durable.rank() {
                return Err(ProviderError::RootBeforeDurableChildren {
                    root,
                    child,
                    child_state,
                });
            }
        }
        self.active_roots
            .entry(root)
            .or_default()
            .extend(children.iter().copied());
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
        let record = self.record(digest)?;
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
