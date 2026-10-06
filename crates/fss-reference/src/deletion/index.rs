#![forbid(unsafe_code)]
//! Read side of committed deletions: which imports, objects, units and slots are `deleted`.
//!
//! Built from the append-only ledger alone (the `deletion_record` and `deletion_completion`
//! deltas) plus the retained plan objects they name, so every reader (the locked deployment and
//! the lock-free orient reader) answers identically. A digest named by a committed plan is
//! `deleted` from the moment the record is durable, even while an interrupted commit has not yet
//! unlinked its bytes: content is never served after the tombstone.

mod proof;

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EvidenceDeltaBatch};

use super::DeletionError;
use super::plan::DeletionPlan;
use crate::ReferenceDeployment;

/// One committed deletion record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionEntry {
    /// Sealed plan identity.
    pub plan_digest: ContentDigest,
    /// The sealed plan.
    pub plan: DeletionPlan,
    /// Completion record identity, once appended.
    pub completion_digest: Option<ContentDigest>,
}

impl DeletionEntry {
    /// Whether the completion record is durable.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completion_digest.is_some()
    }
}

/// Every committed deletion of one deployment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeletionIndex {
    entries: Vec<DeletionEntry>,
    imports: BTreeMap<ContentDigest, usize>,
    objects: BTreeMap<ContentDigest, usize>,
    units: BTreeMap<String, usize>,
}

impl DeletionIndex {
    /// Builds the index from verified committed batches and exact retained plan/completion bytes.
    /// Partial authority prefixes deny reads of their whole closure, but never claim completion.
    /// Missing, duplicate, reordered or altered transitions and completion payloads fail closed.
    pub fn from_batches<E: From<DeletionError>>(
        batches: &[EvidenceDeltaBatch],
        read: impl FnMut(ContentDigest) -> Result<Vec<u8>, E>,
    ) -> Result<Self, E> {
        let mut index = Self::default();
        for entry in proof::read(batches, read)? {
            let position = index.entries.len();
            for import in &entry.plan.imports {
                index.imports.insert(*import, position);
            }
            for object in &entry.plan.deletable {
                index.objects.insert(object.digest, position);
            }
            for unit in &entry.plan.units {
                if unit.class == "deletable_content" {
                    index.units.insert(unit.id.clone(), position);
                }
            }
            index.entries.push(entry);
        }
        Ok(index)
    }

    /// Reads the index of an open deployment.
    pub fn read(deployment: &ReferenceDeployment) -> Result<Self, DeletionError> {
        let batches = deployment.ledger().batches();
        if !has_records(batches) {
            return Ok(Self::default());
        }
        let spool = deployment.publisher().spool();
        Self::from_batches(batches, |digest| {
            spool.read(digest).map_err(DeletionError::from)
        })
    }

    /// Whether no deletion was ever committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every committed deletion, in commit order.
    #[must_use]
    pub fn entries(&self) -> &[DeletionEntry] {
        &self.entries
    }

    /// The deletion of `import` (by an import, sensor or event scope), if committed.
    #[must_use]
    pub fn import(&self, import: ContentDigest) -> Option<&DeletionEntry> {
        self.imports.get(&import).map(|at| &self.entries[*at])
    }

    /// The deletion that removed object `digest`, if any.
    #[must_use]
    pub fn object(&self, digest: ContentDigest) -> Option<&DeletionEntry> {
        self.objects.get(&digest).map(|at| &self.entries[*at])
    }

    /// The deletion whose plan digest is `plan`, if committed.
    #[must_use]
    pub fn plan(&self, plan: ContentDigest) -> Option<&DeletionEntry> {
        self.entries.iter().find(|entry| entry.plan_digest == plan)
    }

    /// Whether unit `id` (a batch identity or `slot:<name>`) was deleted content.
    #[must_use]
    pub fn unit_deleted(&self, id: &str) -> bool {
        self.units.contains_key(id)
    }

    /// Every deleted object digest.
    #[must_use]
    pub fn deleted_objects(&self) -> BTreeSet<ContentDigest> {
        self.objects.keys().copied().collect()
    }
}

/// Whether any deletion-family authority or reserved batch identity exists. Orphan transitions
/// and completions must enter the verifier, even when their initial record is missing.
#[must_use]
pub fn has_records(batches: &[EvidenceDeltaBatch]) -> bool {
    batches.iter().any(proof::candidate)
}
