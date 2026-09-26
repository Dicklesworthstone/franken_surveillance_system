#![forbid(unsafe_code)]
//! Read side of committed deletions: which imports, objects, units and slots are `deleted`.
//!
//! Built from the append-only ledger alone (the `deletion_record` and `deletion_completion`
//! deltas) plus the retained plan objects they name, so every reader (the locked deployment and
//! the lock-free orient reader) answers identically. A digest named by a committed plan is
//! `deleted` from the moment the record is durable, even while an interrupted commit has not yet
//! unlinked its bytes: content is never served after the tombstone.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EvidenceDeltaBatch};

use super::DeletionError;
use super::plan::{DeletionCompletion, DeletionPlan};
use crate::ReferenceDeployment;
use crate::reference_deployment::{FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD};

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
    /// Builds the index from committed batches; `read` returns the retained bytes of a digest.
    pub fn from_batches<E: From<DeletionError>>(
        batches: &[EvidenceDeltaBatch],
        mut read: impl FnMut(ContentDigest) -> Result<Vec<u8>, E>,
    ) -> Result<Self, E> {
        let mut index = Self::default();
        let mut completions: BTreeMap<String, ContentDigest> = BTreeMap::new();
        for batch in batches {
            for delta in &batch.deltas {
                if delta.family == FAMILY_DELETION_RECORD {
                    let bytes = read(delta.payload_digest)?;
                    let plan = DeletionPlan::decode(&bytes, delta.payload_digest)?;
                    if plan.record_object_id_of(delta.payload_digest) != delta.object_id.as_str() {
                        return Err(DeletionError::RecordMismatch.into());
                    }
                    let position = index.entries.len();
                    for import in &plan.imports {
                        index.imports.insert(*import, position);
                    }
                    for object in &plan.deletable {
                        index.objects.insert(object.digest, position);
                    }
                    for unit in &plan.units {
                        if unit.class == "deletable_content" {
                            index.units.insert(unit.id.clone(), position);
                        }
                    }
                    index.entries.push(DeletionEntry {
                        plan_digest: delta.payload_digest,
                        plan,
                        completion_digest: None,
                    });
                } else if delta.family == FAMILY_DELETION_COMPLETION {
                    completions.insert(delta.object_id.as_str().to_owned(), delta.payload_digest);
                }
            }
        }
        for entry in &mut index.entries {
            let object = entry.plan.record_object_id_of(entry.plan_digest);
            if let Some(digest) = completions.get(&object) {
                let bytes = read(*digest)?;
                let completion = DeletionCompletion::decode(&bytes, *digest)?;
                if completion.plan_digest != entry.plan_digest {
                    return Err(DeletionError::RecordMismatch.into());
                }
                entry.completion_digest = Some(*digest);
            }
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

/// Whether any committed batch carries a deletion record (no plan object is read otherwise).
#[must_use]
pub fn has_records(batches: &[EvidenceDeltaBatch]) -> bool {
    batches.iter().any(|batch| {
        batch
            .deltas
            .iter()
            .any(|delta| delta.family == FAMILY_DELETION_RECORD)
    })
}
