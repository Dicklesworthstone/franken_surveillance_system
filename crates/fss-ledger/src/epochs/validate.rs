#![forbid(unsafe_code)]
//! Deterministic semantic batch admission and incremental Radix-Merkle delta application.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BatchId, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor,
    ObjectRevision,
};

use crate::merkle::RadixMerkleTrie;
use crate::oracle::{
    AnchorField, MAX_ORACLE_CHILDREN_PER_BATCH, MAX_ORACLE_DELTAS_PER_BATCH, MAX_ORACLE_TEXT_BYTES,
    OracleBoundField,
};

use super::{EpochLedgerError, successor_history_root_v2};

#[derive(Debug)]
pub(crate) struct ValidatedBatch {
    pub(crate) batch: EvidenceDeltaBatch,
    pub(crate) next_trie: RadixMerkleTrie,
    pub(crate) next_history_root: ContentDigest,
}

pub(crate) fn validate_and_apply_batch(
    head_anchor: &LedgerAnchor,
    head_history_root: ContentDigest,
    trie: &RadixMerkleTrie,
    batch_index: &BTreeMap<BatchId, (u64, ContentDigest)>,
    batch: EvidenceDeltaBatch,
    max_objects: Option<u64>,
) -> Result<ValidatedBatch, EpochLedgerError> {
    check_counts(batch.deltas.len(), batch.children.len())?;
    check_texts(&batch.deltas, &batch.basis_anchor, &batch.new_anchor)?;
    check_deltas(&batch.deltas)?;
    if !batch.is_canonically_ordered() {
        return Err(EpochLedgerError::NonCanonicalOrdering {
            batch_id: batch.batch_id,
        });
    }
    let computed = batch.computed_digest();
    if computed != batch.batch_digest {
        return Err(EpochLedgerError::BatchDigestMismatch {
            batch_id: batch.batch_id,
            declared: batch.batch_digest,
            computed,
        });
    }
    if let Some(&(committed_sequence, committed_digest)) = batch_index.get(&batch.batch_id) {
        return Err(if committed_digest == batch.batch_digest {
            EpochLedgerError::DuplicateBatch {
                batch_id: batch.batch_id,
                committed_sequence,
            }
        } else {
            EpochLedgerError::BatchIdConflict {
                batch_id: batch.batch_id,
                committed_sequence,
                committed_digest,
                offered_digest: batch.batch_digest,
            }
        });
    }

    let head_sequence = head_anchor.commit_sequence;
    let basis_sequence = batch.basis_anchor.commit_sequence;
    if basis_sequence > head_sequence {
        return Err(EpochLedgerError::SequenceGap {
            head_sequence,
            basis_sequence,
        });
    }
    if basis_sequence < head_sequence {
        if batch.basis_anchor.site_lineage != head_anchor.site_lineage
            || batch.basis_anchor.ledger_epoch != head_anchor.ledger_epoch
        {
            return Err(EpochLedgerError::BasisForked { basis_sequence });
        }
        return Err(EpochLedgerError::SuccessorConflict {
            basis_sequence,
            head_sequence,
        });
    }
    if &batch.basis_anchor != head_anchor {
        return Err(EpochLedgerError::BasisForked { basis_sequence });
    }

    let expected_sequence = head_sequence
        .checked_add(1)
        .ok_or(EpochLedgerError::SequenceExhausted)?;
    check_successor(&batch.basis_anchor, &batch.new_anchor, expected_sequence)?;

    let next_trie = apply_deltas_incremental(trie, &batch.deltas, max_objects)?;
    let computed_root = next_trie.root();
    if computed_root != batch.new_anchor.state_root {
        return Err(EpochLedgerError::StateRootMismatch {
            declared: batch.new_anchor.state_root,
            computed: computed_root,
        });
    }
    let next_history_root = successor_history_root_v2(
        head_history_root,
        expected_sequence,
        batch.batch_digest,
        &batch.new_anchor,
    )?;

    Ok(ValidatedBatch {
        batch,
        next_trie,
        next_history_root,
    })
}

pub(crate) fn apply_deltas_incremental(
    trie: &RadixMerkleTrie,
    deltas: &[EvidenceDelta],
    max_objects: Option<u64>,
) -> Result<RadixMerkleTrie, EpochLedgerError> {
    let mut next = trie.clone();
    let mut touched = BTreeSet::new();
    for delta in deltas {
        if !touched.insert(&delta.object_id) {
            return Err(EpochLedgerError::DuplicateObjectInBatch {
                object_id: delta.object_id.clone(),
            });
        }
        let committed = trie.get(&delta.object_id);
        let committed_generation = committed.map(|rev| rev.generation);
        let follows = match committed_generation {
            Some(generation) => {
                delta.prior_generation == Some(generation)
                    && generation.checked_add(1) == Some(delta.new_generation)
            }
            None => delta.prior_generation.is_none() && delta.new_generation == 1,
        };
        if !follows {
            return Err(EpochLedgerError::GenerationConflict {
                object_id: delta.object_id.clone(),
                committed_generation,
                prior_generation: delta.prior_generation,
                new_generation: delta.new_generation,
            });
        }
        if let Some(existing) = committed
            && delta.plane != existing.plane
        {
            return Err(EpochLedgerError::PlaneConflict {
                object_id: delta.object_id.clone(),
                committed_plane: existing.plane,
                delta_plane: delta.plane,
            });
        }
        let revision = ObjectRevision {
            generation: delta.new_generation,
            family: delta.family.clone(),
            plane: delta.plane,
            payload_digest: delta.payload_digest,
            validity: delta.validity,
        };
        let _ = next.insert(delta.object_id.clone(), revision)?;
    }
    if let Some(limit) = max_objects
        && next.len() > limit
    {
        return Err(EpochLedgerError::ObjectCapacityExhausted {
            max_objects: limit,
            required: next.len(),
        });
    }
    Ok(next)
}

pub(crate) fn delta_order_key(delta: &EvidenceDelta) -> (&str, &str, u64, &str) {
    (
        delta.family.as_str(),
        delta.object_id.as_str(),
        delta.new_generation,
        delta.delta_id.as_str(),
    )
}

pub(crate) fn check_counts(deltas: usize, children: usize) -> Result<(), EpochLedgerError> {
    if deltas > MAX_ORACLE_DELTAS_PER_BATCH {
        return Err(EpochLedgerError::BoundExceeded {
            field: OracleBoundField::Deltas,
            length: deltas,
            maximum: MAX_ORACLE_DELTAS_PER_BATCH,
        });
    }
    if children > MAX_ORACLE_CHILDREN_PER_BATCH {
        return Err(EpochLedgerError::BoundExceeded {
            field: OracleBoundField::Children,
            length: children,
            maximum: MAX_ORACLE_CHILDREN_PER_BATCH,
        });
    }
    Ok(())
}

pub(crate) fn check_texts(
    deltas: &[EvidenceDelta],
    basis: &LedgerAnchor,
    successor: &LedgerAnchor,
) -> Result<(), EpochLedgerError> {
    check_text(OracleBoundField::SiteLineageText, &basis.site_lineage)?;
    check_text(OracleBoundField::SiteLineageText, &successor.site_lineage)?;
    for delta in deltas {
        check_text(OracleBoundField::DeltaIdText, &delta.delta_id)?;
        check_text(OracleBoundField::FamilyText, &delta.family)?;
    }
    Ok(())
}

pub(crate) fn check_deltas(deltas: &[EvidenceDelta]) -> Result<(), EpochLedgerError> {
    for delta in deltas {
        if delta.delta_id.is_empty() || delta.family.is_empty() {
            return Err(EpochLedgerError::Contract(ContractError::InvalidIdentifier));
        }
        if delta.validity.earliest > delta.validity.latest {
            return Err(EpochLedgerError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }
    }
    Ok(())
}

fn check_text(field: OracleBoundField, value: &str) -> Result<(), EpochLedgerError> {
    if value.len() > MAX_ORACLE_TEXT_BYTES {
        return Err(EpochLedgerError::BoundExceeded {
            field,
            length: value.len(),
            maximum: MAX_ORACLE_TEXT_BYTES,
        });
    }
    Ok(())
}

fn check_successor(
    basis: &LedgerAnchor,
    successor: &LedgerAnchor,
    expected_sequence: u64,
) -> Result<(), EpochLedgerError> {
    let field = if successor.site_lineage != basis.site_lineage {
        Some(AnchorField::SiteLineage)
    } else if successor.ledger_epoch != basis.ledger_epoch {
        Some(AnchorField::LedgerEpoch)
    } else if successor.commit_sequence != expected_sequence {
        Some(AnchorField::CommitSequence)
    } else if successor.adapter_registry_epoch != basis.adapter_registry_epoch {
        Some(AnchorField::AdapterRegistryEpoch)
    } else if successor.schema_epoch != basis.schema_epoch {
        Some(AnchorField::SchemaEpoch)
    } else if successor.policy_epoch != basis.policy_epoch {
        Some(AnchorField::PolicyEpoch)
    } else if successor.privacy_epoch != basis.privacy_epoch {
        Some(AnchorField::PrivacyEpoch)
    } else {
        None
    };
    match field {
        Some(field) => Err(EpochLedgerError::InvalidSuccessorAnchor { field }),
        None => Ok(()),
    }
}
