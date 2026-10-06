#![forbid(unsafe_code)]
//! Recover deletion authority as an exact ordered prefix of the sealed plan.
//!
//! A committed header denies reads immediately, even with no transition parts yet. Completion
//! additionally requires every exact tombstone/retraction and the exact completion payload.
//! This is a metadata-only check: intentionally deleted source bytes are never requested.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EvidenceDelta, EvidenceDeltaBatch, Plane};
use fss_publication::ROOT_RETRACTION_FAMILY;

use super::{DeletionEntry, DeletionError};
use crate::deletion::{DeletionCompletion, DeletionPlan};
use crate::reference_deployment::{
    FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD, FAMILY_DELETION_TOMBSTONE,
};

fn owned_family(family: &str) -> bool {
    matches!(
        family,
        FAMILY_DELETION_RECORD
            | FAMILY_DELETION_TOMBSTONE
            | FAMILY_DELETION_COMPLETION
            | ROOT_RETRACTION_FAMILY
    )
}

pub(super) fn candidate(batch: &EvidenceDeltaBatch) -> bool {
    batch.batch_id.as_str().starts_with("batch:deletion:")
        || batch.deltas.iter().any(|delta| owned_family(&delta.family))
}

struct Progress {
    entry: DeletionEntry,
    expected: Vec<EvidenceDelta>,
    consumed: usize,
    next_part: usize,
    last_sequence: u64,
}

fn mismatch<T>() -> Result<T, DeletionError> {
    Err(DeletionError::RecordMismatch)
}

fn sequence(batch: &EvidenceDeltaBatch, last: u64) -> Result<(), DeletionError> {
    if batch.basis_anchor.commit_sequence < last
        || batch.basis_anchor.commit_sequence.checked_add(1)
            != Some(batch.new_anchor.commit_sequence)
        || batch.basis_anchor.site_lineage != batch.new_anchor.site_lineage
        || batch.computed_digest() != batch.batch_digest
    {
        return mismatch();
    }
    Ok(())
}

impl Progress {
    fn new(plan: DeletionPlan, digest: ContentDigest) -> Result<Self, DeletionError> {
        if !plan.blockers.is_empty() {
            return mismatch();
        }
        let mut expected = crate::deletion::commit::record_deltas(&plan, digest)?;
        expected.sort_by(|a, b| {
            (
                a.family.as_str(),
                a.object_id.as_str(),
                a.new_generation,
                a.delta_id.as_str(),
            )
                .cmp(&(
                    b.family.as_str(),
                    b.object_id.as_str(),
                    b.new_generation,
                    b.delta_id.as_str(),
                ))
        });
        let mut objects = BTreeSet::new();
        if expected
            .iter()
            .any(|delta| !objects.insert(delta.object_id.clone()))
        {
            return mismatch();
        }
        let last_sequence = plan.basis_anchor.commit_sequence;
        Ok(Self {
            entry: DeletionEntry {
                plan_digest: digest,
                plan,
                completion_digest: None,
            },
            expected,
            consumed: 0,
            next_part: 1,
            last_sequence,
        })
    }

    fn consume(&mut self, batch: &EvidenceDeltaBatch) -> Result<(), DeletionError> {
        sequence(batch, self.last_sequence)?;
        let end = self
            .consumed
            .checked_add(batch.deltas.len())
            .ok_or(DeletionError::RecordMismatch)?;
        if self.entry.completion_digest.is_some()
            || batch.deltas.is_empty()
            || batch.children != [self.entry.plan_digest]
            || batch.basis_anchor.site_lineage != self.entry.plan.site_lineage
            || self.expected.get(self.consumed..end) != Some(batch.deltas.as_slice())
        {
            return mismatch();
        }
        self.consumed = end;
        self.last_sequence = batch.new_anchor.commit_sequence;
        Ok(())
    }

    fn complete(&mut self, batch: &EvidenceDeltaBatch) -> Result<ContentDigest, DeletionError> {
        sequence(batch, self.last_sequence)?;
        let [delta] = batch.deltas.as_slice() else {
            return mismatch();
        };
        let digest = self.entry.plan_digest;
        let plan = &self.entry.plan;
        let mut children = vec![digest, delta.payload_digest];
        children.sort_unstable();
        children.dedup();
        if self.entry.completion_digest.is_some()
            || self.consumed != self.expected.len()
            || batch.batch_id.as_str() != DeletionPlan::completion_batch_id(digest)
            || batch.basis_anchor.site_lineage != plan.site_lineage
            || batch.children != children
            || delta.family != FAMILY_DELETION_COMPLETION
            || delta.delta_id != format!("delta:deletion-complete:{}", digest.to_text())
            || delta.object_id.as_str() != plan.record_object_id_of(digest)
            || delta.prior_generation != Some(1)
            || delta.new_generation != 2
            || delta.plane != Plane::Authority
            || delta.validity != plan.validity
            || delta.witness_digest != Some(digest)
            || delta.operation_id.is_some()
        {
            return mismatch();
        }
        Ok(delta.payload_digest)
    }
}

pub(super) fn read<E: From<DeletionError>>(
    batches: &[EvidenceDeltaBatch],
    mut read: impl FnMut(ContentDigest) -> Result<Vec<u8>, E>,
) -> Result<Vec<DeletionEntry>, E> {
    let mut states: Vec<Progress> = Vec::new();
    let mut plans: BTreeMap<ContentDigest, usize> = BTreeMap::new();
    let mut records: BTreeMap<String, usize> = BTreeMap::new();
    for batch in batches {
        if !candidate(batch) {
            continue;
        }
        if let Some(marker) = batch
            .deltas
            .iter()
            .find(|delta| delta.family == FAMILY_DELETION_RECORD)
        {
            let digest = marker.payload_digest;
            let bytes = read(digest)?;
            let plan = DeletionPlan::decode(&bytes, digest)?;
            let object = plan.record_object_id_of(digest);
            if plans.contains_key(&digest)
                || records.contains_key(&object)
                || batch.batch_id.as_str() != DeletionPlan::record_batch_id(digest)
                || batch.basis_anchor != plan.basis_anchor
                || plan.site_lineage != plan.basis_anchor.site_lineage
            {
                return Err(DeletionError::RecordMismatch.into());
            }
            let mut progress = Progress::new(plan, digest)?;
            // Legacy: every transition in the header. Multipart: a header-only first batch.
            if batch.deltas.len() != 1 && batch.deltas.len() != progress.expected.len() {
                return Err(DeletionError::RecordMismatch.into());
            }
            progress.consume(batch)?;
            plans.insert(digest, states.len());
            records.insert(object, states.len());
            states.push(progress);
        } else if let Some(completion) = batch
            .deltas
            .iter()
            .find(|delta| delta.family == FAMILY_DELETION_COMPLETION)
        {
            let position = records
                .get(completion.object_id.as_str())
                .ok_or(DeletionError::RecordMismatch)?;
            let progress = &mut states[*position];
            let digest = progress.complete(batch)?;
            let bytes = read(digest)?;
            let completion = DeletionCompletion::decode(&bytes, digest)?;
            if completion != DeletionCompletion::of(&progress.entry.plan)? {
                return Err(DeletionError::RecordMismatch.into());
            }
            progress.entry.completion_digest = Some(digest);
            progress.last_sequence = batch.new_anchor.commit_sequence;
        } else {
            let first = batch.deltas.first().ok_or(DeletionError::RecordMismatch)?;
            let position = plans
                .get(&first.payload_digest)
                .ok_or(DeletionError::RecordMismatch)?;
            let progress = &mut states[*position];
            let expected_id = format!(
                "{}:part:{:010}",
                DeletionPlan::record_batch_id(progress.entry.plan_digest),
                progress.next_part
            );
            if batch.batch_id.as_str() != expected_id {
                return Err(DeletionError::RecordMismatch.into());
            }
            progress.consume(batch)?;
            progress.next_part = progress
                .next_part
                .checked_add(1)
                .ok_or(DeletionError::RecordMismatch)?;
        }
    }
    Ok(states.into_iter().map(|state| state.entry).collect())
}
