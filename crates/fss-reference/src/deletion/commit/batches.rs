#![forbid(unsafe_code)]
//! Bounded authority publication for one already approved deletion closure.
//!
//! The first batch is the existing deletion record, which denies reads of the entire sealed
//! closure immediately. All tombstone/retraction batches must be durable before any unlink.
//! Small plans retain the original single-batch representation and identities.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{BatchId, ContentDigest, EvidenceDelta, EvidenceDeltaBatch};

use super::{checkpoint, completion_delta, record_deltas};
use crate::deletion::{
    DeletionCompletion, DeletionError, DeletionPlan, STAGE_DELETION_AUTHORITY_BATCH_APPENDED,
};
use crate::{ReferenceDeployment, ReplayCx};

const PREFLIGHT: &str = "deletion:authority_preflight";

pub(super) struct PlannedBatch {
    pub(super) id: BatchId,
    pub(super) deltas: Vec<EvidenceDelta>,
}

fn bound(limit: &'static str) -> DeletionError {
    DeletionError::Bound { limit }
}

fn ordered(deltas: &mut [EvidenceDelta]) {
    deltas.sort_by(|a, b| {
        (a.family.as_str(), a.object_id.as_str(), a.new_generation, a.delta_id.as_str())
            .cmp(&(b.family.as_str(), b.object_id.as_str(), b.new_generation, b.delta_id.as_str()))
    });
}

fn encoded_len(
    plan: &DeletionPlan,
    id: &BatchId,
    deltas: &[EvidenceDelta],
    children: &[ContentDigest],
) -> Result<usize, DeletionError> {
    let mut children = children.to_vec();
    children.sort_unstable();
    children.dedup();
    let mut batch = EvidenceDeltaBatch {
        batch_id: id.clone(),
        basis_anchor: plan.basis_anchor.clone(),
        new_anchor: plan.basis_anchor.clone(),
        deltas: deltas.to_vec(),
        children,
        batch_digest: ContentDigest::sha256(b""),
    };
    batch.batch_digest = batch.computed_digest();
    fss_ledger::encode_batch(&batch)
        .map(|bytes| bytes.len())
        .map_err(|_| DeletionError::RecordMismatch)
}

/// Bisect overlarge groups before any write. Fixed-width ordinal IDs make the partition
/// independent of the current ledger head and the number of previously published parts.
fn fit(
    plan: &DeletionPlan,
    digest: ContentDigest,
    group: &[EvidenceDelta],
    maximum: usize,
    out: &mut Vec<PlannedBatch>,
    cx: &ReplayCx,
) -> Result<(), DeletionError> {
    checkpoint(cx, PREFLIGHT)?;
    let ordinal = u32::try_from(out.len()).map_err(|_| bound("deletion_authority_batches"))?;
    let id = BatchId::parse(format!(
        "{}:part:{ordinal:010}",
        DeletionPlan::record_batch_id(digest)
    ))?;
    if encoded_len(plan, &id, group, &[digest])? <= maximum {
        out.push(PlannedBatch { id, deltas: group.to_vec() });
        return Ok(());
    }
    if group.len() <= 1 {
        return Err(bound("journal_record_max_bytes"));
    }
    let (left, right) = group.split_at(group.len() / 2);
    fit(plan, digest, left, maximum, out, cx)?;
    fit(plan, digest, right, maximum, out, cx)
}

/// Pure planning plus cancellation: validate every indivisible object and journal record before
/// the caller stages even the deletion plan. Actual free-space checks remain the spool owner's;
/// completion may reuse space reclaimed by the deletion, rather than requiring spare space twice.
pub(super) fn build(
    deployment: &ReferenceDeployment,
    plan: &DeletionPlan,
    digest: ContentDigest,
    cx: &ReplayCx,
) -> Result<Vec<PlannedBatch>, DeletionError> {
    checkpoint(cx, PREFLIGHT)?;
    let bytes = plan.canonical_bytes()?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(DeletionError::RecordMismatch);
    }
    let limits = deployment.limits();
    let entries = limits.batch_entries_max;
    // Completion is one delta but carries both the plan and the completion object.
    if entries < 2 {
        return Err(bound("batch_entries_max"));
    }
    let record_max = limits.journal_record_max_bytes as usize;
    let object_max = limits.spool_object_max_bytes.min(
        deployment.publisher().spool().limits().max_object_bytes as u64,
    );
    let completion_bytes = DeletionCompletion::of(plan)?.canonical_bytes()?;
    if bytes.len() as u64 > object_max || completion_bytes.len() as u64 > object_max {
        return Err(bound("spool_object_max_bytes"));
    }
    let completion = ContentDigest::sha256(&completion_bytes);
    let completion_id = BatchId::parse(DeletionPlan::completion_batch_id(digest))?;
    if encoded_len(
        plan,
        &completion_id,
        &[completion_delta(plan, digest, completion)?],
        &[completion, digest],
    )? > record_max {
        return Err(bound("journal_record_max_bytes"));
    }

    let id = BatchId::parse(DeletionPlan::record_batch_id(digest))?;
    let mut deltas = record_deltas(plan, digest)?;
    ordered(&mut deltas);
    if deltas.len() <= entries && encoded_len(plan, &id, &deltas, &[digest])? <= record_max {
        return Ok(vec![PlannedBatch { id, deltas }]);
    }
    let record = deltas.first().ok_or(DeletionError::RecordMismatch)?;
    if record.family != crate::reference_deployment::FAMILY_DELETION_RECORD {
        return Err(DeletionError::RecordMismatch);
    }
    if encoded_len(plan, &id, std::slice::from_ref(record), &[digest])? > record_max {
        return Err(bound("journal_record_max_bytes"));
    }
    let mut out = vec![PlannedBatch { id, deltas: vec![record.clone()] }];
    for group in deltas[1..].chunks(entries) {
        fit(plan, digest, group, record_max, &mut out, cx)?;
    }
    Ok(out)
}

/// Verify the complete existing prefix before appending anything. Neither an unexpected part,
/// a changed payload nor a gap may be mistaken for an idempotent retry. Already committed
/// batches are not submitted to custody verification again: their root witnesses may have been
/// intentionally unlinked by a previous, interrupted application of this very deletion.
pub(super) fn finish(
    deployment: &mut ReferenceDeployment,
    plan: &DeletionPlan,
    digest: ContentDigest,
    cx: &ReplayCx,
) -> Result<(), DeletionError> {
    let batches = build(deployment, plan, digest, cx)?;
    let history: BTreeMap<_, _> = deployment.ledger().batches().iter()
        .map(|batch| (batch.batch_id.as_str(), batch)).collect();
    let mut present = 0_usize;
    let mut missing = false;
    let mut previous = plan.basis_anchor.commit_sequence;
    for (ordinal, expected) in batches.iter().enumerate() {
        checkpoint(cx, PREFLIGHT)?;
        let Some(stored) = history.get(expected.id.as_str()) else {
            missing = true;
            continue;
        };
        if missing
            || stored.deltas != expected.deltas
            || stored.children != [digest]
            || stored.new_anchor.commit_sequence <= previous
            || (ordinal == 0 && stored.basis_anchor != plan.basis_anchor)
        {
            return Err(DeletionError::RecordMismatch);
        }
        previous = stored.new_anchor.commit_sequence;
        present += 1;
    }
    if present == 0 {
        return Err(DeletionError::RecordMismatch);
    }
    let prefix = format!("{}:part:", DeletionPlan::record_batch_id(digest));
    let expected_ids: BTreeSet<_> = batches.iter().map(|batch| batch.id.as_str()).collect();
    for id in history.keys() {
        checkpoint(cx, PREFLIGHT)?;
        if id.starts_with(&prefix) && !expected_ids.contains(*id) {
            return Err(DeletionError::RecordMismatch);
        }
    }
    // Reject a changed already-published transition before extending the prefix, too.
    verify_current(deployment, &batches[..present], cx)?;
    for (ordinal, batch) in batches.iter().enumerate() {
        checkpoint(cx, PREFLIGHT)?;
        if ordinal >= present {
            deployment.append_deletion_batch(
                batch.id.clone(), batch.deltas.clone(), vec![digest], cx,
            )?;
        }
        checkpoint(cx, STAGE_DELETION_AUTHORITY_BATCH_APPENDED)?;
    }
    // This is the unlink barrier: all exact authority transitions must still be current.
    verify_current(deployment, &batches, cx)
}

fn verify_current(
    deployment: &ReferenceDeployment,
    batches: &[PlannedBatch],
    cx: &ReplayCx,
) -> Result<(), DeletionError> {
    for batch in batches {
        for delta in &batch.deltas {
            checkpoint(cx, PREFLIGHT)?;
            let current = deployment.ledger().current().objects.get(&delta.object_id)
                .ok_or(DeletionError::RecordMismatch)?;
            if current.generation != delta.new_generation
                || current.family != delta.family
                || current.plane != delta.plane
                || current.validity != delta.validity
                || current.payload_digest != delta.payload_digest
            {
                return Err(DeletionError::RecordMismatch);
            }
        }
    }
    Ok(())
}
