#![forbid(unsafe_code)]
//! Read-only retry admission. An idempotency key is not permission to replace evidence.
//!
//! The import identity predates capture hints and receive time. Consequently, an unchanged
//! identity alone cannot establish that a retry describes the committed capsule history.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{BatchId, ContentDigest, EvidenceDelta, EvidenceDeltaBatch};

use super::{FileImportManifest, FileIngestError, PlannedBatch};
use crate::ingest::retained::{MAX_RETAINED_PAYLOAD_BYTES, RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

const STAGE: &str = "file_adapter:retry_preflight";

fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE)
        .map_err(|_| FileIngestError::CancellationRequested { stage: STAGE })
}

fn conflict(batch_id: &BatchId, detail: &str) -> FileIngestError {
    FileIngestError::ImportPlanConflict {
        batch_id: batch_id.clone(),
        detail: detail.to_owned(),
    }
}

/// Compare the complete payload, not anchors that necessarily differ on a later retry.
/// The deployment sorts deltas before appending; compare a sorted multiset so that this check
/// neither depends on its presentation order nor silently collapses duplicate entries.
fn same_payload(stored: &EvidenceDeltaBatch, planned: &PlannedBatch) -> bool {
    fn ordered(deltas: &[EvidenceDelta]) -> Vec<&EvidenceDelta> {
        let mut out: Vec<_> = deltas.iter().collect();
        out.sort_by(|left, right| left.delta_id.cmp(&right.delta_id));
        out
    }
    let mut children = planned.children.clone();
    children.sort_unstable();
    children.dedup();
    ordered(&stored.deltas) == ordered(&planned.deltas) && stored.children == children
}

/// Validate every already-committed capsule batch before the caller stages any new objects.
/// A complete retry additionally reopens the retained authority and verifies its byte custody.
/// No staging, journal append, root publication, repair, or authority mutation occurs here.
pub(crate) fn preflight(
    deployment: &ReferenceDeployment,
    planned: &[PlannedBatch],
    manifest_batch_id: &BatchId,
    import_identity: ContentDigest,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<Option<RetainedFileImport>, FileIngestError> {
    checkpoint(cx)?;
    let history: BTreeMap<&str, &EvidenceDeltaBatch> = deployment
        .ledger()
        .batches()
        .iter()
        .map(|batch| (batch.batch_id.as_str(), batch))
        .collect();
    let completion = history.get(manifest_batch_id.as_str()).copied();
    let mut missing = false;
    let mut previous_sequence = None;
    let mut custody = BTreeSet::new();

    for batch in planned {
        checkpoint(cx)?;
        let Some(stored) = history.get(batch.batch_id.as_str()).copied() else {
            if completion.is_some() {
                return Err(conflict(
                    &batch.batch_id,
                    "completed import is missing a planned capsule batch",
                ));
            }
            missing = true;
            continue;
        };
        if missing
            || previous_sequence
                .is_some_and(|sequence| stored.new_anchor.commit_sequence <= sequence)
            || completion.is_some_and(|complete| {
                stored.new_anchor.commit_sequence >= complete.new_anchor.commit_sequence
            })
        {
            return Err(conflict(
                &batch.batch_id,
                "committed capsule batches are not an ordered prefix of the import plan",
            ));
        }
        if !same_payload(stored, batch) {
            return Err(conflict(
                &batch.batch_id,
                "retry changes committed capsule evidence, capture timing, or custody",
            ));
        }
        previous_sequence = Some(stored.new_anchor.commit_sequence);
        custody.extend(stored.children.iter().copied());
    }

    // Refuse an old, longer capsule partition rather than silently leaving its tail out of a
    // newly reconstructed receipt. Match canonical capsule-batch suffixes, not unrelated IDs.
    let planned_ids: BTreeSet<_> = planned
        .iter()
        .map(|batch| batch.batch_id.as_str())
        .collect();
    let prefix = manifest_batch_id
        .as_str()
        .strip_suffix("manifest")
        .ok_or_else(|| conflict(manifest_batch_id, "invalid completing batch identity"))?;
    for stored in history.values() {
        checkpoint(cx)?;
        let is_capsule_batch = stored
            .batch_id
            .as_str()
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.strip_prefix('c'))
            .is_some_and(|index| {
                !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
            });
        if is_capsule_batch && !planned_ids.contains(stored.batch_id.as_str()) {
            return Err(conflict(
                &stored.batch_id,
                "committed capsule batch is absent from the retry plan",
            ));
        }
    }

    let retained = if completion.is_some() {
        // A completing batch without its retained root is damage, not an incomplete import
        // that may silently republish or restage evidence during an idempotent retry.
        let limits = RetainedReadLimits {
            max_source_bytes: manifest.input_bytes,
            max_chunk_bytes: manifest.chunk_bytes,
            max_segment_bytes: MAX_RETAINED_PAYLOAD_BYTES,
        };
        let retained = RetainedFileImport::open(deployment, import_identity, limits, cx)?;
        if retained.manifest_digest() != manifest.canonical_digest()
            || retained.manifest() != manifest
        {
            return Err(conflict(
                manifest_batch_id,
                "retry manifest differs from the committed import manifest",
            ));
        }
        custody.insert(retained.import_root());
        custody.insert(retained.manifest_digest());
        Some(retained)
    } else {
        None
    };

    if previous_sequence.is_some() {
        // The first committed capsule batch binds the custody manifest. Re-read each unique
        // source chunk as well as committed capsule payloads: fresh input bytes must not hide
        // loss or corruption of the retained copy. At most one object is held at a time.
        custody.extend(manifest.ordered_chunks.iter().copied());
        for digest in custody {
            checkpoint(cx)?;
            let _verified_bytes = deployment.publisher().spool().read(digest)?;
        }
    }
    checkpoint(cx)?;
    Ok(retained)
}
