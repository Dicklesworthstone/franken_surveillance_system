#![forbid(unsafe_code)]
//! The same canonical review subject and receipt without acquiring a publication owner.

use super::*;
use crate::ingest::FileIngestError;
use crate::retained_source::verify_event_lineage;

pub(super) fn retained_error(error: FileIngestError) -> ReviewError {
    match error {
        FileIngestError::Reference(error) => error.into(),
        FileIngestError::Spool(error) => error.into(),
        FileIngestError::CancellationRequested { .. } => ReviewError::Cancelled,
        _ => ReviewError::CustodyMismatch,
    }
}

pub(super) fn current_revision(
    deployment: &dyn RetainedSource,
    event_id: &EventId,
    revisions: &[Revision],
    cx: &ReplayCx,
) -> Result<(EventHypothesis, ReferenceEventReceipt), ReviewError> {
    checkpoint(cx, "event_review:current")?;
    let last = revisions.last().ok_or(ReviewError::StaleRevision)?;
    let object = fss_core::ObjectId::parse(format!("object:event:{}", event_id.as_str()))?;
    let current = deployment
        .ledger()
        .current()
        .objects
        .get(&object)
        .ok_or(ReviewError::StaleRevision)?;
    if current.family != FAMILY_EVENT_REVISION
        || current.generation != last.event.revision
        || current.payload_digest != last.root
        || last.event.event_id != *event_id
    {
        return Err(ReviewError::CustodyMismatch);
    }
    let chain: Vec<_> = revisions
        .iter()
        .map(|revision| revision.event.clone())
        .collect();
    let publications = verify_event_lineage(deployment, &chain, MAX_REVIEW_HISTORY_BYTES)
        .map_err(retained_error)?;
    if publications.len() != revisions.len()
        || publications
            .iter()
            .zip(revisions)
            .any(|((root, sequence), revision)| {
                *root != revision.root || *sequence != revision.anchor.commit_sequence
            })
    {
        return Err(ReviewError::CustodyMismatch);
    }
    deployment.verify_read_head().map_err(retained_error)?;
    checkpoint(cx, "event_review:current_checked")?;
    let receipt = ReferenceEventReceipt {
        event_root: last.root,
        event_object_digest: ContentDigest::sha256(&last.event.canonical_bytes()),
        event_revision_digest: last.event.revision_digest(),
        authority_anchor: last.anchor.clone(),
        lineage_tamper_status: fss_core::event::compute_sensor_tamper_status(chain.iter(), None),
        prior_revision_encodings: chain[..chain.len() - 1]
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect(),
    };
    Ok((last.event.clone(), receipt))
}
