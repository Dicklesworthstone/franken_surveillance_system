#![forbid(unsafe_code)]
//! Immutable model-run metadata discovery, without tensor or original media payload reads.

use super::*;
use crate::ingest::recorded_decode::{ComponentInterpretation, retained_frame_metadata};

/// Verified receipt/publication and source-metadata linkage for one completed scalar run.
/// The model, normalized input, output tensors and source pixels have not been read or
/// validated. This metadata cannot substitute for [`RecordedInference::open`] or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedInferenceMetadata {
    /// Semantic lookup key accepted by the native inference reader, not a retained blob.
    pub run_identity: ContentDigest,
    /// Content address of the actual canonical execution receipt.
    pub record_digest: ContentDigest,
    /// Root of the exact native model-run publication.
    pub publication_root: ContentDigest,
    /// Existing native publication slot, including the semantic run key.
    pub publication_slot: SlotName,
    /// RecordedModel digest declared by the original receipt; payload verification is separate.
    pub model_digest: ContentDigest,
    /// Original retained executor source profile, including historical profiles.
    pub executor_profile_digest: ContentDigest,
    /// Verified decoded-frame metadata root, not evidence that pixels are retrievable.
    pub frame_root: ContentDigest,
    /// Original import identity, bound through the native frame and import metadata owners.
    pub import_identity: ContentDigest,
    /// Exact source segment required by the native inference reader.
    pub segment_index: u64,
    /// Original explicit luma interpretation required by the native inference reader.
    pub interpretation: ComponentInterpretation,
    /// Original source capsule's declared interval, with no new clock claim.
    pub validity: CaptureInterval,
    /// Exact model-run completion anchor, rather than the current deployment head.
    pub authority_anchor: LedgerAnchor,
}

impl RecordedInferenceMetadata {
    /// Verify only bounded metadata using one caller-owned retained source and allowance.
    /// Exact frame completion/import/capsule linkage and current deletion restrictions are
    /// checked. No original media, pixels, model bytes or input/output tensors are hydrated.
    /// Immutable callers revalidate the same owner before releasing their complete response.
    pub fn read(
        source: &dyn RetainedSource,
        record_digest: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_inference:metadata")?;
        let bytes = source.read_object_bounded(record_digest, 4096)?;
        let receipt = Receipt::decode(&bytes, record_digest)?;
        let target = batch_id(receipt.identity())?;
        let batch = source
            .ledger()
            .batches()
            .iter()
            .find(|batch| batch.batch_id == target)
            .ok_or(ModelRunError::Unavailable)?;
        let frame = retained_frame_metadata(
            source,
            receipt.frame_receipt,
            receipt.frame,
            &receipt.source_anchor,
            cx,
        )?;
        let manifest = receipt.manifest()?;
        let expected = receipt.delta_at(frame.capsule().capture, manifest.root())?;
        let mut children = manifest.children().to_vec();
        children.push(manifest.root());
        children.sort_unstable();
        children.dedup();
        if batch.deltas.as_slice() != [expected]
            || batch.children != children
            || source.read_object_bounded(manifest.root(), manifest.canonical_bytes().len())?
                != manifest.canonical_bytes()
        {
            return Err(ModelRunError::Mismatch);
        }
        let publication_slot = slot(receipt.identity())?;
        source.check_publication(
            &publication_slot,
            manifest.root(),
            manifest.children().len(),
        )?;
        for digest in manifest.children() {
            source.check_object_available(*digest)?;
        }
        checkpoint(cx, "recorded_inference:metadata_complete")?;
        source.verify_read_head()?;
        Ok(Self {
            run_identity: receipt.identity(),
            record_digest,
            publication_root: manifest.root(),
            publication_slot,
            model_digest: receipt.model,
            executor_profile_digest: receipt.runtime,
            frame_root: receipt.frame,
            import_identity: frame.import_identity(),
            segment_index: frame.segment_index(),
            interpretation: frame.codec().interpretation,
            validity: frame.capsule().capture,
            authority_anchor: batch.new_anchor.clone(),
        })
    }
}
