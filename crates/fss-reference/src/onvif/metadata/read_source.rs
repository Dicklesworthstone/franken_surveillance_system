#![forbid(unsafe_code)]
//! Frozen ONVIF source reconstruction through a real read-only flat-closure capability.
//!
//! The deployment context supplies verified current batches and committed deletion proofs.
//! This module opens no publisher, acquires no writer lock, scans no namespace, and creates
//! no fallback source. Root records, every direct child and local deletion markers are checked
//! by the caller's one nonrenewing reader. A semantic refusal aborts the whole caller request.
//! Completing one root is a bounded observation, never an atomic filesystem snapshot or lease.

use std::cell::RefCell;
use std::fmt;

use fss_core::{CanonicalEncode, ContentDigest, DigestAlgorithm, EvidenceDeltaBatch, LedgerAnchor};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_closure::{PinnedClosureError, PinnedClosureReader};
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;

use super::tracks::{Source, TrackSourcePin};
use super::{MetadataError, SourceBinding, rtp};
use crate::deletion::DeletionIndex;

/// One complete frozen source, with the exact XML available for additive lifecycle parsing.
/// RTP originals remain in their existing retained document owners. No raw source is rendered.
pub(crate) struct LoadedSource {
    pub(crate) source: Source,
    pub(crate) raw_xml: Option<Vec<u8>>,
    /// Every selected root/child, including empty or rejected documents and native provenance.
    pub(crate) reference_digests: Vec<ContentDigest>,
}

impl fmt::Debug for LoadedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, identity, root) = match &self.source {
            Source::Xml(source) => ("xml", source.identity(), source.publication_root()),
            Source::Rtp(source) => ("rtp", source.identity(), source.publication_root()),
        };
        f.debug_struct("LoadedSource")
            .field("kind", &kind)
            .field("identity", &identity)
            .field("root", &root)
            .field("raw_xml", &self.raw_xml.as_ref().map(|_| "[redacted]"))
            .field("reference_count", &self.reference_digests.len())
            .finish()
    }
}

fn pinned_error(error: PinnedClosureError) -> MetadataError {
    match error {
        PinnedClosureError::Observation(PinnedMetadataError::Audit(
            CustodyAuditError::Cancelled,
        )) => MetadataError::Cancelled,
        PinnedClosureError::Observation(PinnedMetadataError::Audit(
            CustodyAuditError::Limit(_) | CustodyAuditError::InvalidRequest,
        )) => MetadataError::Limit,
        _ => MetadataError::Custody,
    }
}

fn check_deleted(
    deletions: &DeletionIndex,
    pin: TrackSourcePin,
    slot: &SlotName,
    digests: impl IntoIterator<Item = ContentDigest>,
) -> Result<(), MetadataError> {
    super::check_deleted_for_unit(
        deletions,
        pin.identity(),
        &format!("slot:{}", slot.as_str()),
        digests,
    )
}

fn publication(
    batches: &[EvidenceDeltaBatch],
    slot: &SlotName,
    manifest: &ObjectManifest,
    binding: &SourceBinding,
    checkpoint: &dyn Fn() -> Result<(), MetadataError>,
) -> Result<LedgerAnchor, MetadataError> {
    super::check_publication_in_batches(
        batches,
        slot,
        manifest,
        binding,
        || Ok(manifest.children().to_vec()),
        checkpoint,
    )
}

fn finish_root(
    reader: &mut PinnedClosureReader<'_>,
    checkpoint: &dyn Fn() -> Result<(), MetadataError>,
) -> Result<(), MetadataError> {
    // Keep the original semantic refusal rather than replacing it with generic cancellation.
    // This guard does not need Sync; the reader independently gates every filesystem call.
    let refusal = RefCell::new(None);
    let finished = reader.finish_root_with(&|| {
        if refusal.borrow().is_some() {
            return true;
        }
        match checkpoint() {
            Ok(()) => false,
            Err(error) => {
                *refusal.borrow_mut() = Some(error);
                true
            }
        }
    });
    if let Some(error) = refusal.into_inner() {
        return Err(error);
    }
    finished.map_err(pinned_error)?;
    Ok(())
}

/// Reconstruct one exact source through its unchanged frozen verifier and current authority.
/// The caller owns complete pre/post history verification, aggregate projection work and final
/// reader finalization; this function never refills those allowances or releases a partial root.
pub(crate) fn read_source(
    reader: &mut PinnedClosureReader<'_>,
    site: &str,
    batches: &[EvidenceDeltaBatch],
    deletions: &DeletionIndex,
    pin: TrackSourcePin,
    checkpoint: &dyn Fn() -> Result<(), MetadataError>,
) -> Result<LoadedSource, MetadataError> {
    for digest in [pin.identity(), pin.root()] {
        if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
            return Err(MetadataError::InvalidBinding);
        }
    }
    if reader.limits().max_object_bytes > rtp::MAX_INPUT_BYTES
        || batches.len() > super::MAX_HISTORY_BATCHES
    {
        return Err(MetadataError::Limit);
    }
    // Bound the complete supplied history, including batches after publication.
    batches.iter().try_fold(0_usize, |count, batch| {
        count
            .checked_add(batch.deltas.len())
            .filter(|count| *count <= super::MAX_HISTORY_DELTAS)
            .ok_or(MetadataError::Limit)
    })?;
    let slot = match pin {
        TrackSourcePin::Xml { identity, .. } => super::slot(identity)?,
        TrackSourcePin::Rtp { identity, .. } => rtp::slot(identity)?,
    };
    check_deleted(deletions, pin, &slot, [pin.identity(), pin.root()])?;
    checkpoint()?;
    let manifest = reader.manifest(&slot, pin.root()).map_err(pinned_error)?;
    checkpoint()?;
    let manifest_limit = match pin {
        TrackSourcePin::Xml { .. } => super::MAX_RECIPE_BYTES,
        TrackSourcePin::Rtp { .. } => rtp::MAX_MANIFEST_BYTES,
    };
    if manifest.kind() != slot.as_str()
        || manifest.metadata_digest().is_some()
        || !manifest.children().contains(&pin.identity())
        || manifest.canonical_bytes().len() > manifest_limit
    {
        return Err(MetadataError::Custody);
    }
    check_deleted(
        deletions,
        pin,
        &slot,
        std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
    )?;
    let mut read = |digest, maximum| {
        checkpoint()?;
        check_deleted(deletions, pin, &slot, [digest])?;
        let bytes = reader
            .child(&manifest, digest, maximum)
            .map_err(pinned_error)?;
        checkpoint()?;
        Ok(bytes)
    };
    let check_manifest = |expected: &ObjectManifest| {
        if expected != &manifest {
            Err(MetadataError::Custody)
        } else {
            Ok(())
        }
    };
    let (source, raw_xml) = match pin {
        TrackSourcePin::Xml { identity, .. } => {
            let reconstructed = super::reconstruct_xml(
                identity,
                site,
                &mut read,
                |_| checkpoint(),
                check_manifest,
            )?;
            let anchor = publication(
                batches,
                &slot,
                reconstructed.manifest(),
                reconstructed.binding(),
                checkpoint,
            )?;
            let (source, xml) = reconstructed.finish(anchor);
            (Source::Xml(source), Some(xml))
        }
        TrackSourcePin::Rtp { identity, .. } => {
            let reconstructed = rtp::reconstruct_rtp(
                identity,
                site,
                &mut read,
                |_| checkpoint(),
                |digests| check_deleted(deletions, pin, &slot, digests.iter().copied()),
                check_manifest,
            )?;
            let anchor = publication(
                batches,
                &slot,
                reconstructed.manifest(),
                reconstructed.binding(),
                checkpoint,
            )?;
            (Source::Rtp(reconstructed.finish(anchor)), None)
        }
    };
    let mut reference_digests: Vec<_> = std::iter::once(manifest.root())
        .chain(manifest.children().iter().copied())
        .collect();
    reference_digests.sort_unstable();
    reference_digests.dedup();
    checkpoint()?;
    finish_root(reader, checkpoint)?;
    Ok(LoadedSource {
        source,
        raw_xml,
        reference_digests,
    })
}

#[cfg(test)]
#[path = "read_source/tests.rs"]
mod tests;
