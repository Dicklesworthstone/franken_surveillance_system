#![forbid(unsafe_code)]
//! Reconstruct a file publication plan from retained part manifests and supplied file metadata.
//!
//! The supplied metadata is untrusted until its exact canonical bytes match the durable,
//! ledgered aggregate. No original media path, transient payload list or remembered part
//! boundaries are needed. This verifies publication only; it does not waive the legacy
//! retained-reader requirement for a final import-completion batch.

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest};
use fss_publication::{LocalPublicationState, SlotName};

use super::file_adapter::{FileImportManifest, FileIngestError};
use super::file_publication::{
    FilePublicationPlan, MAX_FILE_PUBLICATION_PARTS, MAX_FILE_PUBLICATION_PAYLOADS,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Checkpoint before reading the aggregate and before each retained part manifest.
pub const STAGE_FILE_PART_RECOVER: &str = "file_parts:recover";

fn invalid(detail: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("file publication recovery: {detail}"),
    }
}

fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE_FILE_PART_RECOVER)
        .map_err(|_| FileIngestError::CancellationRequested {
            stage: STAGE_FILE_PART_RECOVER,
        })
}

/// Recovers and verifies an exact publication plan without the original source or in-memory plan.
///
/// `metadata` may come from a retained receipt or a separately decoded manifest; it is checked
/// against the aggregate's actual canonical bytes, not trusted as authority. Every part must
/// be in the exact import namespace and ordinal, durable, ledgered, nonempty and disjoint.
/// The reconstructed plan is deterministic and can be used for an idempotent publication retry.
/// Missing, unledgered or retracted roots are errors, never silently healed by this read.
pub fn recover_file_publication(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
    metadata: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<FilePublicationPlan, FileIngestError> {
    checkpoint(cx)?;
    super::retained::refuse_deleted(deployment, import_identity)?;
    if metadata.part_roots.len() > MAX_FILE_PUBLICATION_PARTS {
        return Err(invalid("part count exceeds the reconstruction bound"));
    }
    // Use the same slot grammar as the writer, without trusting any caller-supplied path.
    let empty = FilePublicationPlan::new(import_identity, [], 1)?;
    let root = read_manifest(deployment, empty.slot(), None, cx)?;
    let payloads;
    let child_limit;
    if metadata.part_roots.is_empty() {
        let metadata_digest = root
            .metadata_digest()
            .ok_or_else(|| invalid("aggregate has no typed file metadata"))?;
        payloads = root
            .children()
            .iter()
            .copied()
            .filter(|digest| *digest != metadata_digest)
            .collect();
        child_limit = root.children().len().max(1);
    } else {
        let metadata_digest = root
            .metadata_digest()
            .ok_or_else(|| invalid("aggregate has no typed file metadata"))?;
        if root.children() != [metadata_digest].as_slice() {
            return Err(invalid(
                "partitioned aggregate must contain only its metadata",
            ));
        }
        let mut children = Vec::new();
        let mut bound = None;
        for (ordinal, digest) in metadata.part_roots.iter().copied().enumerate() {
            checkpoint(cx)?;
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(invalid("part root uses an unsupported digest algorithm"));
            }
            let slot = SlotName::parse(&format!("{}-p{ordinal:06}", empty.slot()))
                .map_err(|_| invalid("invalid part slot"))?;
            let part = read_manifest(deployment, &slot, Some(digest), cx)?;
            let part_children = part.children();
            if part.metadata_digest().is_some() || part_children.is_empty() {
                return Err(invalid("part must be a nonempty opaque-payload manifest"));
            }
            let expected = *bound.get_or_insert(part_children.len());
            if part_children.len() > expected
                || (ordinal + 1 < metadata.part_roots.len() && part_children.len() != expected)
            {
                return Err(invalid(
                    "part sizes do not follow the canonical partition boundary",
                ));
            }
            if children
                .last()
                .zip(part_children.first())
                .is_some_and(|(last, first)| last >= first)
            {
                return Err(invalid(
                    "part payloads are overlapping or out of canonical order",
                ));
            }
            let total = children
                .len()
                .checked_add(part_children.len())
                .ok_or_else(|| invalid("payload count overflow"))?;
            if total > MAX_FILE_PUBLICATION_PAYLOADS {
                return Err(invalid("payload closure exceeds the reconstruction bound"));
            }
            children.extend_from_slice(part_children);
        }
        payloads = children;
        child_limit = bound.ok_or_else(|| invalid("partitioned aggregate has no parts"))?;
    }
    let plan = FilePublicationPlan::new(import_identity, payloads, child_limit)?;
    // This checks metadata sizes before canonical encoding, exact part roots, and source-chunk
    // membership. It also rejects omitted parts even when the remaining parts are individually
    // valid: the final root must still be the exact original aggregate.
    if plan.root_manifest(metadata)? != root {
        return Err(invalid(
            "metadata or reconstructed closure differs from the aggregate",
        ));
    }
    plan.verify(deployment, metadata, cx)?;
    checkpoint(cx)?;
    Ok(plan)
}

fn read_manifest(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    expected: Option<ContentDigest>,
    cx: &ReplayCx,
) -> Result<ObjectManifest, FileIngestError> {
    checkpoint(cx)?;
    let publisher = deployment.publisher();
    let visible = publisher
        .root(slot)
        .ok_or_else(|| invalid("publication root is absent"))?;
    if visible.state != LocalPublicationState::Durable
        || visible.child_count > MAX_MANIFEST_CHILDREN
        || expected.is_some_and(|digest| visible.root != digest)
    {
        return Err(invalid(
            "publication root is not the exact bounded durable root",
        ));
    }
    let bytes = publisher.spool().read(visible.root)?;
    let manifest = ObjectManifest::from_canonical_bytes(&bytes)?;
    if manifest.root() != visible.root
        || manifest.kind() != slot.as_str()
        || manifest.children().len() != visible.child_count
    {
        return Err(invalid("manifest differs from its publication record"));
    }
    Ok(manifest)
}
