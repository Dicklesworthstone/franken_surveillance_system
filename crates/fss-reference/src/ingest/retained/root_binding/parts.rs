#![forbid(unsafe_code)]
//! Resolve typed part roots without hydrating their media payloads.

use super::{FileImportManifest, FileIngestError, STAGE, checkpoint, invalid};
use crate::ingest::file_publication::{
    FilePublicationPlan, MAX_FILE_PUBLICATION_PARTS, MAX_FILE_PUBLICATION_PAYLOADS,
};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName};
use std::collections::BTreeSet;

/// Returns the exact payload union and the first publication sequence. Source consumers still
/// verify each requested chunk. The aggregate's native closure deliberately excludes parts.
pub(super) fn resolve(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    root: &ObjectManifest,
    metadata: &FileImportManifest,
    aggregate_sequence: u64,
    cx: &ReplayCx,
) -> Result<(BTreeSet<ContentDigest>, u64), FileIngestError> {
    if metadata.part_roots.len() > MAX_FILE_PUBLICATION_PARTS {
        return Err(invalid("part count exceeds the reconstruction bound"));
    }
    let metadata_digest = metadata.canonical_digest();
    if root.children() != [metadata_digest].as_slice() {
        return Err(invalid(
            "partitioned aggregate must contain only its metadata",
        ));
    }
    let identity_text = slot
        .as_str()
        .strip_prefix("fi-")
        .ok_or_else(|| invalid("invalid import slot identity"))?;
    let mut identity_bytes = [0_u8; 32];
    if identity_text.len() != 64 {
        return Err(invalid("invalid import identity length"));
    }
    for (index, pair) in identity_text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        identity_bytes[index] =
            (digit(pair[0]).ok_or_else(|| invalid("invalid import identity"))? << 4)
                | digit(pair[1]).ok_or_else(|| invalid("invalid import identity"))?;
    }
    let identity = ContentDigest::new(DigestAlgorithm::Sha256, identity_bytes);
    let mut payloads = Vec::new();
    let mut bound = None;
    let mut first_sequence = aggregate_sequence;
    let mut previous_sequence = None;
    let mut roots = BTreeSet::new();
    for (ordinal, digest) in metadata.part_roots.iter().copied().enumerate() {
        checkpoint(cx, STAGE)?;
        if digest.algorithm() != DigestAlgorithm::Sha256 || !roots.insert(digest) {
            return Err(invalid(
                "part roots are duplicated or use an unsupported digest",
            ));
        }
        let part_slot = SlotName::parse(&format!("{slot}-p{ordinal:06}"))
            .map_err(|_| invalid("invalid part slot"))?;
        let publisher = deployment.publisher();
        let visible = publisher
            .root(&part_slot)
            .ok_or_else(|| invalid("retained import part is absent"))?;
        if visible.state != LocalPublicationState::Durable || visible.root != digest {
            return Err(invalid(
                "retained import part is not the exact durable root",
            ));
        }
        let part = ObjectManifest::from_canonical_bytes(&publisher.spool().read(digest)?)?;
        if part.root() != digest
            || part.kind() != part_slot.as_str()
            || part.metadata_digest().is_some()
            || part.children().is_empty()
            || visible.child_count != part.children().len()
        {
            return Err(invalid("invalid retained import part manifest"));
        }
        let reachability =
            super::check_reachability(deployment, &part_slot, digest, aggregate_sequence)?;
        let sequence = reachability.new_anchor.commit_sequence;
        if previous_sequence.is_some_and(|previous| sequence <= previous) {
            return Err(invalid(
                "part publication order differs from its ordinal order",
            ));
        }
        previous_sequence = Some(sequence);
        first_sequence = first_sequence.min(sequence);
        // Parts contain opaque leaves: no hidden recursive closure or extra ledger children.
        if reachability.children.as_slice() != part.children() {
            return Err(invalid(
                "part reachability differs from its exact payload membership",
            ));
        }
        let width = *bound.get_or_insert(part.children().len());
        if part.children().len() > width
            || (ordinal + 1 < metadata.part_roots.len() && part.children().len() != width)
            || payloads
                .last()
                .zip(part.children().first())
                .is_some_and(|(last, first)| last >= first)
        {
            return Err(invalid(
                "part boundaries are noncanonical, overlapping or out of order",
            ));
        }
        let count = payloads
            .len()
            .checked_add(part.children().len())
            .ok_or_else(|| invalid("part payload count overflow"))?;
        if count > MAX_FILE_PUBLICATION_PAYLOADS {
            return Err(invalid(
                "part payload closure exceeds the reconstruction bound",
            ));
        }
        payloads.extend_from_slice(part.children());
    }
    let width = bound.ok_or_else(|| invalid("partitioned import has no parts"))?;
    // Reuse the writer's partition and aggregate construction, rather than defining a second
    // serialization dialect. No source payload is read by this reconstruction.
    let plan = FilePublicationPlan::new(identity, payloads.iter().copied(), width)?;
    if plan.part_roots() != metadata.part_roots || plan.root_manifest(metadata)? != *root {
        return Err(invalid(
            "retained parts do not reconstruct the exact import publication",
        ));
    }
    let mut held: BTreeSet<_> = payloads.into_iter().collect();
    held.insert(metadata_digest);
    checkpoint(cx, STAGE)?;
    Ok((held, first_sequence))
}
