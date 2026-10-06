#![forbid(unsafe_code)]
//! A completion witness must bind an actual, previously ledgered import publication.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncode, ContentDigest, EvidenceDeltaBatch, Plane};
use fss_object::ObjectManifest;
use fss_publication::{
    LocalPublicationState, ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY, SlotName,
    root_reachability_batch_id, root_reachability_object_id,
};

use super::{FileImportManifest, FileIngestError, checkpoint, invalid};
use crate::{ReferenceDeployment, ReplayCx};

const STAGE: &str = "file_retained:root_binding";

/// Verify bounded metadata/authority membership, not detection quality or full source bytes.
/// Source/segment reads still verify their actual chunks through the existing retained reader.
pub(super) fn verify(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    completion: &EvidenceDeltaBatch,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    checkpoint(cx, STAGE)?;
    let visible = deployment
        .publisher()
        .root(slot)
        .ok_or_else(|| invalid("import root is unavailable"))?;
    if visible.state != LocalPublicationState::Durable || visible.root != import_root {
        return Err(invalid(
            "import root is not the witnessed durable publication",
        ));
    }
    let root_bytes = deployment.publisher().spool().read(import_root)?;
    let root = ObjectManifest::from_canonical_bytes(&root_bytes)?;
    if root.root() != import_root
        || root.kind() != slot.as_str()
        || root.metadata_digest() != Some(manifest_digest)
    {
        return Err(invalid(
            "publication root does not bind the exact import metadata",
        ));
    }

    let reachability_id = root_reachability_batch_id(slot)
        .map_err(|_| invalid("import slot has no reachability identity"))?;
    let object_id = root_reachability_object_id(slot)
        .map_err(|_| invalid("import slot has no reachability object identity"))?;
    let ledger = deployment.ledger();
    let reachability = ledger
        .batches()
        .iter()
        .find(|batch| batch.batch_id == reachability_id)
        .ok_or_else(|| invalid("durable import root has no committed reachability proof"))?;
    if reachability.new_anchor.commit_sequence >= completion.new_anchor.commit_sequence {
        return Err(invalid("root reachability must precede import completion"));
    }
    let [claim] = reachability.deltas.as_slice() else {
        return Err(invalid("root reachability is not one canonical claim"));
    };
    if claim.delta_id != format!("{ROOT_REACHABILITY_DELTA_PREFIX}{}", slot.as_str())
        || claim.object_id != object_id
        || claim.family != ROOT_REACHABILITY_FAMILY
        || claim.plane != Plane::Authority
        || claim.prior_generation.is_some()
        || claim.new_generation != 1
        || claim.payload_digest != import_root
        || claim.witness_digest.is_some()
        || claim.operation_id.is_some()
    {
        return Err(invalid(
            "root reachability claim disagrees with the import witness",
        ));
    }
    let current = ledger
        .current()
        .objects
        .get(&object_id)
        .ok_or_else(|| invalid("root reachability is no longer current"))?;
    if current.generation != 1
        || current.family != ROOT_REACHABILITY_FAMILY
        || current.plane != Plane::Authority
        || current.payload_digest != import_root
    {
        return Err(invalid(
            "import root reachability is retracted or superseded",
        ));
    }

    let held: BTreeSet<_> = root.children().iter().copied().collect();
    let ledgered: BTreeSet<_> = reachability.children.iter().copied().collect();
    if !held.is_subset(&ledgered) {
        return Err(invalid(
            "root children are absent from its ledgered closure",
        ));
    }
    let chunks: BTreeSet<_> = manifest.ordered_chunks.iter().copied().collect();
    if !chunks.is_subset(&held) {
        return Err(invalid(
            "import source chunks are outside the publication root",
        ));
    }
    let custody = ObjectManifest::new("custody", chunks, None)?;
    if !held.contains(&custody.root()) {
        return Err(invalid(
            "import custody manifest is outside the publication root",
        ));
    }
    checkpoint(cx, STAGE)?;
    if deployment.publisher().spool().read(custody.root())? != custody.canonical_bytes() {
        return Err(invalid(
            "import custody manifest disagrees with source chunk identities",
        ));
    }

    // Resolve all capsule identities in one history pass. Do not hydrate every capsule or
    // source chunk on every retained segment read; their consumers perform exact byte checks.
    let prefix = completion
        .batch_id
        .as_str()
        .strip_suffix("manifest")
        .ok_or_else(|| invalid("invalid completing import batch identity"))?;
    let mut capsules = BTreeMap::new();
    let mut initial_custody = false;
    let import_hex = slot
        .as_str()
        .strip_prefix("fi-")
        .ok_or_else(|| invalid("invalid import slot identity"))?;
    let import_object = format!("object:file-import:{import_hex}");
    for batch in ledger.batches() {
        checkpoint(cx, STAGE)?;
        let is_capsule_batch = batch
            .batch_id
            .as_str()
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.strip_prefix('c'))
            .is_some_and(|index| {
                !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
            });
        if !is_capsule_batch {
            continue;
        }
        if batch.new_anchor.commit_sequence >= reachability.new_anchor.commit_sequence {
            return Err(invalid(
                "capsule authority must precede import root publication",
            ));
        }
        let children: BTreeSet<_> = batch.children.iter().copied().collect();
        for delta in &batch.deltas {
            checkpoint(cx, STAGE)?;
            if delta.family == "file_import" && delta.object_id.as_str() == import_object {
                if initial_custody
                    || delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || delta.payload_digest != custody.root()
                    || !children.contains(&custody.root())
                {
                    return Err(invalid(
                        "initial import authority disagrees with source custody",
                    ));
                }
                initial_custody = true;
            } else if delta.family == "sensor_capsule"
                && (delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || !children.contains(&delta.payload_digest)
                    || !held.contains(&delta.payload_digest)
                    || capsules
                        .insert(delta.object_id.as_str(), delta.payload_digest)
                        .is_some())
            {
                return Err(invalid(
                    "capsule authority is duplicated or outside import custody",
                ));
            }
        }
    }
    if !initial_custody || capsules.len() != manifest.capsule_ids.len() {
        return Err(invalid(
            "import manifest and capsule authority have different membership",
        ));
    }
    for capsule_id in &manifest.capsule_ids {
        checkpoint(cx, STAGE)?;
        let object = format!("object:capsule:{}", capsule_id.as_str());
        if !capsules.contains_key(object.as_str()) {
            return Err(invalid("manifest capsule lacks authority in this import"));
        }
    }
    checkpoint(cx, STAGE)?;
    Ok(())
}
