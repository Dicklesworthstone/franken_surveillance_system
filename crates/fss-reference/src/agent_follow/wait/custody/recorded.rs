#![forbid(unsafe_code)]
//! Exact custody of the recorded imports supporting the selected quiet witnesses.
//!
//! File parts are typed independent publications, not aggregate manifest children. Resolve
//! only the owner's explicit part list and reconstruct its existing publication plan. Leaves
//! remain opaque: their verified bytes include source chunks, capsules and retained original
//! transport evidence, but their shape never authorizes recursive traversal or media replay.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EvidenceDelta, EvidenceDeltaBatch, Plane};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest};
use fss_publication::{
    ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY, SlotName, root_reachability_batch_id,
    root_reachability_object_id,
};

use super::{SourceAudit, invalid};
use crate::agent_follow::wait::FollowWaitError;
use crate::agent_orient::{DeploymentHistory, DeploymentSnapshot, HistoryPosition};
use crate::ingest::FileImportManifest;
use crate::ingest::file_publication::FilePublicationPlan;
use crate::ingest::retained::RetainedReadLimits;

struct Completion {
    metadata: ContentDigest,
    sequence: u64,
    children: Vec<ContentDigest>,
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn current<'a>(batches: &'a [EvidenceDeltaBatch], object: &str) -> Option<&'a EvidenceDelta> {
    batches
        .iter()
        .rev()
        .flat_map(|batch| batch.deltas.iter().rev())
        .find(|delta| delta.object_id.as_str() == object)
}

/// Completion and the current generation must identify the same exact immutable import.
fn completion(
    history: &DeploymentHistory,
    identity: ContentDigest,
    root: ContentDigest,
) -> Result<Completion, FollowWaitError> {
    let hex = hex(identity);
    let batches = history.batches_through_head();
    let batch_id = format!("batch:file-import:{hex}:manifest");
    let object = format!("object:file-import-manifest:{hex}");
    let import = format!("object:file-import:{hex}");
    let mut matching = batches
        .iter()
        .filter(|batch| batch.batch_id.as_str() == batch_id);
    let batch = matching
        .next()
        .ok_or_else(|| invalid("coverage import has no completion"))?;
    if matching.next().is_some() {
        return Err(invalid("coverage import completion is duplicated"));
    }
    let mut metadata = batch
        .deltas
        .iter()
        .filter(|delta| delta.object_id.as_str() == object);
    let delta = metadata
        .next()
        .ok_or_else(|| invalid("coverage import metadata has no authority"))?;
    if metadata.next().is_some()
        || delta.family != "file_import_manifest"
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.witness_digest != Some(root)
        || current(batches, &object) != Some(delta)
        || !batch.children.contains(&root)
        || !batch.children.contains(&delta.payload_digest)
    {
        return Err(invalid(
            "coverage import completion does not bind its exact root and metadata",
        ));
    }
    let mut imports = batch
        .deltas
        .iter()
        .filter(|claim| claim.object_id.as_str() == import);
    let claim = imports
        .next()
        .ok_or_else(|| invalid("coverage import has no completed generation"))?;
    if imports.next().is_some()
        || claim.family != "file_import"
        || claim.plane != Plane::Authority
        || claim.prior_generation != Some(1)
        || claim.new_generation != 2
        || claim.payload_digest != delta.payload_digest
        || claim.witness_digest != Some(root)
        || current(batches, &import) != Some(claim)
    {
        return Err(invalid("coverage import generation and metadata disagree"));
    }
    Ok(Completion {
        metadata: delta.payload_digest,
        sequence: batch.new_anchor.commit_sequence,
        children: batch.children.clone(),
    })
}

/// Reuse the native root-reachability identities and claim shape at the exact consumer prefix.
fn reachability(
    history: &DeploymentHistory,
    slot: &SlotName,
    root: &ObjectManifest,
    before: u64,
    exact_children: bool,
) -> Result<u64, FollowWaitError> {
    let batch_id = root_reachability_batch_id(slot)
        .map_err(|_| invalid("coverage import publication slot is not ledgerable"))?;
    let object = root_reachability_object_id(slot)
        .map_err(|_| invalid("coverage import publication identity is invalid"))?;
    let batches = history.batches_through_head();
    let mut matching = batches.iter().filter(|batch| batch.batch_id == batch_id);
    let batch = matching
        .next()
        .ok_or_else(|| invalid("coverage import publication has no reachability"))?;
    if matching.next().is_some() || batch.new_anchor.commit_sequence >= before {
        return Err(invalid(
            "coverage import publication does not precede its consumer",
        ));
    }
    let [claim] = batch.deltas.as_slice() else {
        return Err(invalid(
            "coverage import reachability is not one canonical claim",
        ));
    };
    if claim.delta_id != format!("{ROOT_REACHABILITY_DELTA_PREFIX}{slot}")
        || claim.object_id != object
        || claim.family != ROOT_REACHABILITY_FAMILY
        || claim.plane != Plane::Authority
        || claim.prior_generation.is_some()
        || claim.new_generation != 1
        || claim.payload_digest != root.root()
        || claim.witness_digest.is_some()
        || claim.operation_id.is_some()
        || current(batches, object.as_str()) != Some(claim)
    {
        return Err(invalid(
            "coverage import publication is not the current exact root",
        ));
    }
    if exact_children {
        if batch.children.as_slice() != root.children() {
            return Err(invalid(
                "coverage import part has different ledgered children",
            ));
        }
    } else {
        let ledgered: BTreeSet<_> = batch.children.iter().copied().collect();
        if root
            .children()
            .iter()
            .any(|digest| !ledgered.contains(digest))
        {
            return Err(invalid("coverage import children lack committed custody"));
        }
    }
    Ok(batch.new_anchor.commit_sequence)
}

fn verify_import(
    audit: &mut SourceAudit<'_>,
    identity: ContentDigest,
    root_digest: ContentDigest,
    completed: &Completion,
) -> Result<(), FollowWaitError> {
    let slot = SlotName::parse(&format!("fi-{}", hex(identity)))
        .map_err(|_| invalid("coverage import slot is invalid"))?;
    let root = ObjectManifest::from_canonical_bytes(audit.read(root_digest)?)
        .map_err(|_| invalid("coverage import root is not a canonical manifest"))?;
    if root.root() != root_digest
        || root.kind() != slot.as_str()
        || root.metadata_digest() != Some(completed.metadata)
    {
        return Err(invalid(
            "coverage import root does not bind its completed metadata",
        ));
    }
    audit.verify_publication(&slot, root_digest, root.children().len())?;
    let aggregate_sequence =
        reachability(audit.history(), &slot, &root, completed.sequence, false)?;
    let metadata = FileImportManifest::decode_metadata(
        audit.read(completed.metadata)?,
        completed.metadata,
        RetainedReadLimits::default(),
    )
    .map_err(|_| invalid("coverage import metadata is unsupported or invalid"))?;

    let mut publications = Vec::new();
    let payloads = if metadata.part_roots.is_empty() {
        root.children()
            .iter()
            .copied()
            .filter(|digest| *digest != completed.metadata)
            .collect::<Vec<_>>()
    } else {
        if root.children() != [completed.metadata].as_slice() {
            return Err(invalid(
                "partitioned coverage import aggregate is not metadata-only",
            ));
        }
        if metadata.part_roots.len() > audit.remaining_objects() {
            return Err(FollowWaitError::SourceBudgetExhausted);
        }
        let mut payloads = Vec::new();
        let mut seen = BTreeSet::new();
        let mut previous_sequence = None;
        for (ordinal, digest) in metadata.part_roots.iter().copied().enumerate() {
            audit.checkpoint()?;
            if !seen.insert(digest) {
                return Err(invalid("coverage import repeats a typed part root"));
            }
            let part_slot = SlotName::parse(&format!("{slot}-p{ordinal:06}"))
                .map_err(|_| invalid("coverage import part slot is invalid"))?;
            let part = ObjectManifest::from_canonical_bytes(audit.read(digest)?)
                .map_err(|_| invalid("coverage import part is not a canonical manifest"))?;
            if part.root() != digest
                || part.kind() != part_slot.as_str()
                || part.metadata_digest().is_some()
                || part.children().is_empty()
            {
                return Err(invalid(
                    "coverage import part is not the exact typed publication",
                ));
            }
            audit.verify_publication(&part_slot, digest, part.children().len())?;
            let sequence =
                reachability(audit.history(), &part_slot, &part, aggregate_sequence, true)?;
            if previous_sequence.is_some_and(|previous| sequence <= previous) {
                return Err(invalid(
                    "coverage import part order differs from committed publication order",
                ));
            }
            previous_sequence = Some(sequence);
            if payloads
                .last()
                .zip(part.children().first())
                .is_some_and(|(last, first)| last >= first)
            {
                return Err(invalid(
                    "coverage import parts overlap or have noncanonical boundaries",
                ));
            }
            let count = payloads
                .len()
                .checked_add(part.children().len())
                .ok_or(FollowWaitError::SourceBudgetExhausted)?;
            if count > audit.remaining_objects() {
                return Err(FollowWaitError::SourceBudgetExhausted);
            }
            payloads.extend_from_slice(part.children());
            publications.push((part_slot, digest, part.children().len()));
        }
        payloads
    };
    let width = publications
        .first()
        .map_or(MAX_MANIFEST_CHILDREN, |(_, _, count)| *count);
    let plan = FilePublicationPlan::new(identity, payloads.iter().copied(), width)
        .map_err(|_| invalid("coverage import payloads do not form the native publication plan"))?;
    if plan.part_roots() != metadata.part_roots
        || plan
            .root_manifest(&metadata)
            .map_err(|_| invalid("coverage import metadata does not reconstruct its publication"))?
            != root
    {
        return Err(invalid(
            "coverage import parts do not reconstruct the exact native publication",
        ));
    }
    let held: BTreeSet<_> = payloads
        .iter()
        .copied()
        .chain([completed.metadata])
        .collect();
    if completed
        .children
        .iter()
        .any(|digest| *digest != root_digest && !held.contains(digest))
    {
        return Err(invalid(
            "coverage import completion names content outside its publication",
        ));
    }
    let custody = ObjectManifest::new("custody", metadata.ordered_chunks.iter().copied(), None)
        .map_err(|_| invalid("coverage import source custody is invalid"))?;
    if !held.contains(&custody.root()) {
        return Err(invalid(
            "coverage import has no exact source-chunk custody manifest",
        ));
    }
    if payloads.len() > audit.remaining_objects() {
        return Err(FollowWaitError::SourceBudgetExhausted);
    }
    for digest in payloads {
        audit.read(digest)?;
    }
    for (part_slot, digest, count) in publications {
        audit.verify_publication(&part_slot, digest, count)?;
    }
    audit.verify_publication(&slot, root_digest, root.children().len())?;
    Ok(())
}

pub(super) fn verify(
    audit: &mut SourceAudit<'_>,
    snapshot: &DeploymentSnapshot,
) -> Result<(), FollowWaitError> {
    let mut verified = BTreeMap::new();
    for retained in &snapshot.coverage {
        audit.checkpoint()?;
        let witnesses: BTreeSet<_> = retained
            .record
            .zones
            .iter()
            .flat_map(|zone| &zone.witnesses)
            .map(|witness| witness.witness.witness_digest())
            .filter(|digest| audit.requires_witness(*digest))
            .collect();
        if witnesses.is_empty() {
            continue;
        }
        let record = &retained.record;
        if snapshot.deletions.import(record.import_identity).is_some() {
            return Err(invalid("a selected recorded coverage import is deleted"));
        }
        audit.read(retained.payload_digest)?;
        let completed = completion(audit.history(), record.import_identity, record.import_root)?;
        let basis = audit
            .history()
            .roots_at(HistoryPosition {
                commit_sequence: record.basis.commit_sequence,
                effect_records: None,
            })
            .ok_or_else(|| invalid("recorded coverage basis is not a committed prefix"))?
            .0;
        if basis != record.basis
            || completed.sequence > basis.commit_sequence
            || basis.commit_sequence >= retained.committed_sequence
        {
            return Err(invalid(
                "recorded coverage does not follow its exact completed import basis",
            ));
        }
        match verified.get(&record.import_identity) {
            Some(root) if *root != record.import_root => {
                return Err(invalid("recorded coverage assigns two roots to one import"));
            }
            Some(_) => {}
            None => {
                verify_import(
                    audit,
                    record.import_identity,
                    record.import_root,
                    &completed,
                )?;
                verified.insert(record.import_identity, record.import_root);
            }
        }
        for digest in witnesses {
            audit.witness_verified(digest);
        }
    }
    Ok(())
}
