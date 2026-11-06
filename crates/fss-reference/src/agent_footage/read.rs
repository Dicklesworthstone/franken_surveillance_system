#![forbid(unsafe_code)]
//! Explicit metadata read authority, custody verification and final revalidation.

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget,
};
use crate::ingest::file_publication::FilePublicationPlan;
use crate::ingest::retained::RetainedReadLimits;
use crate::ingest::{ADP_FILE_ROW_ID, FileImportManifest};
use fss_core::{CanonicalDecode, EvidenceDelta, EvidenceDeltaBatch, Plane};
use fss_object::ObjectManifest;
use fss_publication::{
    ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY, SlotName, root_reachability_batch_id,
    root_reachability_object_id, root_record_bytes,
};
use std::collections::{BTreeMap, BTreeSet};

fn invalid<T>() -> Result<T, FootageQueryError> {
    Err(FootageQueryError::InvalidRecord)
}
fn history_error(error: DeploymentReadError) -> FootageQueryError {
    if error.reason().contains("budget") || error.reason().contains("read bound") {
        FootageQueryError::OverBudget
    } else {
        FootageQueryError::Read(error.into())
    }
}

/// This authority owns no writer, lock, recovery handle, media decoder or source-file path.
/// Every additional object read is admitted by the same allowance as native snapshot replay.
struct ReadAuthority<'a> {
    history: &'a DeploymentHistory,
    budget: &'a MetadataReadBudget,
    deletions: &'a crate::deletion::DeletionIndex,
    limits: &'a FootageQueryLimits,
    check: &'a mut dyn FnMut(&'static str) -> bool,
    metadata: BTreeSet<ContentDigest>,
    custody: BTreeSet<ContentDigest>,
    publications: BTreeMap<SlotName, (ContentDigest, usize)>,
}
impl ReadAuthority<'_> {
    fn check(&mut self, stage: &'static str) -> Result<(), FootageQueryError> {
        checkpoint(self.check, stage)
    }
    fn deny_deleted(&mut self, digest: ContentDigest) -> Result<(), FootageQueryError> {
        if self.deletions.object(digest).is_some() {
            return invalid();
        }
        if !self.custody.contains(&digest) && self.custody.len() >= self.limits.max_objects {
            return Err(FootageQueryError::OverBudget);
        }
        self.custody.insert(digest);
        self.check("footage:tombstone")?;
        self.history
            .wait_check_tombstone(digest)
            .map_err(history_error)
    }
    fn object(&mut self, digest: ContentDigest) -> Result<Vec<u8>, FootageQueryError> {
        self.check("footage:metadata")?;
        self.deny_deleted(digest)?;
        let max = self
            .budget
            .allowance(self.limits.snapshot.max_object_bytes)
            .map_err(|_| FootageQueryError::OverBudget)?;
        let bytes = self
            .history
            .wait_read_object(digest, max)
            .map_err(|error| {
                if max < self.limits.snapshot.max_object_bytes {
                    FootageQueryError::OverBudget
                } else {
                    let _ = error;
                    FootageQueryError::InvalidRecord
                }
            })?;
        self.budget
            .charge(bytes.len())
            .map_err(|_| FootageQueryError::OverBudget)?;
        if ContentDigest::sha256(&bytes) != digest {
            return invalid();
        }
        self.metadata.insert(digest);
        Ok(bytes)
    }
    fn manifest(&mut self, digest: ContentDigest) -> Result<ObjectManifest, FootageQueryError> {
        let bytes = self.object(digest)?;
        let m = ObjectManifest::from_canonical_bytes(&bytes)
            .map_err(|_| FootageQueryError::InvalidRecord)?;
        if m.root() != digest || m.canonical_bytes() != bytes {
            return invalid();
        }
        Ok(m)
    }
    fn publication(
        &mut self,
        slot: &SlotName,
        root: ContentDigest,
        count: usize,
    ) -> Result<(), FootageQueryError> {
        self.check("footage:publication")?;
        let bytes = self
            .history
            .wait_read_publication(slot, fss_publication::MAX_ROOT_RECORD_BYTES as usize)
            .map_err(history_error)?;
        if root_record_bytes(slot, root, count).map_err(|_| FootageQueryError::InvalidRecord)?
            != bytes
        {
            return invalid();
        }
        if self
            .publications
            .insert(slot.clone(), (root, count))
            .is_some_and(|old| old != (root, count))
        {
            return invalid();
        }
        Ok(())
    }
    fn revalidate(&mut self) -> Result<(), FootageQueryError> {
        self.check("footage:revalidate")?;
        let metadata: Vec<_> = self.metadata.iter().copied().collect();
        for digest in metadata {
            self.object(digest)?;
        }
        let publications: Vec<_> = self
            .publications
            .iter()
            .map(|(s, (r, n))| (s.clone(), *r, *n))
            .collect();
        for (slot, root, count) in publications {
            self.publication(&slot, root, count)?;
        }
        let custody: Vec<_> = self.custody.iter().copied().collect();
        for digest in custody {
            self.deny_deleted(digest)?;
        }
        Ok(())
    }
}
struct Index<'a> {
    batches: BTreeMap<&'a str, &'a EvidenceDeltaBatch>,
    latest: BTreeMap<&'a str, &'a EvidenceDelta>,
    capsules: BTreeMap<&'a str, Vec<&'a EvidenceDeltaBatch>>,
    completions: Vec<(&'a EvidenceDeltaBatch, &'a EvidenceDelta, &'a str)>,
}
impl<'a> Index<'a> {
    fn new(
        history: &'a DeploymentHistory,
        limits: &FootageQueryLimits,
        check: &mut dyn FnMut(&'static str) -> bool,
    ) -> Result<Self, FootageQueryError> {
        let mut result = Self {
            batches: BTreeMap::new(),
            latest: BTreeMap::new(),
            capsules: BTreeMap::new(),
            completions: Vec::new(),
        };
        for batch in history.batches_through_head() {
            checkpoint(check, "footage:authority")?;
            if result
                .batches
                .insert(batch.batch_id.as_str(), batch)
                .is_some()
            {
                return invalid();
            }
            if let Some((identity, suffix)) = batch
                .batch_id
                .as_str()
                .strip_prefix("batch:file-import:")
                .and_then(|v| v.split_once(':'))
            {
                if suffix
                    .strip_prefix('c')
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                {
                    result.capsules.entry(identity).or_default().push(batch);
                }
            }
            for delta in &batch.deltas {
                if !result.latest.contains_key(delta.object_id.as_str())
                    && result.latest.len() >= limits.max_objects
                {
                    return Err(FootageQueryError::OverBudget);
                }
                result.latest.insert(delta.object_id.as_str(), delta);
                if delta.family == "file_import_manifest" {
                    if result.completions.len() >= limits.max_imports {
                        return Err(FootageQueryError::OverBudget);
                    }
                    let identity = batch
                        .batch_id
                        .as_str()
                        .strip_prefix("batch:file-import:")
                        .and_then(|v| v.strip_suffix(":manifest"))
                        .ok_or(FootageQueryError::InvalidRecord)?;
                    result.completions.push((batch, delta, identity));
                }
            }
        }
        Ok(result)
    }
    fn reachability(
        &self,
        slot: &SlotName,
        root: ContentDigest,
        before: u64,
    ) -> Result<&'a EvidenceDeltaBatch, FootageQueryError> {
        let batch_id =
            root_reachability_batch_id(slot).map_err(|_| FootageQueryError::InvalidRecord)?;
        let object_id =
            root_reachability_object_id(slot).map_err(|_| FootageQueryError::InvalidRecord)?;
        let batch = *self
            .batches
            .get(batch_id.as_str())
            .ok_or(FootageQueryError::InvalidRecord)?;
        let [claim] = batch.deltas.as_slice() else {
            return invalid();
        };
        if batch.new_anchor.commit_sequence >= before
            || claim.delta_id != format!("{ROOT_REACHABILITY_DELTA_PREFIX}{}", slot.as_str())
            || claim.object_id != object_id
            || claim.family != ROOT_REACHABILITY_FAMILY
            || claim.plane != Plane::Authority
            || claim.prior_generation.is_some()
            || claim.new_generation != 1
            || claim.payload_digest != root
            || claim.witness_digest.is_some()
            || claim.operation_id.is_some()
        {
            return invalid();
        }
        let current = self
            .latest
            .get(object_id.as_str())
            .ok_or(FootageQueryError::InvalidRecord)?;
        if current.new_generation != 1
            || current.family != ROOT_REACHABILITY_FAMILY
            || current.plane != Plane::Authority
            || current.payload_digest != root
        {
            return invalid();
        }
        Ok(batch)
    }
}

fn root_membership(
    reader: &mut ReadAuthority<'_>,
    index: &Index<'_>,
    identity: ContentDigest,
    slot: &SlotName,
    root_digest: ContentDigest,
    metadata: &FileImportManifest,
    completion: &EvidenceDeltaBatch,
) -> Result<(BTreeSet<ContentDigest>, u64), FootageQueryError> {
    let root = reader.manifest(root_digest)?;
    if root.kind() != slot.as_str() || root.metadata_digest() != Some(metadata.canonical_digest()) {
        return invalid();
    }
    reader.publication(slot, root_digest, root.children().len())?;
    let reach = index.reachability(slot, root_digest, completion.new_anchor.commit_sequence)?;
    let mut held: BTreeSet<_> = root.children().iter().copied().collect();
    let ledgered: BTreeSet<_> = reach.children.iter().copied().collect();
    if !held.is_subset(&ledgered) {
        return invalid();
    }
    let mut first = reach.new_anchor.commit_sequence;
    if !metadata.part_roots.is_empty() {
        if root.children() != [metadata.canonical_digest()].as_slice() {
            return invalid();
        }
        let mut payloads = Vec::new();
        let mut width = None;
        let mut previous = None;
        for (ordinal, digest) in metadata.part_roots.iter().copied().enumerate() {
            reader.check("footage:part")?;
            let part_slot = SlotName::parse(&format!("{slot}-p{ordinal:06}"))
                .map_err(|_| FootageQueryError::InvalidRecord)?;
            let part = reader.manifest(digest)?;
            if part.kind() != part_slot.as_str()
                || part.metadata_digest().is_some()
                || part.children().is_empty()
            {
                return invalid();
            }
            reader.publication(&part_slot, digest, part.children().len())?;
            let proof = index.reachability(&part_slot, digest, reach.new_anchor.commit_sequence)?;
            let sequence = proof.new_anchor.commit_sequence;
            if previous.is_some_and(|p| sequence <= p)
                || proof.children.as_slice() != part.children()
            {
                return invalid();
            }
            previous = Some(sequence);
            first = first.min(sequence);
            let bound = *width.get_or_insert(part.children().len());
            if part.children().len() > bound
                || (ordinal + 1 < metadata.part_roots.len() && part.children().len() != bound)
                || payloads
                    .last()
                    .zip(part.children().first())
                    .is_some_and(|(a, b)| a >= b)
            {
                return invalid();
            }
            if payloads.len().saturating_add(part.children().len()) > reader.limits.max_objects {
                return Err(FootageQueryError::OverBudget);
            }
            payloads.extend_from_slice(part.children());
        }
        let plan = FilePublicationPlan::new(
            identity,
            payloads.iter().copied(),
            width.ok_or(FootageQueryError::InvalidRecord)?,
        )
        .map_err(|_| FootageQueryError::InvalidRecord)?;
        if plan.part_roots() != metadata.part_roots
            || plan
                .root_manifest(metadata)
                .map_err(|_| FootageQueryError::InvalidRecord)?
                != root
        {
            return invalid();
        }
        held = payloads.into_iter().collect();
        held.insert(metadata.canonical_digest());
    }
    if held.len() > reader.limits.max_objects {
        return Err(FootageQueryError::OverBudget);
    }
    if completion
        .children
        .iter()
        .any(|d| *d != root_digest && !held.contains(d))
    {
        return invalid();
    }
    for digest in &held {
        reader.deny_deleted(*digest)?;
    }
    Ok((held, first))
}

fn import_rows(
    reader: &mut ReadAuthority<'_>,
    index: &Index<'_>,
    snapshot: &DeploymentSnapshot,
    completion: &EvidenceDeltaBatch,
    claim: &EvidenceDelta,
    identity_text: &str,
    rows: &mut Vec<FootageQueryRow>,
) -> Result<bool, FootageQueryError> {
    let identity = ContentDigest::parse(format!("sha256:{identity_text}"))
        .map_err(|_| FootageQueryError::InvalidRecord)?;
    if identity.to_text() != format!("sha256:{identity_text}") {
        return invalid();
    }
    let root = claim
        .witness_digest
        .ok_or(FootageQueryError::InvalidRecord)?;
    if snapshot.deletions.import(identity).is_some()
        || snapshot.deletions.object(claim.payload_digest).is_some()
        || snapshot.deletions.object(root).is_some()
    {
        return Ok(false);
    }
    if claim.plane != Plane::Authority
        || claim.prior_generation.is_some()
        || claim.new_generation != 1
        || claim.object_id.as_str() != format!("object:file-import-manifest:{identity_text}")
        || !completion.children.contains(&root)
        || !completion.children.contains(&claim.payload_digest)
    {
        return invalid();
    }
    let import_object = format!("object:file-import:{identity_text}");
    let final_delta = completion
        .deltas
        .iter()
        .find(|d| d.object_id.as_str() == import_object)
        .ok_or(FootageQueryError::InvalidRecord)?;
    if final_delta.family != "file_import"
        || final_delta.plane != Plane::Authority
        || final_delta.prior_generation != Some(1)
        || final_delta.new_generation != 2
        || final_delta.payload_digest != claim.payload_digest
        || final_delta.witness_digest != Some(root)
    {
        return invalid();
    }
    for delta in [claim, final_delta] {
        let latest = index
            .latest
            .get(delta.object_id.as_str())
            .ok_or(FootageQueryError::InvalidRecord)?;
        if latest.family == "deletion_tombstone" {
            return Ok(false);
        }
        if *latest != delta {
            return invalid();
        }
    }
    let metadata = FileImportManifest::decode_metadata(
        &reader.object(claim.payload_digest)?,
        claim.payload_digest,
        RetainedReadLimits::default(),
    )
    .map_err(|_| FootageQueryError::InvalidRecord)?;
    if metadata.adapter_id != ADP_FILE_ROW_ID {
        return Ok(true);
    }
    if rows.len().saturating_add(metadata.capsule_ids.len()) > reader.limits.max_capsules {
        return Err(FootageQueryError::OverBudget);
    }
    let slot = SlotName::parse(&format!("fi-{identity_text}"))
        .map_err(|_| FootageQueryError::InvalidRecord)?;
    let (held, first) =
        root_membership(reader, index, identity, &slot, root, &metadata, completion)?;
    let chunks: BTreeSet<_> = metadata.ordered_chunks.iter().copied().collect();
    if !chunks.is_subset(&held) {
        return invalid();
    }
    let custody = ObjectManifest::new("custody", chunks, None)
        .map_err(|_| FootageQueryError::InvalidRecord)?;
    if !held.contains(&custody.root())
        || reader.object(custody.root())? != custody.canonical_bytes()
    {
        return invalid();
    }
    let mut capsules = BTreeMap::new();
    let mut initial = false;
    for batch in index.capsules.get(identity_text).into_iter().flatten() {
        reader.check("footage:membership")?;
        if batch.new_anchor.commit_sequence >= first {
            return invalid();
        }
        for delta in &batch.deltas {
            if delta.family == "file_import" && delta.object_id.as_str() == import_object {
                if initial
                    || delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || delta.payload_digest != custody.root()
                    || !batch.children.contains(&custody.root())
                {
                    return invalid();
                }
                initial = true;
            } else if delta.family == "sensor_capsule" {
                if delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || !batch.children.contains(&delta.payload_digest)
                    || !held.contains(&delta.payload_digest)
                    || capsules.insert(delta.object_id.as_str(), delta).is_some()
                {
                    return invalid();
                }
            }
        }
    }
    if !initial || capsules.len() != metadata.capsule_ids.len() {
        return invalid();
    }
    for span in &metadata.segment_spans {
        reader.check("footage:capsule")?;
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        let delta = *capsules
            .get(object.as_str())
            .ok_or(FootageQueryError::InvalidRecord)?;
        let current = index
            .latest
            .get(object.as_str())
            .ok_or(FootageQueryError::InvalidRecord)?;
        if current.family == "deletion_tombstone"
            || snapshot.deletions.object(delta.payload_digest).is_some()
        {
            return invalid();
        }
        if *current != delta {
            return invalid();
        }
        let bytes = reader.object(delta.payload_digest)?;
        let capsule = SensorCapsule::from_canonical_bytes(&bytes)
            .map_err(|_| FootageQueryError::InvalidRecord)?;
        if capsule.canonical_bytes() != bytes
            || capsule.capsule_id != span.capsule_id
            || capsule.source_digest != span.segment_sha256
            || capsule.source_bytes != span.len
            || capsule.gap_before != span.gap_before
            || capsule.sequence != span.segment_index as u64
            || delta.validity != capsule.capture
            || delta.witness_digest.is_some()
            || delta.operation_id.is_some()
        {
            return invalid();
        }
        rows.push(FootageQueryRow {
            import_identity: identity,
            import_root: root,
            manifest_digest: claim.payload_digest,
            capsule_digest: delta.payload_digest,
            capsule,
            segment_index: span.segment_index as u64,
            source_offset: span.offset,
            source_len: span.len,
            input_digest: metadata.input_sha256,
            input_bytes: metadata.input_bytes,
            format: metadata.format.clone(),
            capture_time_label: metadata.capture_time_label.clone(),
            committed_sequence: completion.new_anchor.commit_sequence,
        });
    }
    Ok(false)
}

pub(super) fn query(
    root: &Path,
    request: &FootageQueryRequest,
    limits: &FootageQueryLimits,
    check: &mut dyn FnMut(&'static str) -> bool,
) -> Result<DeploymentFootageQuery, FootageQueryError> {
    request.validate()?;
    limits.validate()?;
    checkpoint(check, "footage:start")?;
    let budget = MetadataReadBudget::new(limits.max_metadata_bytes, limits.max_metadata_objects);
    let history =
        DeploymentHistory::read_metadata(root, &limits.snapshot, &budget).map_err(history_error)?;
    checkpoint(check, "footage:snapshot")?;
    let snapshot = history.snapshot_at(history.head()).map_err(history_error)?;
    budget
        .ensure_valid()
        .map_err(|_| FootageQueryError::InvalidRecord)?;
    let anchor = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|a| a.as_str() != anchor)
    {
        return Err(FootageQueryError::AnchorChanged);
    }
    let index = Index::new(&history, limits, check)?;
    let mut reader = ReadAuthority {
        history: &history,
        budget: &budget,
        deletions: &snapshot.deletions,
        limits,
        check,
        metadata: BTreeSet::new(),
        custody: BTreeSet::new(),
        publications: BTreeMap::new(),
    };
    let mut rows = Vec::new();
    let mut other_adapter_imports = 0;
    for (batch, claim, identity) in &index.completions {
        reader.check("footage:import")?;
        if import_rows(
            &mut reader,
            &index,
            &snapshot,
            batch,
            claim,
            identity,
            &mut rows,
        )? {
            other_adapter_imports += 1;
        }
    }
    rows.sort_by(|a, b| {
        (&a.import_identity, a.segment_index).cmp(&(&b.import_identity, b.segment_index))
    });
    let mut identities = BTreeSet::new();
    for row in &rows {
        if !identities.insert(row.capsule.capsule_id.clone()) {
            return invalid();
        }
    }
    let mut result = super::result::compile(
        snapshot.clone(),
        request,
        limits,
        rows,
        other_adapter_imports,
    )?;
    reader.revalidate()?;
    // No cursor/page leaves the boundary until a second independently replayed head agrees.
    reader.check("footage:final_head")?;
    let final_history =
        DeploymentHistory::read_metadata(root, &limits.snapshot, &budget).map_err(history_error)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(history_error)?;
    budget
        .ensure_valid()
        .map_err(|_| FootageQueryError::InvalidRecord)?;
    if snapshot_anchor_token(&final_snapshot) != anchor
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != result.snapshot.deletions
    {
        return Err(FootageQueryError::AnchorChanged);
    }
    // Recheck local deletion markers after the final journal read, too.
    for digest in reader.custody.iter().copied() {
        checkpoint(reader.check, "footage:tombstone_final")?;
        final_history
            .wait_check_tombstone(digest)
            .map_err(history_error)?;
    }
    checkpoint(reader.check, "footage:complete")?;
    (result.metadata_bytes_read, result.metadata_objects_read) = budget.consumed();
    Ok(result)
}
