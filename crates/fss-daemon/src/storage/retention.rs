#![forbid(unsafe_code)]
//! Rebuildable media retention, durable pins, and canonical retirement before pack reclaim.

use std::collections::BTreeSet;

use fss_pack::{PackReadBudget, RootStatus};
use fss_projection_store::{
    DeletionTarget, DeletionTombstonePayload, EvidenceHoldPayload, FAMILY_DELETION_TOMBSTONE,
    FAMILY_EVIDENCE_HOLD,
};

use super::*;

const EVENT_HOLD_SCOPE: &str = "daemon:event:";
const LEGACY_HOLD_BLOCKER: &str = "recovery:legacy-hold-state-unverified";
const HISTORY_CANDIDATE: &str = "retention:canonical-history";
const CATALOG_REFERENCE_BLOCKER: &str = "retention:live-catalog-reference";
const MAX_RETENTION_METADATA_BYTES: u64 = 64 * 1024;

pub(super) struct RetainedRoot {
    pub(super) media_digest: ContentDigest,
    pub(super) metadata_digest: ContentDigest,
    pub(super) legacy_hold_state: bool,
}

pub(super) struct RetiredRoot {
    root_id: String,
    media_digest: ContentDigest,
    metadata_digest: Option<ContentDigest>,
}

type RecoveredRetention = (
    BTreeMap<String, RetentionCandidate>,
    BTreeMap<String, RetainedRoot>,
    Vec<RetiredRoot>,
    u64,
);

/// Visit the entire catalog in bounded pages. Metadata is content-verified before it can
/// influence capacity or deletion; opening refuses an incomplete/corrupt live GOP closure.
pub(super) fn recover_retained_roots(
    packs: &PackStore,
    head_sequence: u64,
) -> Result<RecoveredRetention, DaemonError> {
    let mut pending_deletions = Vec::new();
    let mut candidates = BTreeMap::new();
    let mut roots = BTreeMap::new();
    let mut max_sequence = head_sequence;
    let mut cursor: Option<String> = None;
    loop {
        let page = packs.list_roots(cursor.as_deref(), 512)?;
        for entry in page.entries {
            max_sequence = max_sequence.max(entry.sequence);
            let record = entry.record;
            if let Some(rest) = record.root_id.strip_prefix("gop:")
                && let Some(tail) = rest.rsplit(':').next()
                && let Ok(sequence) = tail.parse::<u64>()
            {
                max_sequence = max_sequence.max(sequence);
            }
            if matches!(entry.status, RootStatus::Tombstoned { .. })
                && record.root_id.starts_with("gop:")
                && record.kind == "media-gop-v2"
                && packs.object_tombstone(&record.root_digest)?.is_none()
            {
                pending_deletions.push(RetiredRoot {
                    root_id: record.root_id.clone(),
                    media_digest: record.root_digest,
                    metadata_digest: record.metadata_digest,
                });
            }
            if !matches!(entry.status, RootStatus::Live)
                || !record.root_id.starts_with("gop:")
                || !matches!(record.kind.as_str(), "media-gop-v1" | "media-gop-v2")
            {
                continue;
            }
            let invalid = || DaemonError::InvalidConfig {
                detail: format!(
                    "cannot recover verified retention metadata for {}",
                    record.root_id
                ),
            };
            let metadata_digest = record.metadata_digest.ok_or_else(invalid)?;
            let metadata = packs.read_verified_with_budget(
                &metadata_digest,
                &PackReadBudget::new(MAX_RETENTION_METADATA_BYTES),
            )?;
            let ProjectionRecordPayload::FootageImport(import) =
                ProjectionRecordPayload::decode_bytes(&metadata)?
            else {
                return Err(invalid());
            };
            if !import.completed
                || import.import_id != record.root_digest
                || import.manifest_digest != record.root_digest
                || import.capsule_count != record.child_count
                || import.capture_interval.latest != record.created_at_ns
                || import.total_bytes.checked_add(metadata.len() as u64)
                    != Some(record.total_payload_bytes)
                || packs.lookup(&record.root_digest)?.is_none_or(|location| {
                    location.len != import.total_bytes
                        || location.object_kind != PACK_KIND_MEDIA_CHUNK
                })
            {
                return Err(invalid());
            }
            let candidate = RetentionCandidate {
                import_id: record.root_id.clone(),
                sensor_id: import.sensor_id.as_str().to_owned(),
                capture_end_ns: import.capture_interval.latest,
                byte_size: import.total_bytes,
                // Canonical FSPP payloads are permanent replay inputs, never media garbage.
                object_digests: vec![record.root_digest],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            };
            candidate.validate()?;
            candidates.insert(record.root_id.clone(), candidate);
            roots.insert(
                record.root_id,
                RetainedRoot {
                    media_digest: record.root_digest,
                    metadata_digest,
                    legacy_hold_state: record.kind == "media-gop-v1",
                },
            );
        }
        if !page.has_more {
            break;
        }
        let next = page.next_cursor.ok_or_else(|| DaemonError::InvalidConfig {
            detail: "retention catalog scan did not return its continuation cursor".to_owned(),
        })?;
        if cursor.as_ref().is_some_and(|previous| next <= *previous) {
            return Err(DaemonError::InvalidConfig {
                detail: "retention catalog scan did not advance".to_owned(),
            });
        }
        cursor = Some(next);
    }
    let next = max_sequence
        .checked_add(1)
        .ok_or_else(|| DaemonError::InvalidConfig {
            detail: "retention sequence space exhausted".to_owned(),
        })?;
    Ok((candidates, roots, pending_deletions, next.max(1)))
}

impl StorageEngine {
    /// Durably creates or releases a hold on a retained media closure. The hold identity
    /// cannot be redirected to another target; releasing a hold requires its original target.
    /// The explicit authority context is checked by the canonical commit owner.
    pub fn set_candidate_hold(
        &mut self,
        import_id: &str,
        hold_id: impl Into<String>,
        active: bool,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<bool, DaemonError> {
        self.change_candidate_hold(import_id, hold_id.into(), active, Some((cx, tree)))
    }

    pub(super) fn change_candidate_hold(
        &mut self,
        import_id: &str,
        hold_id: String,
        active: bool,
        authority: Option<(&AuthorityCx, &RegionTree)>,
    ) -> Result<bool, DaemonError> {
        let gate = Arc::clone(&self.retention_gate);
        let _guard = gate.lock().map_err(|_| DaemonError::LockPoisoned {
            component: "retention_gate",
        })?;
        if let Some((cx, tree)) = authority
            && cx.is_cancel_requested(tree)?
        {
            return Err(fss_projection_store::CombinerError::Cancelled.into());
        }
        let (target, at) = if let Some(candidate) = self.candidates.get(import_id) {
            let Some(&target) = candidate.object_digests.first() else {
                return Ok(false);
            };
            (target, candidate.capture_end_ns)
        } else if let Some(pending) = self
            .pending_deletions
            .iter()
            .find(|pending| pending.root_id == import_id)
        {
            let Some(entry) = self.pack_store.get_root(import_id)? else {
                return Ok(false);
            };
            (pending.media_digest, entry.record.created_at_ns)
        } else {
            return Ok(false);
        };
        if active && self.pack_store.object_tombstone(&target)?.is_some() {
            return Err(DaemonError::InvalidConfig {
                detail: "cannot hold a source whose object deletion is already committed"
                    .to_owned(),
            });
        }
        let snapshot = self.projection.snapshot_latest();
        if let Some(previous) = snapshot.get_hold(&hold_id) {
            if previous.target_digest != target || previous.scope.starts_with(EVENT_HOLD_SCOPE) {
                return Err(DaemonError::InvalidConfig {
                    detail: "hold identity belongs to another target or an event evidence closure"
                        .to_owned(),
                });
            }
            if previous.active == active {
                self.refresh_retention_pins();
                return Ok(true);
            }
        }
        let hold_identity = hold_id.clone();
        let (object, delta) =
            self.hold_delta(hold_id, "daemon:media-gop".to_owned(), target, active, at)?;
        let object_id = delta.object_id.clone();
        let generation = delta.new_generation;
        let proposal = CommitProposal {
            request_digest: delta.payload_digest,
            sensor_scope: "retention:hold".to_owned(),
            objects: vec![object],
            batch_id_prefix: format!("retention-hold-g{generation}"),
            deltas: vec![delta],
        };
        match authority {
            Some((cx, tree)) => {
                self.combiner.submit_with_authority(cx, tree, proposal)?;
            }
            None => {
                self.combiner.submit(proposal)?;
            }
        }
        self.record_object_generation(object_id, generation)?;
        self.refresh_retention_pins();
        // Explicit, caller-registered candidates have no catalog reconstruction contract.
        if !self.candidate_roots.contains_key(import_id)
            && let Some(candidate) = self.candidates.get_mut(import_id)
        {
            candidate.held_by.retain(|id| id != &hold_identity);
            if active {
                candidate.held_by.push(hold_identity);
            }
        }
        Ok(true)
    }

    /// Build hold metadata and its canonical delta without publishing either separately.
    fn hold_delta(
        &mut self,
        hold_id: String,
        scope: String,
        target_digest: ContentDigest,
        active: bool,
        at: TimestampNs,
    ) -> Result<(OwnedPackObject, EvidenceDelta), DaemonError> {
        if hold_id.is_empty() || hold_id.len() > 256 || hold_id.chars().any(char::is_control) {
            return Err(DaemonError::InvalidConfig {
                detail: "retention hold identifier must be nonempty and at most 256 bytes"
                    .to_owned(),
            });
        }
        let id_digest = ContentDigest::sha256(hold_id.as_bytes());
        let object_id = ObjectId::parse(format!("obj:retention-hold:{}", id_digest.to_text()))?;
        let (prior_generation, new_generation) = self.next_object_generation(&object_id)?;
        let bytes = ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
            hold_id,
            scope,
            target_digest,
            active,
        })
        .encode_bytes()?;
        let payload_digest = ContentDigest::sha256(&bytes);
        Ok((
            OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, bytes, payload_digest),
            EvidenceDelta {
                delta_id: format!(
                    "delta:retention-hold:{}:{new_generation}",
                    id_digest.to_text()
                ),
                family: FAMILY_EVIDENCE_HOLD.to_owned(),
                object_id,
                prior_generation,
                new_generation,
                validity: CaptureInterval::new(at, at)?,
                plane: Plane::Authority,
                payload_digest,
                witness_digest: Some(target_digest),
                operation_id: None,
            },
        ))
    }

    /// Pin exactly the media roots selected when corroboration commits. Recording the pins
    /// in the same canonical proposal prevents restart from rebinding them to newer footage.
    pub(super) fn append_event_pins(
        &mut self,
        event: &EventHypothesis,
        sensors: &[SensorId],
        proposal: &mut CommitProposal,
    ) -> Result<Vec<(ObjectId, u64)>, DaemonError> {
        if event.state != EventState::Corroborated {
            return Ok(Vec::new());
        }
        let mut targets = BTreeSet::new();
        for sensor in sensors {
            if let Some(latest) = self
                .candidates
                .values()
                .filter(|candidate| candidate.sensor_id == sensor.as_str())
                .max_by_key(|candidate| candidate.capture_end_ns)
                && let Some(target) = latest.object_digests.first()
            {
                targets.insert(*target);
            }
        }
        let snapshot = self.projection.snapshot_latest();
        let scope = format!("{EVENT_HOLD_SCOPE}{}", event.event_id.as_str());
        let mut generations = Vec::new();
        for target in targets {
            let key = ContentDigest::sha256(
                format!("{}\0{}", event.event_id.as_str(), target.to_text()).as_bytes(),
            );
            let hold_id = format!("hold:event-gop:{}", key.to_text());
            if snapshot.get_hold(&hold_id).is_some_and(|hold| {
                hold.active && hold.target_digest == target && hold.scope == scope
            }) {
                continue;
            }
            let (object, delta) =
                self.hold_delta(hold_id, scope.clone(), target, true, event.interval.latest)?;
            generations.push((delta.object_id.clone(), delta.new_generation));
            proposal.objects.push(object);
            proposal.deltas.push(delta);
        }
        Ok(generations)
    }

    /// Materialize active canonical holds, preserving explicit caller-owned candidates.
    /// Legacy GOPs predate durable pins: unknown old hold state is an explicit blocker,
    /// never interpreted as evidence that no hold existed.
    pub(super) fn refresh_retention_pins(&mut self) {
        let snapshot = self.projection.snapshot_latest();
        for candidate in self.candidates.values_mut() {
            candidate
                .held_by
                .retain(|id| id != CATALOG_REFERENCE_BLOCKER);
        }
        let mut by_digest: BTreeMap<ContentDigest, Vec<String>> = BTreeMap::new();
        for (id, root) in &self.candidate_roots {
            if let Some(candidate) = self.candidates.get_mut(id) {
                candidate.held_by.clear();
                candidate.active_event_ids.clear();
                if root.legacy_hold_state {
                    candidate.held_by.push(LEGACY_HOLD_BLOCKER.to_owned());
                }
            }
            by_digest
                .entry(root.media_digest)
                .or_default()
                .push(id.clone());
            by_digest
                .entry(root.metadata_digest)
                .or_default()
                .push(id.clone());
        }
        for hold in snapshot.holds().filter(|hold| hold.active) {
            if let Some(ids) = by_digest.get(&hold.target_digest) {
                for id in ids {
                    if let Some(candidate) = self.candidates.get_mut(id) {
                        if let Some(event_id) = hold.scope.strip_prefix(EVENT_HOLD_SCOPE) {
                            candidate.active_event_ids.push(event_id.to_owned());
                        } else {
                            candidate.held_by.push(hold.hold_id.clone());
                        }
                    }
                }
            }
        }
        for candidate in self.candidates.values_mut() {
            candidate.held_by.sort();
            candidate.held_by.dedup();
            candidate.active_event_ids.sort();
            candidate.active_event_ids.dedup();
        }
    }

    /// Before an eviction pass, protect source closures also referenced by live catalog
    /// roots outside this owner's candidate inventory. This scan is paged and is skipped
    /// when no candidate would otherwise be evicted.
    pub(super) fn refresh_catalog_reference_pins(&mut self) -> Result<(), DaemonError> {
        let mut referenced = BTreeSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self.pack_store.list_live_roots(cursor.as_deref(), 512)?;
            for entry in page.entries {
                if !self.candidates.contains_key(&entry.record.root_id) {
                    referenced.insert(entry.record.root_digest);
                    if let Some(digest) = entry.record.metadata_digest {
                        referenced.insert(digest);
                    }
                }
            }
            if !page.has_more {
                break;
            }
            let next = page.next_cursor.ok_or_else(|| DaemonError::InvalidConfig {
                detail: "retention reference scan omitted its continuation cursor".to_owned(),
            })?;
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(DaemonError::InvalidConfig {
                    detail: "retention reference scan did not advance".to_owned(),
                });
            }
            cursor = Some(next);
        }
        for (id, candidate) in &mut self.candidates {
            if candidate
                .object_digests
                .iter()
                .any(|digest| referenced.contains(digest))
                || self
                    .candidate_roots
                    .get(id)
                    .is_some_and(|root| referenced.contains(&root.metadata_digest))
            {
                candidate.held_by.push(CATALOG_REFERENCE_BLOCKER.to_owned());
                candidate.held_by.sort();
                candidate.held_by.dedup();
            }
        }
        Ok(())
    }

    /// Reconcile an interrupted physical tombstone batch in this running owner. Roots
    /// already durably retired must not be planned again with a different reason digest.
    pub(super) fn synchronize_retired_roots(&mut self) -> Result<(), DaemonError> {
        let mut retired = Vec::new();
        for (id, root) in &self.candidate_roots {
            if self
                .pack_store
                .get_root(id)?
                .is_some_and(|entry| matches!(entry.status, RootStatus::Tombstoned { .. }))
            {
                if !root.legacy_hold_state
                    && !self
                        .pending_deletions
                        .iter()
                        .any(|pending| pending.root_id == *id)
                {
                    self.pending_deletions.push(RetiredRoot {
                        root_id: id.clone(),
                        media_digest: root.media_digest,
                        metadata_digest: Some(root.metadata_digest),
                    });
                }
                retired.push(id.clone());
            }
        }
        for id in retired {
            self.candidate_roots.remove(&id);
            self.candidates.remove(&id);
        }
        Ok(())
    }

    /// Complete only canonical retirements that are still unheld at this authority anchor.
    /// Storage open or the maintenance/forwarding gate keeps the owned writers quiescent.
    /// Bytes awaiting a later hold release remain in protected capacity accounting.
    pub(super) fn resume_pending_retention_deletions(&mut self) -> Result<(), DaemonError> {
        let snapshot = self.projection.snapshot_latest();
        let held: BTreeSet<_> = snapshot
            .holds()
            .filter(|hold| hold.active)
            .map(|hold| hold.target_digest)
            .collect();
        let retained: BTreeSet<_> = self
            .candidates
            .values()
            .flat_map(|candidate| candidate.object_digests.iter().copied())
            .collect();
        let mut completed = BTreeSet::new();
        for root in &self.pending_deletions {
            // An object tombstone is already irreversible. Repair any index removal
            // interrupted after its fsync, without granting a new deletion.
            if self
                .pack_store
                .object_tombstone(&root.media_digest)?
                .is_some()
            {
                let _ = self
                    .pack_store
                    .resume_root_object_deletion(&root.root_id, root.media_digest)?;
                completed.insert(root.root_id.clone());
                continue;
            }
            if snapshot.get_footage_import(&root.media_digest).is_some()
                || held.contains(&root.media_digest)
                || root
                    .metadata_digest
                    .is_some_and(|digest| held.contains(&digest))
                || retained.contains(&root.media_digest)
            {
                continue;
            }
            let _ = self
                .pack_store
                .resume_root_object_deletion(&root.root_id, root.media_digest)?;
            if self
                .pack_store
                .object_tombstone(&root.media_digest)?
                .is_some()
            {
                completed.insert(root.root_id.clone());
            }
        }
        self.pending_deletions
            .retain(|root| !completed.contains(&root.root_id));
        Ok(())
    }

    /// Bytes outside recoverable media closures (including all canonical history payloads)
    /// count as protected storage, rather than disappearing from capacity accounting.
    fn protected_payload_bytes(&self) -> Result<u64, DaemonError> {
        let mut digests = BTreeSet::new();
        let mut media_bytes = 0_u64;
        for root in self.candidate_roots.values() {
            if digests.insert(root.media_digest)
                && let Some(location) = self.pack_store.lookup(&root.media_digest)?
            {
                media_bytes = media_bytes.saturating_add(location.len);
            }
        }
        let logical_protected = self
            .pack_store
            .telemetry_snapshot()?
            .total_payload_bytes
            .saturating_sub(media_bytes);
        let physical_protected = self
            .pack_store
            .on_disk_pack_bytes()?
            .saturating_sub(media_bytes);
        Ok(logical_protected.max(physical_protected))
    }

    pub(super) fn accounted_ring_bytes(&self) -> Result<u64, DaemonError> {
        Ok(self
            .candidates
            .values()
            .fold(self.protected_payload_bytes()?, |bytes, candidate| {
                bytes.saturating_add(candidate.byte_size)
            }))
    }

    pub(super) fn retention_plan_candidates(&self) -> Result<Vec<RetentionCandidate>, DaemonError> {
        let mut candidates: Vec<_> = self.candidates.values().cloned().collect();
        let protected = self.protected_payload_bytes()?;
        if protected > 0 {
            candidates.push(RetentionCandidate {
                import_id: HISTORY_CANDIDATE.to_owned(),
                sensor_id: HISTORY_CANDIDATE.to_owned(),
                capture_end_ns: TimestampNs(0),
                byte_size: protected,
                object_digests: Vec::new(),
                is_derived_proxy: false,
                held_by: vec!["retention:canonical-replay-inputs".to_owned()],
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            });
        }
        Ok(candidates)
    }

    /// Retire indexed footage in bounded canonical batches before any physical tombstone.
    /// A restart after the canonical commit recovers still-live roots and safely retries
    /// pack cleanup; already-retired rows do not create duplicate semantic retirements.
    pub(super) fn commit_retention_deletions(
        &mut self,
        batch: &RetentionEvictionBatch,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<u64, DaemonError> {
        let evicted: BTreeSet<_> = batch
            .tombstones
            .iter()
            .map(|t| t.import_id.as_str())
            .collect();
        let retained: BTreeSet<_> = self
            .candidates
            .iter()
            .filter(|(id, _)| !evicted.contains(id.as_str()))
            .flat_map(|(_, candidate)| candidate.object_digests.iter().copied())
            .collect();
        let snapshot = self.projection.snapshot_latest();
        let targets: BTreeSet<_> = batch
            .tombstones
            .iter()
            .filter_map(|t| self.candidate_roots.get(&t.import_id))
            .map(|root| root.media_digest)
            .filter(|digest| {
                !retained.contains(digest) && snapshot.get_footage_import(digest).is_some()
            })
            .collect();
        let targets: Vec<_> = targets.into_iter().collect();
        for chunk in targets.chunks(256) {
            let mut objects = Vec::with_capacity(chunk.len());
            let mut deltas = Vec::with_capacity(chunk.len());
            let mut generations = Vec::with_capacity(chunk.len());
            for target in chunk {
                let bytes = ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                    target: DeletionTarget::FootageImport(*target),
                })
                .encode_bytes()?;
                let digest = ContentDigest::sha256(&bytes);
                let object_id =
                    ObjectId::parse(format!("obj:retention-delete:{}", target.to_text()))?;
                let (prior_generation, new_generation) = self.next_object_generation(&object_id)?;
                generations.push((object_id.clone(), new_generation));
                objects.push(OwnedPackObject::with_digest(
                    PACK_KIND_METADATA,
                    0,
                    bytes,
                    digest,
                ));
                deltas.push(EvidenceDelta {
                    delta_id: format!(
                        "delta:retention-delete:{}:{new_generation}",
                        target.to_text()
                    ),
                    family: FAMILY_DELETION_TOMBSTONE.to_owned(),
                    object_id,
                    prior_generation,
                    new_generation,
                    validity: CaptureInterval::new(batch.evaluated_at_ns, batch.evaluated_at_ns)?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: Some(batch.batch_digest()),
                    operation_id: None,
                });
            }
            let mut request = fss_core::CanonicalEncoder::new();
            request.text("fss.daemon.retention-delete-request.v1");
            request.digest(batch.batch_digest());
            for delta in &deltas {
                request.text(&delta.delta_id);
                request.digest(delta.payload_digest);
            }
            let request_digest = ContentDigest::sha256(&request.finish_checked()?);
            self.combiner.submit_with_authority(
                cx,
                tree,
                CommitProposal {
                    request_digest,
                    sensor_scope: "retention:delete".to_owned(),
                    objects,
                    deltas,
                    batch_id_prefix: "retention-delete".to_owned(),
                },
            )?;
            for (id, generation) in generations {
                self.record_object_generation(id, generation)?;
            }
        }
        Ok(self.projection.head_anchor().commit_sequence)
    }
}
