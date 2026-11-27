#![forbid(unsafe_code)]
//! Exact source-retirement intents are immutable children of canonical deletion commits.
//! A staged object or a missing projection row is never recovery authority.

use fss_core::{CanonicalDecode, CanonicalDecoder, DigestAlgorithm, ObjectRevision};
use fss_pack::{DeletionTombstone, EvictionReason, VirtualRootRecord};

use super::*;

pub(super) const RETENTION_INTENT_PREFIX: &str = "obj:retention-delete:v2:";
pub(super) const PENDING_RETIREMENT_BLOCKER: &str = "retention:committed-intent-pending";
pub(super) const UNPROVEN_RETIREMENT_BLOCKER: &str = "retention:missing-canonical-intent";
const INTENT_DOMAIN: &str = "fss.daemon.retention_intent.v1";
const INTENT_MAGIC: &[u8] = b"FSDR";
const INTENT_VERSION: u32 = 1;
const MAX_INTENT_ROOTS: usize = 256;
const MAX_INTENT_BYTES: u64 = 256 * 1024;
const MAX_PENDING_INTENTS: usize = 65_536;
const MAX_PENDING_INTENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntendedRoot {
    record: VirtualRootRecord,
    sensor_id: String,
    media_bytes: u64,
    reason: EvictionReason,
    reason_digest: ContentDigest,
}

/// A single source target's exact original catalog retirement scope. A committed prefix of
/// a multi-wave canonical retirement can recover without granting the uncommitted suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetentionIntent {
    pub(super) source: ContentDigest,
    original_batch: ContentDigest,
    object_reason: ContentDigest,
    pub(super) evaluated_at: TimestampNs,
    roots: Vec<IntendedRoot>,
}

fn invalid_intent(detail: &'static str) -> DaemonError {
    CombinerError::InvalidProposal(detail).into()
}

impl RetentionIntent {
    fn validate(&self) -> Result<(), DaemonError> {
        if self.source.algorithm() != DigestAlgorithm::Sha256
            || self.original_batch.algorithm() != DigestAlgorithm::Sha256
            || self.object_reason.algorithm() != DigestAlgorithm::Sha256
            || self.roots.is_empty()
            || self.roots.len() > MAX_INTENT_ROOTS
        {
            return Err(invalid_intent(
                "retention intent digest or root bounds are invalid",
            ));
        }
        let mut previous: Option<&str> = None;
        let mut total = 0_u64;
        for root in &self.roots {
            root.record.validate()?;
            let record = &root.record;
            if record.kind != "media-gop-v2"
                || !record.root_id.starts_with("gop:")
                || record.root_digest != self.source
                || record.metadata_digest.is_none()
                || record.metadata_digest == Some(self.source)
                || root.media_bytes == 0
                || record.total_payload_bytes <= root.media_bytes
                || previous.is_some_and(|id| id >= record.root_id.as_str())
            {
                return Err(invalid_intent(
                    "retention intent does not name an exact ordered GOP closure",
                ));
            }
            let _ = SensorId::parse(root.sensor_id.clone())?;
            // Recompute the original planner rationale, never a fresh policy decision.
            let mut reason = CanonicalEncoder::new();
            reason.text("fss.canonical.v1");
            reason.text(fss_pack::PACK_RETENTION_EVICTION_BATCH_DOMAIN);
            reason.text(&record.root_id);
            reason.tag(root.reason.to_tag());
            self.evaluated_at.encode_canonical(&mut reason);
            if ContentDigest::sha256(&reason.finish_checked()?) != root.reason_digest {
                return Err(invalid_intent(
                    "retention intent reason differs from its original decision",
                ));
            }
            total = total
                .checked_add(root.media_bytes)
                .ok_or_else(|| invalid_intent("retention intent byte accounting overflow"))?;
            previous = Some(&record.root_id);
        }
        if !self
            .roots
            .iter()
            .any(|root| root.reason_digest == self.object_reason)
        {
            return Err(invalid_intent(
                "retention intent object reason is outside its original roots",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, DaemonError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.bytes(INTENT_MAGIC);
        encoder.u32(INTENT_VERSION);
        encoder.text(INTENT_DOMAIN);
        encoder.digest(self.source);
        encoder.digest(self.original_batch);
        encoder.digest(self.object_reason);
        self.evaluated_at.encode_canonical(&mut encoder);
        encoder.u64(self.roots.len() as u64);
        for root in &self.roots {
            root.record.encode_canonical(&mut encoder);
            encoder.text(&root.sensor_id);
            encoder.u64(root.media_bytes);
            encoder.tag(root.reason.to_tag());
            encoder.digest(root.reason_digest);
        }
        let bytes = encoder.finish_checked()?;
        if bytes.len() as u64 > MAX_INTENT_BYTES {
            return Err(invalid_intent("retention intent exceeds its byte bound"));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DaemonError> {
        if bytes.len() as u64 > MAX_INTENT_BYTES {
            return Err(invalid_intent("retention intent exceeds its byte bound"));
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.bytes()? != INTENT_MAGIC
            || decoder.u32()? != INTENT_VERSION
            || decoder.text()? != INTENT_DOMAIN
        {
            return Err(invalid_intent("unsupported retention intent format"));
        }
        let source = decoder.digest()?;
        let original_batch = decoder.digest()?;
        let object_reason = decoder.digest()?;
        let evaluated_at = TimestampNs::decode_canonical(&mut decoder)?;
        let count = decoder.u64()?;
        if count == 0 || count > MAX_INTENT_ROOTS as u64 {
            return Err(invalid_intent(
                "retention intent root count exceeds its bound",
            ));
        }
        let mut roots = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let record = VirtualRootRecord::decode_canonical(&mut decoder)?;
            let sensor_id = decoder.text()?.to_owned();
            let media_bytes = decoder.u64()?;
            let reason = match decoder.tag()? {
                1 => EvictionReason::ExpiredHotWindow,
                2 => EvictionReason::SensorQuotaExceeded,
                3 => EvictionReason::DeploymentPressureProxyShed,
                4 => EvictionReason::DeploymentQuotaExceeded,
                _ => return Err(invalid_intent("unknown retention intent reason")),
            };
            roots.push(IntendedRoot {
                record,
                sensor_id,
                media_bytes,
                reason,
                reason_digest: decoder.digest()?,
            });
        }
        decoder.ensure_finished()?;
        let intent = Self {
            source,
            original_batch,
            object_reason,
            evaluated_at,
            roots,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub(in crate::storage) fn root_ids(&self) -> impl Iterator<Item = &str> {
        self.roots.iter().map(|root| root.record.root_id.as_str())
    }

    /// This execution proof covers only the committed source sub-intent. It does not
    /// assert completion of the whole original plan or a new canonical ledger transaction.
    fn execution_batch(&self) -> RetentionEvictionBatch {
        let total = self.roots.iter().map(|root| root.media_bytes).sum();
        let mut ordered: Vec<_> = self.roots.iter().collect();
        ordered.sort_by_key(|root| root.reason_digest != self.object_reason);
        RetentionEvictionBatch {
            evaluated_at_ns: self.evaluated_at,
            pressure_before: CapacityPressure::Nominal,
            pressure_after: CapacityPressure::Nominal,
            total_bytes_before: total,
            total_bytes_after: 0,
            pinned_bytes: 0,
            reclaimable_bytes: total,
            proxies_shed_count: 0,
            sources_evicted_count: self.roots.len() as u64,
            accelerate_compaction: false,
            tombstones: ordered
                .into_iter()
                .map(|root| DeletionTombstone {
                    import_id: root.record.root_id.clone(),
                    sensor_id: root.sensor_id.clone(),
                    is_derived_proxy: false,
                    byte_size: root.media_bytes,
                    object_digests: vec![self.source],
                    reason: root.reason,
                    reason_digest: root.reason_digest,
                    evicted_at_ns: self.evaluated_at,
                })
                .collect(),
            reclaimable_digests: vec![self.source],
        }
    }

    fn has_surviving_reference(&self, packs: &PackStore) -> Result<bool, DaemonError> {
        let ids: BTreeSet<_> = self.root_ids().collect();
        let mut closure: BTreeSet<_> = self
            .roots
            .iter()
            .filter_map(|root| root.record.metadata_digest)
            .collect();
        closure.insert(self.source);
        let mut cursor: Option<String> = None;
        loop {
            let page = packs.list_live_roots(cursor.as_deref(), 512)?;
            if page.entries.iter().any(|entry| {
                !ids.contains(entry.record.root_id.as_str())
                    && (closure.contains(&entry.record.root_digest)
                        || entry
                            .record
                            .metadata_digest
                            .is_some_and(|metadata| closure.contains(&metadata)))
            }) {
                return Ok(true);
            }
            if !page.has_more {
                return Ok(false);
            }
            let next = page.next_cursor.ok_or_else(|| {
                invalid_intent("retention recovery reference scan omitted its cursor")
            })?;
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(invalid_intent(
                    "retention recovery reference scan did not advance",
                ));
            }
            cursor = Some(next);
        }
    }
}

/// Discover only intents named by committed authority objects. Historical target-only
/// tombstones and arbitrary staged bytes are intentionally not upgraded into authority.
pub(in crate::storage) fn recover_retention_intents(
    packs: &PackStore,
    canonical: &BTreeMap<ObjectId, ObjectRevision>,
) -> Result<BTreeMap<ContentDigest, RetentionIntent>, DaemonError> {
    let mut pending = BTreeMap::new();
    let budget = PackReadBudget::new(MAX_PENDING_INTENT_BYTES);
    for (id, revision) in canonical {
        let Some(encoded_digest) = id.as_str().strip_prefix(RETENTION_INTENT_PREFIX) else {
            continue;
        };
        let digest = ContentDigest::parse(encoded_digest)?;
        if digest.algorithm() != DigestAlgorithm::Sha256
            || revision.family != FAMILY_DELETION_TOMBSTONE
            || revision.plane != Plane::Authority
            || revision.generation != 1
        {
            return Err(invalid_intent(
                "committed retention intent has an invalid authority identity",
            ));
        }
        // Fixed-shape deletion metadata gets a separate small per-record read budget.
        let payload =
            packs.read_verified_with_budget(&revision.payload_digest, &PackReadBudget::new(128))?;
        let ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
            target: DeletionTarget::FootageImport(source),
        }) = ProjectionRecordPayload::decode_bytes(&payload)?
        else {
            return Err(invalid_intent(
                "committed retention intent has another deletion target",
            ));
        };
        if packs.object_tombstone(&source)?.is_some() {
            // PackStore already replays irreversible tombstones into its derived index.
            // Completed history does not accumulate in the pending recovery inventory.
            continue;
        }
        if pending.len() >= MAX_PENDING_INTENTS
            || packs.lookup(&digest)?.is_none_or(|location| {
                location.len > MAX_INTENT_BYTES || location.object_kind != PACK_KIND_METADATA
            })
        {
            return Err(invalid_intent(
                "committed retention intent is missing or exceeds recovery bounds",
            ));
        }
        let bytes = packs.read_verified_with_budget(&digest, &budget)?;
        let intent = RetentionIntent::decode(&bytes)?;
        if intent.source != source
            || revision.validity != CaptureInterval::new(intent.evaluated_at, intent.evaluated_at)?
        {
            return Err(invalid_intent(
                "canonical deletion does not bind its exact retention intent",
            ));
        }
        pending.insert(digest, intent);
    }
    Ok(pending)
}

impl StorageEngine {
    /// Validate every source intent before the first chunk is submitted, preventing a late
    /// format error from stranding a prefix. The caller holds the catalog preparation fence.
    pub(super) fn prepare_retention_intents(
        &self,
        batch: &RetentionEvictionBatch,
        targets: &[ContentDigest],
    ) -> Result<Vec<(ContentDigest, RetentionIntent, Vec<u8>)>, DaemonError> {
        if self.retention_intents.len().saturating_add(targets.len()) > MAX_PENDING_INTENTS {
            return Err(invalid_intent(
                "retention pass exceeds the pending-intent bound",
            ));
        }
        let original_batch = batch.batch_digest();
        let targets: BTreeSet<_> = targets.iter().copied().collect();
        let mut grouped: BTreeMap<ContentDigest, Vec<IntendedRoot>> = BTreeMap::new();
        for tomb in &batch.tombstones {
            let Some(root) = self.candidate_roots.get(&tomb.import_id) else {
                continue;
            };
            if !targets.contains(&root.media_digest) {
                continue;
            }
            let entry = self.pack_store.get_root(&tomb.import_id)?.ok_or_else(|| {
                invalid_intent("retention intent lost its catalog root before commitment")
            })?;
            if !matches!(entry.status, RootStatus::Live)
                || root.legacy_hold_state
                || entry.record.root_digest != root.media_digest
                || entry.record.metadata_digest != Some(root.metadata_digest)
                || tomb.object_digests != [root.media_digest]
                || tomb.is_derived_proxy
                || tomb.evicted_at_ns != batch.evaluated_at_ns
            {
                return Err(invalid_intent(
                    "retention intent differs from its selected GOP closure",
                ));
            }
            grouped
                .entry(root.media_digest)
                .or_default()
                .push(IntendedRoot {
                    record: entry.record,
                    sensor_id: tomb.sensor_id.clone(),
                    media_bytes: tomb.byte_size,
                    reason: tomb.reason,
                    reason_digest: tomb.reason_digest,
                });
        }
        let mut out = Vec::with_capacity(grouped.len());
        let mut identities = BTreeSet::new();
        let mut bytes_total = 0_u64;
        // Deferred earlier groups share the same bounded reopen inventory. Admission
        // accounts for them before any new canonical authority is committed.
        for intent in self.retention_intents.values() {
            bytes_total = bytes_total.saturating_add(intent.encode()?.len() as u64);
            if bytes_total > MAX_PENDING_INTENT_BYTES {
                return Err(invalid_intent(
                    "pending retention intents exceed their recovery byte bound",
                ));
            }
        }
        for (source, mut roots) in grouped {
            let object_reason = roots
                .first()
                .ok_or_else(|| invalid_intent("empty retention source group"))?
                .reason_digest;
            roots.sort_by(|a, b| a.record.root_id.cmp(&b.record.root_id));
            let intent = RetentionIntent {
                source,
                original_batch,
                object_reason,
                evaluated_at: batch.evaluated_at_ns,
                roots,
            };
            let bytes = intent.encode()?;
            bytes_total = bytes_total.saturating_add(bytes.len() as u64);
            if bytes_total > MAX_PENDING_INTENT_BYTES {
                return Err(invalid_intent(
                    "retention pass exceeds its durable intent byte bound",
                ));
            }
            let digest = ContentDigest::sha256(&bytes);
            let id = ObjectId::parse(format!("{RETENTION_INTENT_PREFIX}{}", digest.to_text()))?;
            if !identities.insert(digest)
                || self.retention_intents.contains_key(&digest)
                || self.next_object_generation(&id)?.0.is_some()
            {
                return Err(invalid_intent(
                    "retention intent identity is already committed; resume its exact scope",
                ));
            }
            out.push((digest, intent, bytes));
        }
        Ok(out)
    }

    /// Maintenance holds retention_gate; open has no concurrent writers. A later hold or
    /// reimport defers cleanup without replacing the reason or expanding the original scope.
    pub(in crate::storage) fn resume_committed_retention_intents(
        &mut self,
    ) -> Result<(), DaemonError> {
        if self.retention_reopen_required {
            return Err(CombinerError::SinkFailure(
                "retention commit outcome is indeterminate; reopen storage and replay canonical history before further retention".to_owned(),
            ).into());
        }
        let snapshot = self.projection.snapshot_latest();
        let held: BTreeSet<_> = snapshot
            .holds()
            .filter(|hold| hold.active)
            .map(|hold| hold.target_digest)
            .collect();
        let mut completed = Vec::new();
        for (digest, intent) in &self.retention_intents {
            for root in &intent.roots {
                let entry = self
                    .pack_store
                    .get_root(&root.record.root_id)?
                    .ok_or_else(|| {
                        invalid_intent(
                            "committed retention intent is missing its exact catalog descriptor",
                        )
                    })?;
                if entry.record != root.record
                    || matches!(entry.status, RootStatus::Superseded { .. })
                    || matches!(entry.status, RootStatus::Tombstoned { reason_digest, .. } if reason_digest != root.reason_digest)
                {
                    return Err(invalid_intent(
                        "committed retention intent conflicts with the current root lifecycle",
                    ));
                }
            }
            if self.pack_store.object_tombstone(&intent.source)?.is_some() {
                for root in &intent.roots {
                    self.pack_store
                        .resume_root_object_deletion(&root.record.root_id, intent.source)?;
                }
                completed.push(*digest);
                continue;
            }
            if snapshot.get_footage_import(&intent.source).is_some()
                || held.contains(&intent.source)
                || intent.roots.iter().any(|root| {
                    root.record
                        .metadata_digest
                        .is_some_and(|metadata| held.contains(&metadata))
                        || self
                            .candidates
                            .get(&root.record.root_id)
                            .is_some_and(|candidate| {
                                !candidate.active_obligation_ids.is_empty()
                                    || !candidate.active_event_ids.is_empty()
                                    || candidate.held_by.iter().any(|pin| {
                                        pin != PENDING_RETIREMENT_BLOCKER
                                            && pin != CATALOG_REFERENCE_BLOCKER
                                    })
                            })
                })
            {
                continue;
            }
            let batch = intent.execution_batch();
            let prepared = match self.pack_store.prepare_eviction(&batch) {
                Ok(prepared) => prepared,
                // A newly surviving direct reference is a deferral. Intent structure and
                // exact catalog lifecycle were already checked independently above.
                Err(fss_pack::PackError::RetentionPolicyViolation { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            // Recheck lifecycle after taking the fence: a supersession may have raced
            // the initial inspection, and cannot inherit the old deletion authority.
            for root in &intent.roots {
                let entry = self
                    .pack_store
                    .get_root(&root.record.root_id)?
                    .ok_or_else(|| {
                        invalid_intent("retention root disappeared at its publication boundary")
                    })?;
                if entry.record != root.record
                    || matches!(entry.status, RootStatus::Superseded { .. })
                    || matches!(entry.status, RootStatus::Tombstoned { reason_digest, .. } if reason_digest != root.reason_digest)
                {
                    return Err(invalid_intent(
                        "retention root lifecycle changed at its publication boundary",
                    ));
                }
            }
            // The fence keeps this metadata/source scan and tombstone commit together.
            // Metadata itself remains permanent canonical replay input.
            if intent.has_surviving_reference(&self.pack_store)? {
                continue;
            }
            let _ = prepared.commit(None)?;
            completed.push(*digest);
        }
        for digest in completed {
            if let Some(intent) = self.retention_intents.remove(&digest) {
                for id in intent.root_ids() {
                    self.candidates.remove(id);
                    self.candidate_roots.remove(id);
                    self.pending_deletions.retain(|root| root.root_id != id);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TestDirectory, ingest, manifest, selected_batch, targets};
    use super::*;
    use crate::regions::DaemonRegionTree;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn intent_codec_rejects_truncation_trailing_bytes_unknown_versions_and_bad_bounds() -> TestResult
    {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let batch = selected_batch(&storage)?;
        let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
        let (_, intent, bytes) = &intents[0];
        assert_eq!(RetentionIntent::decode(bytes)?, *intent);
        for cut in 0..bytes.len() {
            assert!(
                RetentionIntent::decode(&bytes[..cut]).is_err(),
                "accepted cut {cut}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(RetentionIntent::decode(&trailing).is_err());
        let mut version = bytes.clone();
        version[15] = 2;
        assert!(RetentionIntent::decode(&version).is_err());
        let mut count = CanonicalEncoder::new();
        count.bytes(INTENT_MAGIC);
        count.u32(INTENT_VERSION);
        count.text(INTENT_DOMAIN);
        count.digest(intent.source);
        count.digest(intent.original_batch);
        count.digest(intent.object_reason);
        intent.evaluated_at.encode_canonical(&mut count);
        count.u64(MAX_INTENT_ROOTS as u64 + 1);
        assert!(RetentionIntent::decode(&count.finish_checked()?).is_err());
        let mut duplicate = intent.clone();
        duplicate.roots.push(duplicate.roots[0].clone());
        assert!(duplicate.encode().is_err());
        let mut reason = intent.clone();
        reason.roots[0].reason_digest = ContentDigest::sha256(b"later policy reason");
        assert!(reason.encode().is_err());
        let mut renamed = intent.clone();
        renamed.roots[0].record.root_id = "gop:other:1:1".to_owned();
        assert!(renamed.encode().is_err());
        storage.shutdown_and_flush()?;
        Ok(())
    }

    #[test]
    fn canonical_intent_cannot_retire_a_substituted_catalog_descriptor() -> TestResult {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let batch = selected_batch(&storage)?;
        let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
        let mut intent = intents[0].1.clone();
        let original = intent.roots[0].record.clone();
        // Even an authentically committed, validly encoded intent cannot apply to a
        // different immutable descriptor merely because root_id and media digest match.
        intent.roots[0].record.generation += 1;
        let bytes = intent.encode()?;
        let chunk = vec![(ContentDigest::sha256(&bytes), intent, bytes)];
        storage.commit_retention_intent_chunk(
            &chunk,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        )?;
        storage.shutdown_and_flush()?;
        assert!(StorageEngine::open(&config, Some(&dir.0)).is_err());
        let packs = PackStore::open(&dir.0, PackConfig::default())?;
        assert!(packs.object_tombstone(&original.root_digest)?.is_none());
        let entry = packs
            .get_root(&original.root_id)?
            .ok_or("missing original root")?;
        assert_eq!(entry.record, original);
        assert!(matches!(entry.status, RootStatus::Live));
        Ok(())
    }

    #[test]
    fn authority_discovery_rejects_missing_child_wrong_target_and_wrong_validity() -> TestResult {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let batch = selected_batch(&storage)?;
        let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
        let (digest, intent, bytes) = &intents[0];
        let payload = ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
            target: DeletionTarget::FootageImport(intent.source),
        })
        .encode_bytes()?;
        let payload_digest = ContentDigest::sha256(&payload);
        storage
            .pack_store
            .append_batch(&[fss_pack::PackObjectInput::with_digest(
                PACK_KIND_METADATA,
                0,
                &payload,
                payload_digest,
            )])?;
        let id = ObjectId::parse(format!("{RETENTION_INTENT_PREFIX}{}", digest.to_text()))?;
        let revision = ObjectRevision {
            generation: 1,
            family: FAMILY_DELETION_TOMBSTONE.to_owned(),
            plane: Plane::Authority,
            payload_digest,
            validity: CaptureInterval::new(intent.evaluated_at, intent.evaluated_at)?,
        };
        let mut inventory = BTreeMap::from([(id.clone(), revision.clone())]);
        assert!(recover_retention_intents(&storage.pack_store, &inventory).is_err());
        storage
            .pack_store
            .append_batch(&[fss_pack::PackObjectInput::with_digest(
                PACK_KIND_METADATA,
                0,
                bytes,
                *digest,
            )])?;
        assert_eq!(
            recover_retention_intents(&storage.pack_store, &inventory)?.len(),
            1
        );
        let mut wrong = revision.clone();
        wrong.validity = CaptureInterval::new(TimestampNs(0), TimestampNs(0))?;
        inventory.insert(id.clone(), wrong);
        assert!(recover_retention_intents(&storage.pack_store, &inventory).is_err());
        let other = ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
            target: DeletionTarget::FootageImport(ContentDigest::sha256(b"other source")),
        })
        .encode_bytes()?;
        let other_digest = ContentDigest::sha256(&other);
        storage
            .pack_store
            .append_batch(&[fss_pack::PackObjectInput::with_digest(
                PACK_KIND_METADATA,
                0,
                &other,
                other_digest,
            )])?;
        let mut wrong = revision.clone();
        wrong.payload_digest = other_digest;
        inventory.insert(id.clone(), wrong);
        assert!(recover_retention_intents(&storage.pack_store, &inventory).is_err());
        let mut wrong = revision;
        wrong.generation = 2;
        inventory.insert(id, wrong);
        assert!(recover_retention_intents(&storage.pack_store, &inventory).is_err());
        assert!(
            storage
                .pack_store
                .object_tombstone(&intent.source)?
                .is_none()
        );
        storage.shutdown_and_flush()?;
        Ok(())
    }
}
