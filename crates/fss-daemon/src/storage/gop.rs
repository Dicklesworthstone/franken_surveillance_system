#![forbid(unsafe_code)]
//! Recoverable GOP publication: buffer, canonical commit, then catalog publication.
//!
//! A rejected pre-commit flush keeps its source frames. An acknowledged canonical commit is
//! never submitted again to repair a catalog failure. On reopen, canonical import metadata
//! supplies the publication intent for a root that was interrupted after the ledger commit.

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::{ClockBasis, ObjectRevision};
use fss_pack::{
    DEFAULT_MAX_OBJECT_BYTES, MEDIA_FRAME_FLAG_DISCONTINUITY, MEDIA_FRAME_FLAG_KEYFRAME,
    MediaChunkBuilder, MediaChunkView, PackReadBudget, RootStatus, VirtualRootRecord,
};
use fss_projection_store::{
    CanonicalBatchSource, CombinerError, FAMILY_FOOTAGE_IMPORT, FootageImportPayload,
};

use crate::manifest::CameraAdapterKind;
use crate::storage_types::map_footage_adapter;

use super::*;

const MAX_GOP_METADATA_BYTES: u64 = 64 * 1024;

pub(super) struct PendingGopPublication {
    root: VirtualRootRecord,
    object_id: ObjectId,
    object_generation: u64,
    media_bytes: u64,
    receipt: StorageCommitReceipt,
    reopen_required: bool,
}

/// The caller may release its source reference only after storage accepts ownership.
#[must_use]
pub(crate) struct FrameIngestOutcome {
    pub(crate) accepted: bool,
    pub(crate) result: Result<Option<StorageCommitReceipt>, DaemonError>,
}

impl StorageEngine {
    /// Buffers one frame toward the camera's coarse-grained FSMC GOP chunk, flushing once
    /// `gop_frames` is reached or a new stream generation begins.
    ///
    /// A flush failure keeps buffered frames or the acknowledged publication receipt. Retry
    /// `flush_camera_gop` to finish that work; an indeterminate commit requires storage reopen.
    pub fn ingest_frame(
        &mut self,
        frame: Arc<CameraFrame>,
        adapter: CameraAdapterKind,
        gop_frames: usize,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<Option<StorageCommitReceipt>, DaemonError> {
        self.ingest_frame_with_outcome(frame, adapter, gop_frames, cx, tree)
            .result
    }

    /// Reports the handoff independently from a later flush failure, so the ring can retain
    /// every frame that storage has not yet accepted.
    pub(crate) fn ingest_frame_with_outcome(
        &mut self,
        frame: Arc<CameraFrame>,
        adapter: CameraAdapterKind,
        gop_frames: usize,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> FrameIngestOutcome {
        let mut accepted = false;
        let result = self.ingest_frame_inner(frame, adapter, gop_frames, cx, tree, &mut accepted);
        FrameIngestOutcome { accepted, result }
    }

    fn ingest_frame_inner(
        &mut self,
        frame: Arc<CameraFrame>,
        adapter: CameraAdapterKind,
        gop_frames: usize,
        cx: &AuthorityCx,
        tree: &RegionTree,
        accepted: &mut bool,
    ) -> Result<Option<StorageCommitReceipt>, DaemonError> {
        let sensor_id = frame.sensor_id.clone();
        let mut receipt = if self.pending_gop_publications.contains_key(&sensor_id)
            || !self.indeterminate_gop_commits.is_empty()
        {
            self.flush_camera_gop(&sensor_id, adapter, cx, tree)?
        } else {
            None
        };
        if self.is_quota_pinned() {
            return Err(DaemonError::StorageQuotaPinned {
                pinned_bytes: self.pinned_bytes.load(Ordering::Acquire),
                cap_bytes: self.retention_config.max_total_deployment_bytes,
            });
        }
        // Do not grow a full GOP whose previous flush was rejected.
        let needs_flush = self.gop_buffers.get(&sensor_id).is_some_and(|buf| {
            buf.len() >= gop_frames.max(1)
                || buf
                    .first()
                    .is_some_and(|first| first.stream_generation != frame.stream_generation)
        });
        if needs_flush {
            receipt = self.flush_camera_gop(&sensor_id, adapter, cx, tree)?;
        }
        let buf = self.gop_buffers.entry(sensor_id.clone()).or_default();
        buf.push(frame);
        *accepted = true;
        if buf.len() >= gop_frames.max(1) {
            receipt = self.flush_camera_gop(&sensor_id, adapter, cx, tree)?;
        }
        Ok(receipt)
    }

    /// Commits a buffered GOP and completes its root publication without discarding rejected
    /// source frames or re-appending a canonical import after acknowledged commit.
    pub fn flush_camera_gop(
        &mut self,
        sensor_id: &SensorId,
        adapter: CameraAdapterKind,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<Option<StorageCommitReceipt>, DaemonError> {
        if let Some(indeterminate_sensor) = self.indeterminate_gop_commits.first() {
            return Err(indeterminate_commit_error(indeterminate_sensor));
        }
        // Check authority before any buffer mutation. This refusal is known to be pre-commit.
        if cx.is_cancel_requested(tree)? {
            return Err(CombinerError::Cancelled.into());
        }
        if self.pending_gop_publications.contains_key(sensor_id) {
            return self.finish_gop_publication(sensor_id).map(Some);
        }
        let Some(frames) = self
            .gop_buffers
            .get(sensor_id)
            .filter(|buf| !buf.is_empty())
        else {
            return Ok(None);
        };
        if self.is_quota_pinned() {
            return Err(DaemonError::StorageQuotaPinned {
                pinned_bytes: self.pinned_bytes.load(Ordering::Acquire),
                cap_bytes: self.retention_config.max_total_deployment_bytes,
            });
        }
        // Clone only Arc handles; original source and pixel allocations stay shared and owned
        // by the buffer until the commit owner confirms their durable publication.
        let frames = frames.clone();
        let first = &frames[0];
        let mut builder = MediaChunkBuilder::new(
            first.stream_id.as_str(),
            first.codec,
            ClockBasis::HostMonotonic,
        )?;
        for frame in &frames {
            let mut flags = 0_u16;
            if frame.is_keyframe {
                flags |= MEDIA_FRAME_FLAG_KEYFRAME;
            }
            if frame.discontinuity_before {
                flags |= MEDIA_FRAME_FLAG_DISCONTINUITY;
            }
            let _ = builder.push_frame(
                frame.sequence,
                TimestampNs(frame.host_receive_ns),
                flags,
                &frame.encoded_payload,
            )?;
        }
        let chunk = builder.build()?;
        let interval = CaptureInterval::new(chunk.window_start_ns, chunk.window_end_ns)?;
        let import_payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
            import_id: chunk.chunk_digest,
            adapter_kind: map_footage_adapter(adapter),
            sensor_id: sensor_id.clone(),
            stream_id: first.stream_id.clone(),
            capture_interval: interval,
            manifest_digest: chunk.chunk_digest,
            capsule_count: chunk.frame_count as u64,
            total_bytes: chunk.bytes.len() as u64,
            adapter_id: format!("adapter:{}", adapter.as_str()),
            adapter_generation: format!("gen:{}", first.stream_generation),
            completed: true,
        });
        let proj_bytes = import_payload.encode_bytes()?;
        let proj_digest = ContentDigest::sha256(&proj_bytes);
        let total_accounted = (chunk.bytes.len() as u64).saturating_add(proj_bytes.len() as u64);
        let media_bytes = chunk.bytes.len() as u64;
        let chunk_seq = self.alloc_chunk_seq();
        let root_id = format!(
            "gop:{}:{}:{chunk_seq}",
            sanitize_object_part(sensor_id.as_str()),
            first.stream_generation
        );
        let object_id = ObjectId::parse(format!("obj:footage:{root_id}"))?;
        let (prior_gen, new_gen) = self.next_object_generation(&object_id)?;
        // Finish all fallible descriptor construction before the canonical commit.
        let root = VirtualRootRecord::new(
            root_id,
            chunk.chunk_digest,
            "media-gop-v2",
            chunk.frame_count as u64,
            total_accounted,
            1,
            chunk.window_end_ns,
            Some(proj_digest),
        )?;
        let delta = EvidenceDelta {
            delta_id: format!("delta:footage:{chunk_seq}"),
            family: FAMILY_FOOTAGE_IMPORT.to_owned(),
            object_id: object_id.clone(),
            prior_generation: prior_gen,
            new_generation: new_gen,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: proj_digest,
            witness_digest: Some(chunk.chunk_digest),
            operation_id: None,
        };
        let proposal = CommitProposal {
            request_digest: chunk.chunk_digest,
            sensor_scope: sensor_id.as_str().to_owned(),
            objects: vec![
                OwnedPackObject::with_digest(
                    PACK_KIND_MEDIA_CHUNK,
                    0,
                    chunk.bytes,
                    chunk.chunk_digest,
                ),
                OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, proj_bytes, proj_digest),
            ],
            deltas: vec![delta],
            batch_id_prefix: format!("gop-{chunk_seq}"),
        };
        let committed = match self.combiner.submit_with_authority(cx, tree, proposal) {
            Ok(receipt) => receipt,
            Err(err) => {
                // The combiner may have appended the ledger before a projection/fsync error.
                // Its opaque sink error cannot certify rollback. Keep the source, refuse
                // blind retry, and let reopen replay the authoritative ledger.
                if !definitely_precommit(&err) {
                    self.indeterminate_gop_commits.insert(sensor_id.clone());
                }
                return Err(err.into());
            }
        };
        self.pending_gop_publications.insert(
            sensor_id.clone(),
            PendingGopPublication {
                root,
                object_id,
                object_generation: new_gen,
                media_bytes,
                receipt: receipt_from_coalesced(committed),
                reopen_required: false,
            },
        );
        self.gop_buffers.remove(sensor_id);
        self.finish_gop_publication(sensor_id).map(Some)
    }

    fn finish_gop_publication(
        &mut self,
        sensor_id: &SensorId,
    ) -> Result<StorageCommitReceipt, DaemonError> {
        let pending = self
            .pending_gop_publications
            .get(sensor_id)
            .ok_or_else(|| DaemonError::InvalidConfig {
                detail: "missing acknowledged GOP publication receipt".to_owned(),
            })?;
        if pending.reopen_required {
            return Err(CombinerError::SinkFailure(
                "GOP canonical commit is acknowledged but catalog publication is indeterminate; reopen storage to reconcile before retry".to_owned(),
            )
            .into());
        }
        self.record_object_generation(pending.object_id.clone(), pending.object_generation)?;
        // Catalog compaction can fail after root append. An exact live descriptor proves
        // publication already happened; a different or retired root must never be replaced.
        match self.pack_store.get_root(&pending.root.root_id)? {
            Some(existing)
                if existing.record == pending.root
                    && matches!(existing.status, RootStatus::Live) => {}
            Some(_) => {
                return Err(CombinerError::SinkFailure(
                    "GOP publication conflicts with an existing or retired catalog root; reconcile before retry".to_owned(),
                )
                .into());
            }
            None => {
                if let Err(err) = self.pack_store.publish_root(pending.root.clone()) {
                    let visibly_published = self
                        .pack_store
                        .get_root(&pending.root.root_id)
                        .ok()
                        .flatten()
                        .is_some_and(|entry| {
                            entry.record == pending.root && matches!(entry.status, RootStatus::Live)
                        });
                    // A journal write/fsync failure can be indeterminate if rollback also
                    // failed. Reopen, rather than append another uncertain journal record.
                    if !visibly_published
                        && let Some(pending) = self.pending_gop_publications.get_mut(sensor_id)
                    {
                        pending.reopen_required = true;
                    }
                    return Err(err.into());
                }
            }
        }
        let metadata_digest =
            pending
                .root
                .metadata_digest
                .ok_or_else(|| DaemonError::InvalidConfig {
                    detail: "acknowledged GOP publication lacks canonical metadata".to_owned(),
                })?;
        let root_id = pending.root.root_id.clone();
        self.candidate_roots.insert(
            root_id.clone(),
            RetainedRoot {
                media_digest: pending.root.root_digest,
                metadata_digest,
                legacy_hold_state: false,
            },
        );
        self.candidates.insert(
            root_id.clone(),
            RetentionCandidate {
                import_id: root_id,
                sensor_id: sensor_id.as_str().to_owned(),
                capture_end_ns: pending.root.created_at_ns,
                byte_size: pending.media_bytes,
                object_digests: vec![pending.root.root_digest],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        );
        let receipt = pending.receipt.clone();
        self.pending_gop_publications.remove(sensor_id);
        Ok(receipt)
    }
}

fn definitely_precommit(error: &CombinerError) -> bool {
    matches!(
        error,
        CombinerError::InvalidConfig(_)
            | CombinerError::InvalidProposal(_)
            | CombinerError::QueueFull { .. }
            | CombinerError::DuplicateObjectInProposal { .. }
            | CombinerError::GenerationConflict { .. }
            | CombinerError::Cancelled
            | CombinerError::Shutdown
    )
}

fn indeterminate_commit_error(sensor_id: &SensorId) -> DaemonError {
    CombinerError::SinkFailure(format!(
        "GOP commit outcome for {} is indeterminate; reopen storage and replay the canonical ledger before retry",
        sensor_id.as_str()
    ))
    .into()
}

/// Complete only daemon GOP publication intents already recorded in canonical history.
/// This does not append ledger deltas, reinterpret imported bytes, or revive retired evidence.
pub(super) fn recover_unpublished_gops(
    packs: &PackStore,
    canonical: &BTreeMap<ObjectId, ObjectRevision>,
    projection: &MvccProjectionStore,
    ledger: &MerkleEpochLedger,
) -> Result<(), DaemonError> {
    let snapshot = projection.snapshot_latest();
    for (object_id, revision) in canonical {
        let Some(root_id) = object_id.as_str().strip_prefix("obj:footage:gop:") else {
            continue;
        };
        if revision.family != FAMILY_FOOTAGE_IMPORT || revision.plane != Plane::Authority {
            continue;
        }
        let root_id = format!("gop:{root_id}");
        let invalid = || DaemonError::InvalidConfig {
            detail: format!("cannot recover committed GOP publication {root_id}"),
        };
        // An existing root owns its immutable lifecycle, including permanent tombstones.
        // A colliding live descriptor is corruption, not successful recovery.
        if let Some(existing) = packs.get_root(&root_id)? {
            if matches!(existing.status, RootStatus::Live)
                && (existing.record.metadata_digest != Some(revision.payload_digest)
                    || !matches!(
                        existing.record.kind.as_str(),
                        "media-gop-v1" | "media-gop-v2"
                    ))
            {
                return Err(invalid());
            }
            continue;
        }
        let metadata = packs.read_verified_with_budget(
            &revision.payload_digest,
            &PackReadBudget::new(MAX_GOP_METADATA_BYTES),
        )?;
        let ProjectionRecordPayload::FootageImport(import) =
            ProjectionRecordPayload::decode_bytes(&metadata)?
        else {
            return Err(invalid());
        };
        // Canonical retirement removes the active import. Historical metadata alone cannot
        // grant renewed retention or disclosure, even if the catalog tail is absent.
        let Some(active_import) = snapshot.get_footage_import(&import.import_id) else {
            continue;
        };
        // Projection rows are keyed by content digest. An older root can share bytes with
        // a later import, including a reimport after retirement. Only the object intent
        // in the currently visible import's exact canonical batch can regain a root.
        let batches = ledger.read_batches_range(
            active_import.committed_sequence,
            active_import.committed_sequence,
        )?;
        let [batch] = batches.as_slice() else {
            return Err(invalid());
        };
        if !batch.deltas.iter().any(|delta| {
            delta.object_id == *object_id
                && delta.payload_digest == revision.payload_digest
                && delta.new_generation == revision.generation
                && delta.family == FAMILY_FOOTAGE_IMPORT
                && delta.plane == Plane::Authority
        }) {
            continue;
        }
        let generation = import
            .adapter_generation
            .strip_prefix("gen:")
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|generation| *generation != 0)
            .ok_or_else(invalid)?;
        let expected_prefix = format!(
            "gop:{}:{generation}:",
            sanitize_object_part(import.sensor_id.as_str())
        );
        if !root_id
            .strip_prefix(&expected_prefix)
            .and_then(|raw| raw.parse::<u64>().ok())
            .is_some_and(|sequence| sequence != 0)
            || !import.completed
            || import.import_id != import.manifest_digest
            || import.capture_interval != revision.validity
            || packs.object_tombstone(&import.import_id)?.is_some()
            || packs.lookup(&import.import_id)?.is_none_or(|location| {
                location.object_kind != PACK_KIND_MEDIA_CHUNK || location.len != import.total_bytes
            })
        {
            return Err(invalid());
        }
        let source = packs.read_verified_with_budget(
            &import.import_id,
            &PackReadBudget::new(DEFAULT_MAX_OBJECT_BYTES),
        )?;
        let media = MediaChunkView::parse(&source)?;
        media.verify_all_frames()?;
        if media.stream_id() != import.stream_id.as_str()
            || media.frame_count() as u64 != import.capsule_count
            || media.window_start_ns() != import.capture_interval.earliest
            || media.window_end_ns() != import.capture_interval.latest
        {
            return Err(invalid());
        }
        let accounted_bytes = import
            .total_bytes
            .checked_add(metadata.len() as u64)
            .ok_or_else(invalid)?;
        let record = VirtualRootRecord::new(
            root_id,
            import.import_id,
            // The canonical import predates the catalog append and does not record the
            // catalog version. Preserve unknown legacy hold state instead of assuming it
            // was an unheld v2 root; retention applies its explicit recovery blocker.
            "media-gop-v1",
            import.capsule_count,
            accounted_bytes,
            1,
            import.capture_interval.latest,
            Some(revision.payload_digest),
        )?;
        let _ = packs.publish_root(record)?;
    }
    Ok(())
}
