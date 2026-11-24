#![forbid(unsafe_code)]
//! `StorageRegion` orchestrating `PackStore` (`A1`), `MerkleEpochLedger` (`A2`),
//! `MvccProjectionStore` + `CommitCombiner` (`A3`), hold-safe retention ring compaction, and
//! incremental `BackgroundScrubber` (`A4`).
//!
//! Semantic plane: `"authority"`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fss_core::{
    CanonicalEncode, CaptureInterval, ClockBasis, ContentDigest, EventHypothesis, EventState,
    EvidenceDelta, ObjectId, Plane, RegionTree, SensorId, TimestampNs,
};
use fss_ipc::ActiveScrubStatus;
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{
    BackgroundScrubber, CapacityPressure, CompactionPolicy, MEDIA_FRAME_FLAG_DISCONTINUITY,
    MEDIA_FRAME_FLAG_KEYFRAME, MediaChunkBuilder, PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA,
    PackConfig, PackStore, RetentionCandidate, RetentionEvictionBatch, RetentionPlanOutcome,
    RetentionRingConfig, ScrubBudget, VirtualRootRecord, plan_retention,
};
use fss_projection_store::{
    CommitCombiner, CommitCombinerConfig, CommitProposal, CoverageStatus, CoverageWitnessPayload,
    DoctorScrubReceipt, EventRevisionPayload, FAMILY_COVERAGE_WITNESS, FAMILY_EVENT_REVISION,
    FAMILY_FOOTAGE_IMPORT, FAMILY_SENSOR_LIVENESS, FootageImportPayload, LedgerPackProjectionSink,
    MvccProjectionStore, OwnedPackObject, PackStorePayloadResolver, ProjectionRecordPayload,
    ProjectionStore, SensorLivenessPayload, SensorLivenessStatus,
};
use fss_reference::agent_orient::projection_bridge::PROJECTION_SUBDIR;
use fss_reference::migration::DeploymentLayoutV2;
use fss_reference::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, DeploymentLimits,
};
use fss_runtime::authority::AuthorityCx;

use crate::control::ForwardBatchWriter;
use crate::error::DaemonError;
use crate::manifest::{CameraAdapterKind, SiteManifest};
use crate::sensor::CameraFrame;
use crate::storage_types::{
    CombinerForwardWriter, map_footage_adapter, map_scrub_verdict, sanitize_object_part,
    scrub_report_to_ipc_status,
};
pub use crate::storage_types::{
    MaintenanceTickReport, StorageCommitReceipt, StorageHeadSnapshot, StorageShutdownSummary,
};

/// Authority-plane storage engine owning v2 packs, segmented Merkle epochs, MVCC projections,
/// group-commit coalescing, hold-safe ring compaction, and incremental scrubbing.
pub struct StorageEngine {
    root_dir: PathBuf,
    site_id: String,
    pack_store: Arc<PackStore>,
    projection: Arc<MvccProjectionStore>,
    combiner: Arc<CommitCombiner<LedgerPackProjectionSink>>,
    object_generations: Arc<Mutex<BTreeMap<ObjectId, u64>>>,
    quota_pinned: Arc<AtomicBool>,
    pinned_bytes: Arc<AtomicU64>,
    retention_config: RetentionRingConfig,
    candidates: BTreeMap<String, RetentionCandidate>,
    gop_buffers: BTreeMap<SensorId, Vec<Arc<CameraFrame>>>,
    scrubber: BackgroundScrubber,
    scrub_budget_bytes: u64,
    last_scrub_status: ActiveScrubStatus,
    pressure: CapacityPressure,
    next_delta_seq: u64,
    next_chunk_seq: u64,
    ingest_paused_reason: Option<&'static str>,
}

impl StorageEngine {
    /// Opens or initializes v2 storage directories (`objects/`, `ledger/`, `projections/mvcc/`,
    /// and canonical v2 `LAYOUT`) under `root_override` (or `manifest.deployment_root`).
    pub fn open(
        manifest: &SiteManifest,
        root_override: Option<&Path>,
    ) -> Result<Self, DaemonError> {
        let root_dir = root_override
            .unwrap_or(&manifest.deployment_root)
            .to_path_buf();
        fs::create_dir_all(&root_dir).map_err(|err| DaemonError::io("create_deploy_root", err))?;

        let layout_path = root_dir.join(DEPLOYMENT_LAYOUT_FILENAME);
        let needs_layout_write = match fs::symlink_metadata(&layout_path) {
            Ok(meta) => {
                if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                    return Err(DaemonError::InvalidConfig {
                        detail: "LAYOUT path exists but is not a regular file".to_owned(),
                    });
                }
                let text = fs::read_to_string(&layout_path)
                    .map_err(|err| DaemonError::io("read_layout", err))?;
                if let Ok(v2) = DeploymentLayoutV2::parse_canonical_text(&text) {
                    if v2.site_lineage != manifest.site_id {
                        return Err(DaemonError::InvalidConfig {
                            detail: format!(
                                "existing v2 LAYOUT site_lineage `{}` does not match manifest site_id `{}`",
                                v2.site_lineage, manifest.site_id
                            ),
                        });
                    }
                    false
                } else if DeploymentLayout::parse_canonical_text(&text).is_ok() {
                    return Err(DaemonError::InvalidConfig {
                        detail: format!(
                            "ERR-DEPLOYMENT-FORMAT-V1-001: deployment root `{}` uses legacy v1 layout; run `fss migrate --from {} --to <new-v2-root>` first",
                            root_dir.display(),
                            root_dir.display()
                        ),
                    });
                } else {
                    return Err(DaemonError::InvalidConfig {
                        detail:
                            "existing LAYOUT matches neither canonical v1 nor canonical v2 schema"
                                .to_owned(),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(err) => return Err(DaemonError::io("stat_layout", err)),
        };

        let pack_cfg = PackConfig {
            target_pack_bytes: manifest.pack_target_bytes,
            ..PackConfig::default()
        };
        let pack_store = Arc::new(PackStore::open(&root_dir, pack_cfg)?);
        let ledger = MerkleEpochLedger::open(
            root_dir.join("ledger"),
            &manifest.site_id,
            EpochLedgerConfig::default(),
            IncompleteTailPolicy::Reject,
        )?;
        let initial_gens: BTreeMap<ObjectId, u64> = ledger
            .snapshot_objects()
            .into_iter()
            .map(|(id, rev)| (id, rev.generation))
            .collect();

        let resolver = PackStorePayloadResolver::new(&pack_store);
        let projection = Arc::new(MvccProjectionStore::open_or_rebuild(
            root_dir.join(PROJECTION_SUBDIR),
            &ledger,
            &resolver,
        )?);
        let effects_path =
            root_dir.join(fss_reference::reference_deployment::RELATIVE_PATH_EFFECTS);
        if let Some(effects_parent) = effects_path.parent() {
            fs::create_dir_all(effects_parent)
                .map_err(|err| DaemonError::io("create_effects_dir", err))?;
        }
        let _effects_journal =
            fss_reference::DurableEffectJournal::open(&effects_path, IncompleteTailPolicy::Reject)
                .map_err(|err| DaemonError::InvalidConfig {
                    detail: format!("failed to initialize v2 effects journal: {err}"),
                })?;
        if needs_layout_write {
            let limits_digest = DeploymentLimits::standard()
                .canonical_digest()
                .map_err(|err| DaemonError::InvalidConfig {
                    detail: format!("deployment limits canonical digest failed: {err}"),
                })?;
            let layout_v2 = DeploymentLayoutV2::new(&manifest.site_id, limits_digest);
            write_layout_v2_atomic(&root_dir, &layout_v2)?;
        }
        let sink =
            LedgerPackProjectionSink::new(ledger, Arc::clone(&pack_store), Arc::clone(&projection));
        let combiner = Arc::new(CommitCombiner::new(sink, CommitCombinerConfig::default())?);

        let retention_config = RetentionRingConfig::new(
            manifest.retain_hot_ns,
            manifest.ring_cap_bytes,
            manifest.ring_cap_bytes,
            manifest.soft_watermark_pct,
            manifest.hard_watermark_pct,
        )?;

        // Seed monotonic chunk & delta sequences strictly past any prior daemon run's
        // committed sequence and published `gop:` root IDs so daemon restarts never collide
        // with existing PackStore virtual roots or ledger delta IDs.
        let head_seq = projection.head_anchor().commit_sequence;
        let mut max_prior_seq = head_seq;
        let mut root_cursor: Option<String> = None;
        for _ in 0..1_024 {
            let page = pack_store.list_roots(root_cursor.as_deref(), 512)?;
            for entry in &page.entries {
                max_prior_seq = max_prior_seq.max(entry.sequence);
                if let Some(rest) = entry.record.root_id.strip_prefix("gop:")
                    && let Some(tail) = rest.rsplit(':').next()
                    && let Ok(parsed) = tail.parse::<u64>()
                {
                    max_prior_seq = max_prior_seq.max(parsed);
                }
            }
            if !page.has_more {
                break;
            }
            root_cursor = page.next_cursor;
        }
        let seed_seq = max_prior_seq.saturating_add(1).max(1);

        Ok(Self {
            root_dir,
            site_id: manifest.site_id.clone(),
            pack_store,
            projection,
            combiner,
            object_generations: Arc::new(Mutex::new(initial_gens)),
            quota_pinned: Arc::new(AtomicBool::new(false)),
            pinned_bytes: Arc::new(AtomicU64::new(0)),
            retention_config,
            candidates: BTreeMap::new(),
            gop_buffers: BTreeMap::new(),
            scrubber: BackgroundScrubber::new(),
            scrub_budget_bytes: manifest.scrub_budget_bytes_per_tick,
            last_scrub_status: ActiveScrubStatus::Idle,
            pressure: CapacityPressure::Nominal,
            next_delta_seq: seed_seq,
            next_chunk_seq: seed_seq,
            ingest_paused_reason: None,
        })
    }

    /// Creates a [`ForwardBatchWriter`] sharing this engine's `CommitCombiner` for IPC forwarding.
    #[must_use]
    pub fn forward_writer(&self) -> Arc<dyn ForwardBatchWriter> {
        Arc::new(CombinerForwardWriter {
            combiner: Arc::clone(&self.combiner),
            object_generations: Arc::clone(&self.object_generations),
            quota_pinned: Arc::clone(&self.quota_pinned),
            pinned_bytes: Arc::clone(&self.pinned_bytes),
            cap_bytes: self.retention_config.max_total_deployment_bytes,
            next_seq: AtomicU64::new(self.next_delta_seq),
        })
    }

    /// Returns the active deployment root directory.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns the site lineage identifier owned by this storage engine.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }

    /// Returns the shared MVCC projection store for read-only anchor-pinned inspection.
    #[must_use]
    pub fn projection(&self) -> &Arc<MvccProjectionStore> {
        &self.projection
    }

    /// Returns the shared sealed packfile store for read-only verification.
    #[must_use]
    pub fn pack_store(&self) -> &Arc<PackStore> {
        &self.pack_store
    }

    /// Returns `true` when critical capacity is 100% pinned and new ingest is paused.
    #[must_use]
    pub fn is_quota_pinned(&self) -> bool {
        self.quota_pinned.load(Ordering::Acquire)
    }

    /// Returns the stable pause error identifier (`ERR-STORAGE-QUOTA-PINNED-001`) if ingest is paused.
    #[must_use]
    pub const fn ingest_paused_reason(&self) -> Option<&'static str> {
        self.ingest_paused_reason
    }

    /// Returns all currently tracked retention candidates in canonical `import_id` order.
    #[must_use]
    pub fn retention_candidates(&self) -> &BTreeMap<String, RetentionCandidate> {
        &self.candidates
    }

    /// Buffers one frame toward the camera's coarse-grained `FSMC` GOP chunk, flushing once
    /// `gop_frames` is reached or a new stream generation begins.
    pub fn ingest_frame(
        &mut self,
        frame: Arc<CameraFrame>,
        adapter: CameraAdapterKind,
        gop_frames: usize,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<Option<StorageCommitReceipt>, DaemonError> {
        if self.is_quota_pinned() {
            return Err(DaemonError::StorageQuotaPinned {
                pinned_bytes: self.pinned_bytes.load(Ordering::Acquire),
                cap_bytes: self.retention_config.max_total_deployment_bytes,
            });
        }
        let sensor_id = frame.sensor_id.clone();
        let gen_changed = self
            .gop_buffers
            .get(&sensor_id)
            .and_then(|buf| buf.first())
            .is_some_and(|first| first.stream_generation != frame.stream_generation);
        let mut receipt = if gen_changed {
            self.flush_camera_gop(&sensor_id, adapter, cx, tree)?
        } else {
            None
        };
        let buf = self.gop_buffers.entry(sensor_id.clone()).or_default();
        buf.push(frame);
        if buf.len() >= gop_frames.max(1) {
            receipt = self.flush_camera_gop(&sensor_id, adapter, cx, tree)?;
        }
        Ok(receipt)
    }

    /// Packs any buffered frames for `sensor_id` into one `FSMC` `MediaChunk` and commits it
    /// atomically through `CommitCombiner` (`PackStore` + `MerkleEpochLedger` + `MvccProjectionStore`).
    pub fn flush_camera_gop(
        &mut self,
        sensor_id: &SensorId,
        adapter: CameraAdapterKind,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<Option<StorageCommitReceipt>, DaemonError> {
        let Some(frames) = self.gop_buffers.remove(sensor_id) else {
            return Ok(None);
        };
        if frames.is_empty() {
            return Ok(None);
        }
        if self.is_quota_pinned() {
            self.gop_buffers.insert(sensor_id.clone(), frames);
            return Err(DaemonError::StorageQuotaPinned {
                pinned_bytes: self.pinned_bytes.load(Ordering::Acquire),
                cap_bytes: self.retention_config.max_total_deployment_bytes,
            });
        }

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

        let chunk_seq = self.alloc_chunk_seq();
        let root_id = format!(
            "gop:{}:{}:{chunk_seq}",
            sanitize_object_part(sensor_id.as_str()),
            first.stream_generation
        );
        let object_id = ObjectId::parse(format!("obj:footage:{root_id}"))?;
        let (prior_gen, new_gen) = self.next_object_generation(&object_id)?;
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
        let committed = self.combiner.submit_with_authority(cx, tree, proposal)?;
        self.record_object_generation(object_id, new_gen)?;

        let root_record = VirtualRootRecord::new(
            root_id.clone(),
            chunk.chunk_digest,
            "media-gop-v1",
            chunk.frame_count as u64,
            total_accounted,
            1,
            chunk.window_end_ns,
            Some(proj_digest),
        )?;
        let _ = self.pack_store.publish_root(root_record)?;
        self.candidates.insert(
            root_id.clone(),
            RetentionCandidate {
                import_id: root_id,
                sensor_id: sensor_id.as_str().to_owned(),
                capture_end_ns: chunk.window_end_ns,
                byte_size: total_accounted,
                object_digests: vec![chunk.chunk_digest, proj_digest],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        );
        Ok(Some(receipt_from_coalesced(committed)))
    }

    /// Atomically commits paired `coverage_witness` and `sensor_liveness` authority deltas.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_coverage_and_liveness(
        &mut self,
        sensor_id: &SensorId,
        zone_id: &str,
        status: CoverageStatus,
        liveness: SensorLivenessStatus,
        active_gaps: u32,
        last_seen_ns: TimestampNs,
        now_ns: TimestampNs,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<StorageCommitReceipt, DaemonError> {
        let start = if last_seen_ns <= now_ns {
            last_seen_ns
        } else {
            now_ns
        };
        let window = CaptureInterval::new(start, now_ns)?;
        let cov_bytes = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
            sensor_id: sensor_id.clone(),
            zone_id: zone_id.to_owned(),
            window,
            status,
            active_gaps,
            health_conflicts: 0,
        })
        .encode_bytes()?;
        let cov_digest = ContentDigest::sha256(&cov_bytes);
        let live_bytes = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
            sensor_id: sensor_id.clone(),
            state: liveness,
            last_seen_ns,
            observed_at_ns: now_ns,
        })
        .encode_bytes()?;
        let live_digest = ContentDigest::sha256(&live_bytes);

        let (s_part, z_part) = (
            sanitize_object_part(sensor_id.as_str()),
            sanitize_object_part(zone_id),
        );
        let cov_obj = ObjectId::parse(format!("obj:coverage:{s_part}:{z_part}"))?;
        let live_obj = ObjectId::parse(format!("obj:liveness:{s_part}"))?;
        let (cov_prior, cov_new) = self.next_object_generation(&cov_obj)?;
        let (live_prior, live_new) = self.next_object_generation(&live_obj)?;
        let seq = self.alloc_delta_seq();
        let req_digest = ContentDigest::sha256(
            format!("{}:{}:{seq}", cov_digest.to_text(), live_digest.to_text()).as_bytes(),
        );
        let proposal = CommitProposal {
            request_digest: req_digest,
            sensor_scope: sensor_id.as_str().to_owned(),
            objects: vec![
                OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, cov_bytes, cov_digest),
                OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, live_bytes, live_digest),
            ],
            deltas: vec![
                EvidenceDelta {
                    delta_id: format!("delta:cov:{seq}"),
                    family: FAMILY_COVERAGE_WITNESS.to_owned(),
                    object_id: cov_obj.clone(),
                    prior_generation: cov_prior,
                    new_generation: cov_new,
                    validity: window,
                    plane: Plane::Authority,
                    payload_digest: cov_digest,
                    witness_digest: None,
                    operation_id: None,
                },
                EvidenceDelta {
                    delta_id: format!("delta:live:{seq}"),
                    family: FAMILY_SENSOR_LIVENESS.to_owned(),
                    object_id: live_obj.clone(),
                    prior_generation: live_prior,
                    new_generation: live_new,
                    validity: window,
                    plane: Plane::Authority,
                    payload_digest: live_digest,
                    witness_digest: None,
                    operation_id: None,
                },
            ],
            batch_id_prefix: format!("cov-{seq}"),
        };
        let committed = self.combiner.submit_with_authority(cx, tree, proposal)?;
        self.record_object_generation(cov_obj, cov_new)?;
        self.record_object_generation(live_obj, live_new)?;
        Ok(receipt_from_coalesced(committed))
    }

    /// Commits a cognition-plane [`EventHypothesis`] revision (`Plane::Cognition`, preserving
    /// Cognition != Authority) and pins recent media closures for corroborated events.
    pub fn commit_event_hypothesis(
        &mut self,
        event: &EventHypothesis,
        sensor_ids: Vec<SensorId>,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<StorageCommitReceipt, DaemonError> {
        let event_root = event.canonical_digest(EventHypothesis::SCHEMA);
        let proj_bytes = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
            event_id: event.event_id.clone(),
            revision: event.revision,
            state: event.state,
            kind: event.kind,
            zones: event.zone_ids.clone(),
            sensor_ids: sensor_ids.clone(),
            interval: event.interval,
            event_root,
            supersedes: event.supersedes,
            corroborated: event.state == EventState::Corroborated,
            tamper_open: false,
        })
        .encode_bytes()?;
        let proj_digest = ContentDigest::sha256(&proj_bytes);

        let obj_id = ObjectId::parse(format!(
            "obj:event:{}",
            sanitize_object_part(event.event_id.as_str())
        ))?;
        let (prior_gen, new_gen) = self.next_object_generation(&obj_id)?;
        let seq = self.alloc_delta_seq();
        let proposal = CommitProposal {
            request_digest: proj_digest,
            sensor_scope: format!("event:{}", event.event_id.as_str()),
            objects: vec![OwnedPackObject::with_digest(
                PACK_KIND_METADATA,
                0,
                proj_bytes,
                proj_digest,
            )],
            deltas: vec![EvidenceDelta {
                delta_id: format!("delta:event:{seq}"),
                family: FAMILY_EVENT_REVISION.to_owned(),
                object_id: obj_id.clone(),
                prior_generation: prior_gen,
                new_generation: new_gen,
                validity: event.interval,
                plane: Plane::Cognition,
                payload_digest: proj_digest,
                witness_digest: Some(event_root),
                operation_id: None,
            }],
            batch_id_prefix: format!("evt-{seq}"),
        };
        let committed = self.combiner.submit_with_authority(cx, tree, proposal)?;
        self.record_object_generation(obj_id, new_gen)?;

        if event.state == EventState::Corroborated {
            let ev_id = event.event_id.as_str().to_owned();
            for sensor in &sensor_ids {
                if let Some(latest) = self
                    .candidates
                    .values_mut()
                    .filter(|c| c.sensor_id == sensor.as_str())
                    .max_by_key(|c| c.capture_end_ns)
                    && !latest.active_event_ids.contains(&ev_id)
                {
                    latest.active_event_ids.push(ev_id.clone());
                }
            }
        }
        Ok(receipt_from_coalesced(committed))
    }

    /// Attaches an active legal/operator hold to an existing retained media closure.
    pub fn pin_candidate_hold(&mut self, import_id: &str, hold_id: impl Into<String>) -> bool {
        if let Some(cand) = self.candidates.get_mut(import_id) {
            let hold = hold_id.into();
            if !cand.held_by.contains(&hold) {
                cand.held_by.push(hold);
            }
            true
        } else {
            false
        }
    }

    /// Registers an explicit retention candidate (e.g., pinned hold closure) into the ring catalog.
    pub fn register_retention_candidate(
        &mut self,
        candidate: RetentionCandidate,
    ) -> Result<(), DaemonError> {
        candidate.validate()?;
        self.candidates
            .insert(candidate.import_id.clone(), candidate);
        Ok(())
    }

    /// Executes one hold-safe retention ring compaction tick and one bounded incremental
    /// `BackgroundScrubber` pass (`A4`).
    pub fn run_maintenance_tick(
        &mut self,
        cx: &AuthorityCx,
        tree: &RegionTree,
        now_ns: TimestampNs,
        force_scrub: bool,
    ) -> Result<MaintenanceTickReport, DaemonError> {
        let candidates_vec: Vec<RetentionCandidate> = self.candidates.values().cloned().collect();
        let outcome = plan_retention(&self.retention_config, &candidates_vec, now_ns)?;
        let head_seq = self.projection.head_anchor().commit_sequence;

        let (mut evicted_imports, mut bytes_reclaimed, mut packs_compacted) = (0_u64, 0_u64, 0_u64);
        let pinned_bytes;
        match outcome {
            RetentionPlanOutcome::NoAction {
                pressure,
                pinned_bytes: pinned,
                ..
            } => {
                self.pressure = pressure;
                self.quota_pinned.store(false, Ordering::Release);
                self.pinned_bytes.store(pinned, Ordering::Release);
                self.ingest_paused_reason = None;
                pinned_bytes = pinned;
            }
            RetentionPlanOutcome::Evict(batch) => {
                self.pressure = batch.pressure_after;
                pinned_bytes = batch.pinned_bytes;
                self.pinned_bytes.store(pinned_bytes, Ordering::Release);
                self.quota_pinned.store(false, Ordering::Release);
                self.ingest_paused_reason = None;
                (evicted_imports, bytes_reclaimed, packs_compacted) =
                    self.execute_eviction_and_compaction(&batch, head_seq)?;
            }
            RetentionPlanOutcome::QuotaPinned {
                error_id,
                pressure,
                pinned_bytes: pinned,
                partial_eviction,
                ..
            } => {
                if let Some(partial) = partial_eviction {
                    (evicted_imports, bytes_reclaimed, packs_compacted) =
                        self.execute_eviction_and_compaction(&partial, head_seq)?;
                }
                self.pressure = pressure;
                pinned_bytes = pinned;
                self.pinned_bytes.store(pinned, Ordering::Release);
                self.quota_pinned.store(true, Ordering::Release);
                self.ingest_paused_reason = Some(error_id);
            }
        }

        let sealed_count = self.pack_store.sealed_pack_ids()?.len();
        let (scrub_report, scrub_status) = if sealed_count > 0 || force_scrub {
            let budget = ScrubBudget {
                max_bytes: self.scrub_budget_bytes.max(1),
                max_packs: 4,
                max_objects: 2_048,
            };
            let report = self.scrubber.scrub_pass_with_authority(
                &self.pack_store,
                cx,
                tree,
                budget,
                now_ns,
            )?;
            let status = scrub_report_to_ipc_status(&report);
            if report.total_sealed_packs > 0 {
                let anchor = self.projection.head_anchor();
                let _ = self.projection.record_scrub_receipt(DoctorScrubReceipt {
                    scrubbed_at_ns: report.scrubbed_at_ns,
                    anchor,
                    first_seq: 0,
                    last_seq: anchor.commit_sequence,
                    verified_objects: report.verified_objects,
                    verified_packs: report.verified_packs,
                    verified_fraction_ppm: report.verified_fraction_ppm,
                    verdict: map_scrub_verdict(report.verdict),
                });
            }
            (Some(report), status)
        } else {
            (None, ActiveScrubStatus::Idle)
        };
        self.last_scrub_status = scrub_status.clone();

        Ok(MaintenanceTickReport {
            pressure: self.pressure,
            quota_pinned: self.is_quota_pinned(),
            pinned_bytes,
            cap_bytes: self.retention_config.max_total_deployment_bytes,
            evicted_imports,
            bytes_reclaimed,
            packs_compacted,
            scrub_report,
            scrub_status,
        })
    }

    /// Captures a point-in-time read-only snapshot of head anchors, pack size, and ring occupancy.
    pub fn head_snapshot(&self) -> Result<StorageHeadSnapshot, DaemonError> {
        let anchor = self.projection.head_anchor();
        Ok(StorageHeadSnapshot {
            commit_sequence: anchor.commit_sequence,
            history_root: anchor.history_root,
            state_root: anchor.authority_root,
            on_disk_pack_bytes: self.pack_store.on_disk_pack_bytes()?,
            ring_used_bytes: self.candidates.values().map(|c| c.byte_size).sum(),
            ring_cap_bytes: self.retention_config.max_total_deployment_bytes,
            pressure: self.pressure,
            quota_pinned: self.is_quota_pinned(),
            scrub_status: self.last_scrub_status.clone(),
        })
    }

    /// Cleanly drains `CommitCombiner`, seals the active packfile, saves the derived index,
    /// emits a verified ledger checkpoint, verifies the full Merkle chain from genesis, and
    /// compacts the MVCC projection snapshot.
    pub fn shutdown_and_flush(self) -> Result<StorageShutdownSummary, DaemonError> {
        let _ = self.combiner.shutdown()?;
        let combiner = Arc::try_unwrap(self.combiner).map_err(|_| DaemonError::ShutdownViolation {
            detail: "CommitCombiner still referenced during storage shutdown (stop ControlPlaneServer first)".to_owned(),
        })?;
        let (mut ledger, pack_store, projection) = combiner.into_sink()?.into_parts();
        let sealed_pack_on_shutdown = pack_store.seal_active_pack()?.is_some();
        let _ = pack_store.save_index_snapshot()?;
        let _ = ledger.force_checkpoint()?;
        let verify = ledger.verify_full_chain()?;
        let projection_snapshot_bytes = projection.compact_snapshot()?;

        Ok(StorageShutdownSummary {
            head_commit_sequence: verify.head_commit_sequence,
            history_root: verify.history_root,
            state_root: verify.state_root,
            sealed_pack_on_shutdown,
            verified_epochs: verify.epochs_verified,
            verified_batches: verify.batches_verified,
            verified_live_objects: verify.live_objects,
            projection_snapshot_bytes,
        })
    }

    fn execute_eviction_and_compaction(
        &mut self,
        batch: &RetentionEvictionBatch,
        head_seq: u64,
    ) -> Result<(u64, u64, u64), DaemonError> {
        if batch.tombstones.is_empty() {
            return Ok((0, 0, 0));
        }
        let proof = self
            .pack_store
            .commit_eviction_tombstones(batch, Some(head_seq))?;
        let evicted = batch.tombstones.len() as u64;
        for tomb in &batch.tombstones {
            self.candidates.remove(&tomb.import_id);
        }
        let compact = self
            .pack_store
            .compact_sealed_packs(&proof, CompactionPolicy::default())?;
        Ok((
            evicted,
            compact.total_bytes_reclaimed,
            compact
                .packs_unlinked_empty
                .saturating_add(compact.packs_rewritten),
        ))
    }

    fn next_object_generation(
        &self,
        object_id: &ObjectId,
    ) -> Result<(Option<u64>, u64), DaemonError> {
        let gens = self
            .object_generations
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "object_generations",
            })?;
        let prior = gens.get(object_id).copied();
        Ok((prior, prior.map_or(1, |g| g.saturating_add(1))))
    }

    fn record_object_generation(
        &self,
        object_id: ObjectId,
        generation: u64,
    ) -> Result<(), DaemonError> {
        let mut gens = self
            .object_generations
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "object_generations",
            })?;
        gens.insert(object_id, generation);
        Ok(())
    }

    fn alloc_delta_seq(&mut self) -> u64 {
        let s = self.next_delta_seq;
        self.next_delta_seq = s.saturating_add(1);
        s
    }
    fn alloc_chunk_seq(&mut self) -> u64 {
        let s = self.next_chunk_seq;
        self.next_chunk_seq = s.saturating_add(1);
        s
    }
}

fn receipt_from_coalesced(c: fss_projection_store::CoalescedCommitReceipt) -> StorageCommitReceipt {
    StorageCommitReceipt {
        commit_sequence: c.commit_sequence,
        batch_id: c.batch_id,
        authority_root: c.authority_root,
        history_root: c.history_root,
        batch_digest: c.batch_digest,
        fsyncs_executed: c.fsyncs_executed,
    }
}

fn write_layout_v2_atomic(root_dir: &Path, layout: &DeploymentLayoutV2) -> Result<(), DaemonError> {
    let text = layout.to_canonical_text();
    let final_path = root_dir.join(DEPLOYMENT_LAYOUT_FILENAME);
    let tmp_path = root_dir.join(format!(
        "{DEPLOYMENT_LAYOUT_FILENAME}.tmp.{}",
        std::process::id()
    ));
    let mut file =
        File::create(&tmp_path).map_err(|err| DaemonError::io("create_layout_tmp", err))?;
    file.write_all(text.as_bytes())
        .map_err(|err| DaemonError::io("write_layout_tmp", err))?;
    file.sync_all()
        .map_err(|err| DaemonError::io("sync_layout_tmp", err))?;
    drop(file);
    fs::rename(&tmp_path, &final_path).map_err(|err| DaemonError::io("rename_layout", err))?;
    Ok(())
}
