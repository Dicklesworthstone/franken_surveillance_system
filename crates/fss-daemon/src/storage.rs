#![forbid(unsafe_code)]
//! `StorageRegion` orchestrating `PackStore` (`A1`), `MerkleEpochLedger` (`A2`),
//! `MvccProjectionStore` + `CommitCombiner` (`A3`), hold-safe retention ring compaction, and
//! incremental `BackgroundScrubber` (`A4`).
//!
//! Semantic plane: `"authority"`.

pub(crate) mod forward_requests;
mod gop;
mod retention;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, EventHypothesis, EventState, EvidenceDelta,
    ObjectId, Plane, RegionTree, SensorId, TimestampNs,
};
use fss_ipc::ActiveScrubStatus;
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{
    BackgroundScrubber, CapacityPressure, CompactionPolicy, PACK_KIND_MEDIA_CHUNK,
    PACK_KIND_METADATA, PackConfig, PackStore, RetentionCandidate, RetentionEvictionBatch,
    RetentionPlanOutcome, RetentionRingConfig, ScrubBudget, plan_retention,
};
use fss_projection_store::{
    CommitCombiner, CommitCombinerConfig, CommitProposal, CoverageStatus, CoverageWitnessPayload,
    DoctorScrubReceipt, EventRevisionPayload, FAMILY_COVERAGE_WITNESS, FAMILY_EVENT_REVISION,
    FAMILY_SENSOR_LIVENESS, LedgerPackProjectionSink, MvccProjectionStore, OwnedPackObject,
    PackStorePayloadResolver, ProjectionRecordPayload, ProjectionStore, SensorLivenessPayload,
    SensorLivenessStatus,
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
    CombinerForwardWriter, map_scrub_verdict, sanitize_object_part, scrub_report_to_ipc_status,
};
use forward_requests::ForwardRequestStore;
use gop::{PendingGopPublication, recover_unpublished_gops};
use retention::{RetainedRoot, RetiredRoot, recover_retained_roots};

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
    forward_requests: Arc<ForwardRequestStore>,
    object_generations: Arc<Mutex<BTreeMap<ObjectId, u64>>>,
    retention_gate: Arc<Mutex<()>>,
    quota_pinned: Arc<AtomicBool>,
    pinned_bytes: Arc<AtomicU64>,
    retention_config: RetentionRingConfig,
    candidates: BTreeMap<String, RetentionCandidate>,
    candidate_roots: BTreeMap<String, RetainedRoot>,
    pending_deletions: Vec<RetiredRoot>,
    gop_buffers: BTreeMap<SensorId, Vec<Arc<CameraFrame>>>,
    gop_adapters: BTreeMap<SensorId, CameraAdapterKind>,
    pending_gop_publications: BTreeMap<SensorId, PendingGopPublication>,
    indeterminate_gop_commits: BTreeSet<SensorId>,
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
        let canonical_objects = ledger.snapshot_objects();

        let resolver = PackStorePayloadResolver::new(&pack_store);
        let projection = Arc::new(MvccProjectionStore::open_or_rebuild(
            root_dir.join(PROJECTION_SUBDIR),
            &ledger,
            &resolver,
        )?);
        recover_unpublished_gops(&pack_store, &canonical_objects, &projection, &ledger)?;
        let initial_gens: BTreeMap<ObjectId, u64> = canonical_objects
            .into_iter()
            .map(|(id, rev)| (id, rev.generation))
            .collect();
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
        let forward_requests = Arc::new(ForwardRequestStore::open(&root_dir)?);

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
        let (candidates, candidate_roots, pending_deletions, seed_seq) =
            recover_retained_roots(&pack_store, head_seq)?;

        let mut engine = Self {
            root_dir,
            site_id: manifest.site_id.clone(),
            pack_store,
            projection,
            combiner,
            forward_requests,
            object_generations: Arc::new(Mutex::new(initial_gens)),
            retention_gate: Arc::new(Mutex::new(())),
            quota_pinned: Arc::new(AtomicBool::new(false)),
            pinned_bytes: Arc::new(AtomicU64::new(0)),
            retention_config,
            candidates,
            candidate_roots,
            pending_deletions,
            gop_buffers: BTreeMap::new(),
            gop_adapters: BTreeMap::new(),
            pending_gop_publications: BTreeMap::new(),
            indeterminate_gop_commits: BTreeSet::new(),
            scrubber: BackgroundScrubber::new(),
            scrub_budget_bytes: manifest.scrub_budget_bytes_per_tick,
            last_scrub_status: ActiveScrubStatus::Idle,
            pressure: CapacityPressure::Nominal,
            next_delta_seq: seed_seq,
            next_chunk_seq: seed_seq,
            ingest_paused_reason: None,
        };
        engine.refresh_retention_pins();
        engine.refresh_catalog_reference_pins()?;
        engine.resume_pending_retention_deletions()?;
        let current = engine.retention_plan_candidates()?;
        let used = current.iter().fold(0_u64, |sum, candidate| {
            sum.saturating_add(candidate.byte_size)
        });
        let pinned = current
            .iter()
            .filter(|candidate| candidate.is_pinned())
            .fold(0_u64, |sum, candidate| {
                sum.saturating_add(candidate.byte_size)
            });
        engine.pressure = engine.retention_config.classify_pressure(used);
        let blocked = engine.pressure == CapacityPressure::Critical
            && current.iter().all(RetentionCandidate::is_pinned);
        engine.pinned_bytes.store(pinned, Ordering::Release);
        engine.quota_pinned.store(blocked, Ordering::Release);
        engine.ingest_paused_reason = blocked.then_some(fss_pack::ERR_STORAGE_QUOTA_PINNED_001);
        Ok(engine)
    }

    /// Creates a [`ForwardBatchWriter`] sharing this engine's `CommitCombiner` for IPC forwarding.
    #[must_use]
    pub fn forward_writer(&self) -> Arc<dyn ForwardBatchWriter> {
        Arc::new(CombinerForwardWriter {
            combiner: Arc::clone(&self.combiner),
            forward_requests: Arc::clone(&self.forward_requests),
            projection: Arc::clone(&self.projection),
            object_generations: Arc::clone(&self.object_generations),
            retention_gate: Arc::clone(&self.retention_gate),
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
        self.commit_coverage_and_liveness_with_evidence(
            sensor_id,
            zone_id,
            status,
            liveness,
            active_gaps,
            0,
            last_seen_ns,
            now_ns,
            None,
            cx,
            tree,
        )
    }

    /// Commits a source-bound health-screen transition and its paired coverage/liveness state.
    ///
    /// The bounded canonical receipt is retained in the same publication as the state change.
    /// Both deltas name its exact digest as their witness; a clear screen only removes the
    /// declared health conflict and does not itself certify continuity or physical coverage.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_health_coverage_and_liveness(
        &mut self,
        sensor_id: &SensorId,
        zone_id: &str,
        status: CoverageStatus,
        liveness: SensorLivenessStatus,
        active_gaps: u32,
        health_conflicts: u32,
        last_seen_ns: TimestampNs,
        now_ns: TimestampNs,
        evidence: &[u8],
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<StorageCommitReceipt, DaemonError> {
        if evidence.is_empty() || evidence.len() > 64 * 1024 {
            return Err(DaemonError::InvalidConfig {
                detail: "health transition evidence must contain 1..=65536 canonical bytes"
                    .to_owned(),
            });
        }
        self.commit_coverage_and_liveness_with_evidence(
            sensor_id,
            zone_id,
            status,
            liveness,
            active_gaps,
            health_conflicts,
            last_seen_ns,
            now_ns,
            Some(evidence),
            cx,
            tree,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_coverage_and_liveness_with_evidence(
        &mut self,
        sensor_id: &SensorId,
        zone_id: &str,
        status: CoverageStatus,
        liveness: SensorLivenessStatus,
        active_gaps: u32,
        health_conflicts: u32,
        last_seen_ns: TimestampNs,
        now_ns: TimestampNs,
        evidence: Option<&[u8]>,
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
            health_conflicts,
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
        let witness_digest = evidence.map(ContentDigest::sha256);
        let mut objects = vec![
            OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, cov_bytes, cov_digest),
            OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, live_bytes, live_digest),
        ];
        let request = format!("{}:{}:{seq}", cov_digest.to_text(), live_digest.to_text());
        let req_digest = if let Some((bytes, digest)) = evidence.zip(witness_digest) {
            objects.push(OwnedPackObject::with_digest(
                PACK_KIND_METADATA,
                0,
                bytes.to_vec(),
                digest,
            ));
            ContentDigest::sha256(format!("{request}:{}", digest.to_text()).as_bytes())
        } else {
            // Preserve the identity of existing unscreened coverage publications.
            ContentDigest::sha256(request.as_bytes())
        };
        let proposal = CommitProposal {
            request_digest: req_digest,
            sensor_scope: sensor_id.as_str().to_owned(),
            objects,
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
                    witness_digest,
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
                    witness_digest,
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
    /// Cognition != Authority) and pins verified source closures for corroborated events.
    pub fn commit_event_hypothesis(
        &mut self,
        event: &EventHypothesis,
        sensor_ids: Vec<SensorId>,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<StorageCommitReceipt, DaemonError> {
        let gate = Arc::clone(&self.retention_gate);
        let _guard = gate.lock().map_err(|_| DaemonError::LockPoisoned {
            component: "retention_gate",
        })?;
        if cx.is_cancel_requested(tree)? {
            return Err(fss_projection_store::CombinerError::Cancelled.into());
        }
        self.flush_event_sources(event, &sensor_ids, cx, tree)?;
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
        let mut proposal = CommitProposal {
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
        let hold_generations = self.append_event_pins(event, &sensor_ids, &mut proposal)?;
        let committed = self.combiner.submit_with_authority(cx, tree, proposal)?;
        self.record_object_generation(obj_id, new_gen)?;

        for (id, generation) in hold_generations {
            self.record_object_generation(id, generation)?;
        }
        self.refresh_retention_pins();
        Ok(receipt_from_coalesced(committed))
    }

    /// Durably attaches a hold through this exclusively owned storage writer.
    /// Returns false for an unknown closure or a refused/failed canonical commit.
    /// Use `set_candidate_hold` for an explicit authority context and typed errors.
    pub fn pin_candidate_hold(&mut self, import_id: &str, hold_id: impl Into<String>) -> bool {
        self.change_candidate_hold(import_id, hold_id.into(), true, None)
            .unwrap_or(false)
    }

    /// Registers an explicit retention candidate (e.g., pinned hold closure) into the ring catalog.
    pub fn register_retention_candidate(
        &mut self,
        candidate: RetentionCandidate,
    ) -> Result<(), DaemonError> {
        candidate.validate()?;
        if self.candidate_roots.contains_key(&candidate.import_id)
            || candidate.import_id == "retention:canonical-history"
        {
            return Err(DaemonError::InvalidConfig {
                detail:
                    "cannot replace a committed media root with an explicit retention candidate"
                        .to_owned(),
            });
        }
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
        let gate = Arc::clone(&self.retention_gate);
        let _guard = gate.lock().map_err(|_| DaemonError::LockPoisoned {
            component: "retention_gate",
        })?;
        if cx.is_cancel_requested(tree)? {
            return Err(fss_projection_store::CombinerError::Cancelled.into());
        }
        self.synchronize_retired_roots()?;
        self.refresh_retention_pins();
        self.resume_pending_retention_deletions()?;
        let candidates_vec = self.retention_plan_candidates_for_eviction()?;
        let mut outcome = plan_retention(&self.retention_config, &candidates_vec, now_ns)?;
        if matches!(
            &outcome,
            RetentionPlanOutcome::Evict(_)
                | RetentionPlanOutcome::QuotaPinned {
                    partial_eviction: Some(_),
                    ..
                }
        ) {
            self.refresh_catalog_reference_pins()?;
            outcome = plan_retention(
                &self.retention_config,
                &self.retention_plan_candidates_for_eviction()?,
                now_ns,
            )?;
        }

        let (mut evicted_imports, mut bytes_reclaimed, mut packs_compacted) = (0_u64, 0_u64, 0_u64);
        match outcome {
            RetentionPlanOutcome::NoAction { .. } => {}
            RetentionPlanOutcome::Evict(batch) => {
                (evicted_imports, bytes_reclaimed, packs_compacted) =
                    self.execute_eviction_and_compaction(&batch, cx, tree)?;
            }
            RetentionPlanOutcome::QuotaPinned {
                partial_eviction, ..
            } => {
                if let Some(batch) = partial_eviction {
                    (evicted_imports, bytes_reclaimed, packs_compacted) =
                        self.execute_eviction_and_compaction(&batch, cx, tree)?;
                }
            }
        }

        // Resume a prior committed compaction even when this tick selects no new eviction.
        if evicted_imports == 0 {
            if cx.is_cancel_requested(tree)? {
                return Err(fss_projection_store::CombinerError::Cancelled.into());
            }
            let policy = self.compaction_policy_for_current_usage()?;
            if self.should_seal_active_pack_for_reclaim()? {
                let _ = self.pack_store.seal_active_pack()?;
            }
            let resumed = self.pack_store.reclaim_superseded_packs(policy)?;
            bytes_reclaimed = bytes_reclaimed.saturating_add(resumed.total_bytes_reclaimed);
            packs_compacted = packs_compacted.saturating_add(
                resumed
                    .packs_unlinked_empty
                    .saturating_add(resumed.packs_rewritten),
            );
        }

        // Canonical retirement adds protected metadata. Report measured logical occupancy
        // after that commit, not the planner's pre-commit estimate.
        let current = self.retention_plan_candidates()?;
        let used = current.iter().fold(0_u64, |sum, candidate| {
            sum.saturating_add(candidate.byte_size)
        });
        let pinned_bytes = current
            .iter()
            .filter(|candidate| candidate.is_pinned())
            .fold(0_u64, |sum, candidate| {
                sum.saturating_add(candidate.byte_size)
            });
        self.pressure = self.retention_config.classify_pressure(used);
        let quota_pinned = self.pressure == CapacityPressure::Critical
            && current.iter().all(RetentionCandidate::is_pinned);
        self.quota_pinned.store(quota_pinned, Ordering::Release);
        self.pinned_bytes.store(pinned_bytes, Ordering::Release);
        self.ingest_paused_reason = quota_pinned.then_some(fss_pack::ERR_STORAGE_QUOTA_PINNED_001);

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
            ring_used_bytes: self.accounted_ring_bytes()?,
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
        let buffered = self
            .gop_buffers
            .values()
            .filter(|frames| !frames.is_empty())
            .count();
        if buffered != 0
            || !self.pending_gop_publications.is_empty()
            || !self.indeterminate_gop_commits.is_empty()
        {
            return Err(DaemonError::ShutdownViolation {
                detail: format!(
                    "unresolved source publication: buffered_cameras={buffered} pending_roots={} indeterminate_commits={}; flush or reconcile before shutdown",
                    self.pending_gop_publications.len(),
                    self.indeterminate_gop_commits.len()
                ),
            });
        }
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

    fn compaction_policy_for_current_usage(&self) -> Result<CompactionPolicy, DaemonError> {
        let on_disk = self.pack_store.on_disk_pack_bytes()?;
        let soft_bytes = self
            .retention_config
            .max_total_deployment_bytes
            .saturating_mul(u64::from(self.retention_config.watermark_soft_pct))
            / 100;
        if on_disk >= soft_bytes {
            // Once physical pack bytes reach the soft watermark, reclaim every sealed pack
            // containing any tombstoned bytes (`live_ratio_ppm < 1_000_000`) while leaving
            // 100%-live packs untouched.
            Ok(CompactionPolicy {
                min_live_ratio_ppm: 1_000_000,
                ..CompactionPolicy::default()
            })
        } else {
            Ok(CompactionPolicy::default())
        }
    }

    fn should_seal_active_pack_for_reclaim(&self) -> Result<bool, DaemonError> {
        let on_disk = self.pack_store.on_disk_pack_bytes()?;
        let seal_threshold = self
            .retention_config
            .max_total_deployment_bytes
            .saturating_add(24_576);
        Ok(on_disk > seal_threshold)
    }

    fn execute_eviction_and_compaction(
        &mut self,
        batch: &RetentionEvictionBatch,
        cx: &AuthorityCx,
        tree: &RegionTree,
    ) -> Result<(u64, u64, u64), DaemonError> {
        if batch.tombstones.is_empty() {
            return Ok((0, 0, 0));
        }
        // Query retirement is canonical before catalog tombstones or physical reclamation.
        // Historical projection metadata stays readable for replay from genesis.
        let head_seq = self.commit_retention_deletions(batch, cx, tree)?;
        if cx.is_cancel_requested(tree)? {
            return Err(fss_projection_store::CombinerError::Cancelled.into());
        }
        let proof = self
            .pack_store
            .commit_eviction_tombstones(batch, Some(head_seq))?;
        let evicted = batch.tombstones.len() as u64;
        for tomb in &batch.tombstones {
            self.candidates.remove(&tomb.import_id);
            self.candidate_roots.remove(&tomb.import_id);
        }
        let policy = self.compaction_policy_for_current_usage()?;
        if self.should_seal_active_pack_for_reclaim()? {
            // Only force-seal the active pack when physical bytes rise past ring_cap + headroom,
            // avoiding tiny-pack header fragmentation during normal ring wraparound.
            let _ = self.pack_store.seal_active_pack()?;
        }
        let compact = self.pack_store.compact_sealed_packs(&proof, policy)?;
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
        checkpoint_failure: c.checkpoint_failure,
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
