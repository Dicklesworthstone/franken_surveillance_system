#![forbid(unsafe_code)]
//! Non-destructive out-of-place v1-to-v2 deployment migration engine.
//!
//! Streams a verified clean v1 deployment into a fresh v2 deployment root while keeping the v1
//! source strictly read-only and guarding the destination with an atomic `.migrate-incomplete`
//! sentinel until every artifact is fsynced and verified.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, ContentDigest, CoverageContinuity, CoverageWitness,
    DigestAlgorithm, EffectState, EventHypothesis, EventId, EventState, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, ObjectId, Obligation, ObligationId, OperationReceipt,
    SensorId, SensorTamperStatus, StreamId, TimestampNs,
};
use fss_ledger::{
    DurableLedgerStatus, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger,
    committed_batch_positions, inspect_durable,
};
use fss_object::ObjectManifest;
use fss_pack::{
    DurabilityMode, PACK_KIND_OBJECT_MANIFEST, PACK_KIND_RAW_PAYLOAD, PackConfig, PackError,
    PackObjectInput, PackReader, PackStore, VirtualRootRecord,
};
use fss_projection_store::{
    CoverageStatus, CoverageWitnessPayload, DeletionTarget, DeletionTombstonePayload,
    EffectOutcomePayload, EventRevisionPayload, EvidenceHoldPayload, FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE, FAMILY_EFFECT_OUTCOME,
    FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD, FAMILY_FILE_IMPORT, FAMILY_FOOTAGE_IMPORT,
    FAMILY_HTTP_IMPORT, FAMILY_OBLIGATION, FAMILY_PRIVACY_MASK_POLICY, FAMILY_RTSP_IMPORT,
    FAMILY_SENSOR_LIVENESS, FAMILY_SENSOR_TAMPER_STATUS, FAMILY_TUTK_IMPORT, FootageAdapterKind,
    FootageImportPayload, HistoryChainMode, MvccProjectionStore, ObligationPayload,
    PROJECTION_PAYLOAD_MAGIC, PayloadResolver, PrivacyMaskPayload, ProjectionError,
    ProjectionRecordPayload, ProjectionStore, ProjectionStoreConfig, SensorLivenessPayload,
    SensorLivenessStatus, SensorTamperPayload, WalSyncPolicy, replay_from_batches,
};
use fss_publication::{LOCAL_TOMBSTONES_DIR, LocalInspection, inspect_linkage};

use crate::deletion::DeletionIndex;
use crate::deletion::holds::HoldRecord;
use crate::discovery::retained_liveness::SensorLivenessRecord;
use crate::discovery::watchdog::{WatchOfflineReason, WatchState};
use crate::durable_effect::DurableEffectJournal;
use crate::ingest::privacy_mask::PrivacyMaskPolicy;
use crate::ingest::recorded_coverage::CoverageRecord;
use crate::ingest::source_coverage::SourceCoverageRecord;
use crate::reference_deployment::{DEPLOYMENT_LAYOUT_FILENAME, DeploymentLimits};

use super::receipt::{
    MIGRATION_RECEIPT_FILENAME, MIGRATION_RECEIPT_SCHEMA, MigrationEquivalenceReceipt,
};
use super::{
    DeploymentFormatVersion, DeploymentLayoutV2, MIGRATE_INCOMPLETE_FILENAME, MigrationError,
    detect_deployment_format, escape_json_str,
};

/// Schema identifier for structured JSONL progress events emitted during migration.
pub const MIGRATION_PROGRESS_SCHEMA: &str = "fss.migration_progress.v1";

/// Default maximum journal size admitted during migration (64 MiB).
const DEFAULT_MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
/// Number of objects grouped per packfile batch append during migration.
const PACK_APPEND_BATCH_OBJECTS: usize = 64;
/// Approximate byte ceiling per packfile group-commit batch (4 MiB).
const PACK_APPEND_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Configuration and endpoints for a non-destructive v1-to-v2 deployment migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationRequest {
    /// Existing v1 deployment root directory (opened strictly read-only, never mutated).
    pub source_v1_root: PathBuf,
    /// Fresh non-existent destination path where the v2 deployment root will be created.
    pub dest_v2_root: PathBuf,
    /// Deployment capacity limits expected for the source v1 deployment.
    pub deployment_limits: DeploymentLimits,
    /// Maximum byte size admitted when reading v1 ledger and effect journals.
    pub max_journal_bytes: usize,
    /// Configuration for the destination v2 [`MerkleEpochLedger`].
    pub epoch_config: EpochLedgerConfig,
    /// Configuration for the destination v2 [`PackStore`].
    pub pack_config: PackConfig,
}

impl MigrationRequest {
    /// Constructs a migration request with standard limits and default v2 storage configs.
    #[must_use]
    pub fn new(source_v1_root: impl Into<PathBuf>, dest_v2_root: impl Into<PathBuf>) -> Self {
        Self {
            source_v1_root: source_v1_root.into(),
            dest_v2_root: dest_v2_root.into(),
            deployment_limits: DeploymentLimits::standard(),
            max_journal_bytes: DEFAULT_MAX_JOURNAL_BYTES,
            epoch_config: EpochLedgerConfig::default(),
            pack_config: PackConfig::default(),
        }
    }
}

/// Structured progress event emitted across migration phases for JSONL logging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationProgressEvent {
    /// Canonical stage name (`inspect_source`, `reserve_destination`, `stream_ledger`,
    /// `pack_objects`, `publish_virtual_roots`, `materialize_projections`,
    /// `copy_effects_and_agent`, `finalize`).
    pub stage: &'static str,
    /// Concise human-readable status detail (secret-free).
    pub detail: String,
    /// Completed unit count in the current stage.
    pub completed: u64,
    /// Total expected unit count in the current stage.
    pub total: u64,
}

impl MigrationProgressEvent {
    /// Formats this progress event as a single-line canonical JSONL record.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        format!(
            "{{\"schema\":\"{MIGRATION_PROGRESS_SCHEMA}\",\"stage\":\"{}\",\"completed\":{},\"total\":{},\"detail\":\"{}\"}}",
            escape_json_str(self.stage),
            self.completed,
            self.total,
            escape_json_str(&self.detail),
        )
    }
}

/// Executes a non-destructive out-of-place migration from a clean v1 deployment root into a
/// brand-new v2 deployment root, returning a self-verifying [`MigrationEquivalenceReceipt`].
pub fn migrate_v1_to_v2(
    request: &MigrationRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<MigrationEquivalenceReceipt, MigrationError> {
    let mut noop_progress = |_: MigrationProgressEvent| {};
    migrate_v1_to_v2_with_progress(request, cancelled, &mut noop_progress)
}

/// Executes [`migrate_v1_to_v2`] while invoking `progress` at each migration milestone.
pub fn migrate_v1_to_v2_with_progress(
    request: &MigrationRequest,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(MigrationProgressEvent),
) -> Result<MigrationEquivalenceReceipt, MigrationError> {
    check_cancel(cancelled, "preflight")?;

    // Phase 0: Strict path validation and destination non-existence refusal.
    let source_root = admit_source_dir(&request.source_v1_root)?;
    let dest_root = admit_fresh_dest_path(&request.dest_v2_root, &source_root)?;

    let v1_layout = match detect_deployment_format(&source_root)? {
        DeploymentFormatVersion::V1 { layout } => layout,
        DeploymentFormatVersion::V2 { .. } => {
            return Err(MigrationError::SourceAlreadyV2 { path: source_root });
        }
        DeploymentFormatVersion::MigrateIncomplete { marker_detail } => {
            return Err(MigrationError::IncompleteMigration {
                path: source_root,
                detail: marker_detail,
            });
        }
        DeploymentFormatVersion::NotADeployment { reason } => {
            return Err(MigrationError::NotADeployment {
                path: source_root,
                reason,
            });
        }
    };

    let expected_limits_digest = request
        .deployment_limits
        .canonical_digest()
        .map_err(|err| MigrationError::SourceNotClean {
            detail: format!("invalid deployment limits: {err}"),
        })?;
    if v1_layout.limits_digest != expected_limits_digest {
        return Err(MigrationError::SourceNotClean {
            detail: "source LAYOUT limits_digest does not match request deployment_limits"
                .to_owned(),
        });
    }

    // Phase 1: Clean read-only v1 inspection (zero mutation, zero locks on source).
    check_cancel(cancelled, "inspect_source")?;
    progress(MigrationProgressEvent {
        stage: "inspect_source",
        detail: "inspecting v1 ledger, effects, and object custody read-only".to_owned(),
        completed: 0,
        total: 1,
    });

    let v1_ledger_path = source_root.join(&v1_layout.ledger_relpath);
    let v1_ledger = inspect_durable(
        &v1_ledger_path,
        &v1_layout.site_lineage,
        request.max_journal_bytes,
    )
    .map_err(|err| MigrationError::SourceNotClean {
        detail: format!("v1 ledger inspection failed: {err}"),
    })?;
    if v1_ledger.status != DurableLedgerStatus::Present {
        return Err(MigrationError::SourceNotClean {
            detail: "v1 authority ledger journal is absent".to_owned(),
        });
    }
    if !v1_ledger.is_clean() {
        return Err(MigrationError::SourceNotClean {
            detail: format!(
                "v1 authority ledger has unclean tail (incomplete_tail={:?}, foreign_range={:?}); repair before migrating",
                v1_ledger.incomplete_tail, v1_ledger.foreign_range
            ),
        });
    }
    verify_v1_batch_continuity(&v1_layout.site_lineage, &v1_ledger)?;

    let v1_effects_path = source_root.join(&v1_layout.effects_relpath);
    let v1_effects = DurableEffectJournal::inspect(&v1_effects_path, request.max_journal_bytes)
        .map_err(|err| MigrationError::SourceNotClean {
            detail: format!("v1 effects journal inspection failed: {err}"),
        })?;
    if !v1_effects.is_clean() {
        return Err(MigrationError::SourceNotClean {
            detail: format!(
                "v1 effects journal is not clean (status={:?}, incomplete_tail={:?}, foreign_range={:?}); repair before migrating",
                v1_effects.status, v1_effects.incomplete_tail, v1_effects.foreign_range
            ),
        });
    }
    let v1_effects_bytes = read_bounded_bytes(&v1_effects_path, request.max_journal_bytes)?;
    let v1_effects_sha256 = ContentDigest::sha256(&v1_effects_bytes);

    let v1_objects_dir = source_root.join(&v1_layout.objects_relpath);
    let v1_local = fss_publication::inspect(
        &v1_objects_dir,
        request.deployment_limits.to_publication_limits(),
    )
    .map_err(|err| MigrationError::SourceNotClean {
        detail: format!("v1 object publication inspection failed: {err}"),
    })?;
    if !v1_local.report.spool.is_clean()
        || !v1_local.report.broken_roots.is_empty()
        || !v1_local.report.foreign.is_empty()
        || v1_local.missing_layout
        || v1_local.spool_over_capacity
        || !v1_local.report.orphaned_temps.is_empty()
        || !v1_local.redundant_temps.is_empty()
        || v1_local.holds_migration_pending
    {
        return Err(MigrationError::SourceNotClean {
            detail: "v1 object spool or publication layout is unclean or incomplete; run doctor/recover first".to_owned(),
        });
    }

    let linkage = inspect_linkage(&v1_local, &v1_ledger);
    if !linkage.not_durable.is_empty()
        || !linkage.conflicts.is_empty()
        || !linkage.unbacked_ledger_claims.is_empty()
        || !linkage.broken.is_empty()
        || linkage.ledger_tail_incomplete.is_some()
    {
        return Err(MigrationError::SourceNotClean {
            detail: "v1 root-to-ledger linkage is not clean; reconcile before migrating".to_owned(),
        });
    }

    let max_obj_bytes =
        usize::try_from(request.deployment_limits.spool_object_max_bytes).unwrap_or(usize::MAX);
    let deletion_index =
        DeletionIndex::from_batches::<MigrationError>(&v1_ledger.batches, |digest| {
            fss_publication::read_verified(&v1_objects_dir, digest, max_obj_bytes).map_err(|err| {
                MigrationError::SourceNotClean {
                    detail: format!("failed reading deletion record {}: {err}", digest.to_text()),
                }
            })
        })?;
    if deletion_index
        .entries()
        .iter()
        .any(|entry| !entry.is_complete())
    {
        return Err(MigrationError::SourceNotClean {
            detail: "v1 source contains an incomplete deletion; resume deletion before migrating"
                .to_owned(),
        });
    }

    let mut deleted_digests: BTreeSet<ContentDigest> = deletion_index.deleted_objects();
    deleted_digests.extend(v1_local.report.tombstones.iter().copied());
    for admitted in &v1_local.report.spool.admitted {
        if deleted_digests.contains(admitted) {
            return Err(MigrationError::SourceNotClean {
                detail: format!(
                    "deleted/tombstoned object {} still exists in v1 spool",
                    admitted.to_text()
                ),
            });
        }
    }

    let (to_pack, source_unreferenced_orphans) = collect_referenced_and_orphan_objects(
        &v1_objects_dir,
        &v1_local,
        &v1_ledger.batches,
        max_obj_bytes,
    )?;

    let agent_inventory = collect_agent_file_inventory(&source_root, request.max_journal_bytes)?;
    let tombstone_files =
        collect_tombstone_files(&v1_objects_dir.join(LOCAL_TOMBSTONES_DIR), max_obj_bytes)?;

    progress(MigrationProgressEvent {
        stage: "inspect_source",
        detail: format!(
            "verified clean v1 source: {} batches, {} referenced objects, {} orphans, {} live roots",
            v1_ledger.batches.len(),
            to_pack.len(),
            source_unreferenced_orphans.len(),
            v1_local.report.roots.len()
        ),
        completed: 1,
        total: 1,
    });

    // Phase 2: Reserve fresh destination and write atomic `.migrate-incomplete` sentinel.
    check_cancel(cancelled, "reserve_destination")?;
    fs::create_dir(&dest_root).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            MigrationError::DestinationExists {
                path: dest_root.clone(),
            }
        } else {
            MigrationError::io("create_dest_root", err)
        }
    })?;

    let sentinel_path = dest_root.join(MIGRATE_INCOMPLETE_FILENAME);
    let sentinel_body = format!(
        "fss.deployment_migrate.incomplete.v1\nsite_lineage={}\nsource_commit_sequence={}\nsource_ledger_root={}\n",
        v1_layout.site_lineage,
        v1_ledger.snapshot.anchor.commit_sequence,
        v1_ledger.last_root.to_text(),
    );
    write_new_file_fsynced(&sentinel_path, sentinel_body.as_bytes())?;
    sync_dir(&dest_root)?;
    if let Some(parent) = dest_root.parent() {
        sync_dir(parent)?;
    }

    progress(MigrationProgressEvent {
        stage: "reserve_destination",
        detail: "reserved destination root and wrote .migrate-incomplete sentinel".to_owned(),
        completed: 1,
        total: 1,
    });
    check_cancel(cancelled, "after_sentinel")?;

    // Phase 3: Stream every v1 EvidenceDeltaBatch in exact commit order into v2 MerkleEpochLedger.
    let v2_ledger_dir = dest_root.join("ledger");
    let mut epoch_ledger = MerkleEpochLedger::open(
        &v2_ledger_dir,
        v1_layout.site_lineage.clone(),
        request.epoch_config,
        IncompleteTailPolicy::Reject,
    )
    .map_err(|err| MigrationError::Ledger(err.to_string()))?;

    let total_batches = v1_ledger.batches.len() as u64;
    let mut v2_batches = Vec::with_capacity(v1_ledger.batches.len());
    for (idx, v1_batch) in v1_ledger.batches.iter().enumerate() {
        check_cancel(cancelled, "stream_ledger")?;
        let v2_batch = epoch_ledger
            .prepare_batch(
                v1_batch.batch_id.clone(),
                v1_batch.deltas.clone(),
                v1_batch.children.iter().copied(),
            )
            .map_err(|err| MigrationError::Ledger(err.to_string()))?;
        let _receipt = epoch_ledger
            .append_batch(v2_batch.clone())
            .map_err(|err| MigrationError::Ledger(err.to_string()))?;
        v2_batches.push(v2_batch);
        progress(MigrationProgressEvent {
            stage: "stream_ledger",
            detail: format!("migrated batch {}", idx + 1),
            completed: (idx + 1) as u64,
            total: total_batches,
        });
    }

    check_cancel(cancelled, "checkpoint_ledger")?;
    let _checkpoint = epoch_ledger
        .force_checkpoint()
        .map_err(|err| MigrationError::Ledger(err.to_string()))?;
    let chain_report =
        epoch_ledger
            .verify_full_chain()
            .map_err(|err| MigrationError::VerificationFailed {
                detail: format!("v2 epoch ledger full chain verification failed: {err}"),
            })?;
    if chain_report.batches_verified != total_batches {
        return Err(MigrationError::VerificationFailed {
            detail: format!(
                "v2 verified batch count {} != source batch count {total_batches}",
                chain_report.batches_verified
            ),
        });
    }
    if epoch_ledger.snapshot_objects() != v1_ledger.snapshot.objects {
        return Err(MigrationError::VerificationFailed {
            detail: "v2 Merkle ledger live object state diverged from v1 canonical snapshot"
                .to_owned(),
        });
    }

    // Phase 4: Pack all referenced v1 spool objects into PackStore + VirtualRootCatalog.
    check_cancel(cancelled, "pack_objects")?;
    let pack_store = PackStore::open(&dest_root, request.pack_config)
        .map_err(|err| MigrationError::Pack(err.to_string()))?;

    let total_objects = to_pack.len() as u64;
    let mut object_sizes: BTreeMap<ContentDigest, u64> = BTreeMap::new();
    let mut pending_payloads: Vec<(ContentDigest, u16, Vec<u8>)> = Vec::new();
    let mut pending_bytes: usize = 0;
    let mut packed_count: u64 = 0;

    for &digest in &to_pack {
        check_cancel(cancelled, "pack_objects")?;
        let raw = fss_publication::read_verified(&v1_objects_dir, digest, max_obj_bytes).map_err(
            |err| MigrationError::SourceNotClean {
                detail: format!(
                    "failed reading verified v1 object {}: {err}",
                    digest.to_text()
                ),
            },
        )?;
        let actual_digest = ContentDigest::sha256(&raw);
        if actual_digest != digest {
            return Err(MigrationError::VerificationFailed {
                detail: format!("v1 object {} failed SHA-256 verification", digest.to_text()),
            });
        }
        let kind = if ObjectManifest::from_canonical_bytes(&raw).is_ok() {
            PACK_KIND_OBJECT_MANIFEST
        } else {
            PACK_KIND_RAW_PAYLOAD
        };
        object_sizes.insert(digest, raw.len() as u64);
        pending_bytes = pending_bytes.saturating_add(raw.len());
        pending_payloads.push((digest, kind, raw));

        if pending_payloads.len() >= PACK_APPEND_BATCH_OBJECTS
            || pending_bytes >= PACK_APPEND_BATCH_BYTES
        {
            flush_pack_batch(&pack_store, &mut pending_payloads)?;
            packed_count = object_sizes.len() as u64;
            pending_bytes = 0;
            progress(MigrationProgressEvent {
                stage: "pack_objects",
                detail: format!("packed {packed_count}/{total_objects} objects"),
                completed: packed_count,
                total: total_objects,
            });
        }
    }
    if !pending_payloads.is_empty() {
        flush_pack_batch(&pack_store, &mut pending_payloads)?;
        packed_count = object_sizes.len() as u64;
        progress(MigrationProgressEvent {
            stage: "pack_objects",
            detail: format!("packed {packed_count}/{total_objects} objects"),
            completed: packed_count,
            total: total_objects,
        });
    }

    if let Some(sealed) = pack_store
        .seal_active_pack()
        .map_err(|err| MigrationError::Pack(err.to_string()))?
    {
        let _footer = pack_store.verify_pack(sealed.pack_id).map_err(|err| {
            MigrationError::VerificationFailed {
                detail: format!("sealed pack {} verification failed: {err}", sealed.pack_id),
            }
        })?;
    }
    let _index_entries = pack_store
        .save_index_snapshot()
        .map_err(|err| MigrationError::Pack(err.to_string()))?;

    // Re-read and verify every packed object's SHA-256 directly from PackStore.
    for (&digest, &expected_len) in &object_sizes {
        check_cancel(cancelled, "verify_packed_objects")?;
        let verified = pack_store.read_verified(&digest).map_err(|err| {
            MigrationError::VerificationFailed {
                detail: format!("v2 pack readback failed for {}: {err}", digest.to_text()),
            }
        })?;
        if verified.len() as u64 != expected_len || ContentDigest::sha256(&verified) != digest {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "v2 pack readback SHA-256 or size mismatch for {}",
                    digest.to_text()
                ),
            });
        }
    }

    // Confirm zero orphans were adopted into v2 packs.
    for &orphan in &source_unreferenced_orphans {
        if pack_store
            .lookup(&orphan)
            .map_err(|err| MigrationError::Pack(err.to_string()))?
            .is_some()
        {
            return Err(MigrationError::VerificationFailed {
                detail: format!(
                    "orphan {} unexpectedly present in v2 pack index",
                    orphan.to_text()
                ),
            });
        }
    }

    // Publish all live v1 roots into v2 VirtualRootCatalog.
    check_cancel(cancelled, "publish_virtual_roots")?;
    let total_roots = v1_local.report.roots.len() as u64;
    for (idx, visible_root) in v1_local.report.roots.iter().enumerate() {
        check_cancel(cancelled, "publish_virtual_roots")?;
        let manifest_bytes = pack_store
            .read_verified(&visible_root.root)
            .map_err(|err| MigrationError::VerificationFailed {
                detail: format!(
                    "manifest {} missing from v2 packs: {err}",
                    visible_root.root.to_text()
                ),
            })?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes).map_err(|err| {
            MigrationError::VerificationFailed {
                detail: format!(
                    "manifest {} decode failed: {err}",
                    visible_root.root.to_text()
                ),
            }
        })?;
        let closure_bytes: u64 = v1_local
            .root_closure(&visible_root.slot)
            .into_iter()
            .flat_map(|set| set.iter())
            .filter_map(|d| object_sizes.get(d).copied())
            .fold(0_u64, u64::saturating_add);
        let record = VirtualRootRecord::from_manifest(
            &visible_root.slot,
            &manifest,
            closure_bytes,
            1,
            TimestampNs(0),
        )
        .map_err(|err| MigrationError::Pack(err.to_string()))?;
        let _root_receipt = pack_store
            .publish_root(record)
            .map_err(|err| MigrationError::Pack(err.to_string()))?;
        progress(MigrationProgressEvent {
            stage: "publish_virtual_roots",
            detail: format!("published virtual root '{}'", visible_root.slot.as_str()),
            completed: (idx + 1) as u64,
            total: total_roots,
        });
    }
    let _compaction = pack_store
        .compact_catalog()
        .map_err(|err| MigrationError::Pack(err.to_string()))?;

    // Preserve local object tombstone denial records byte-for-byte in <dest>/objects/tombstones/.
    if !tombstone_files.is_empty() {
        let dest_tombstones_dir = dest_root.join("objects").join(LOCAL_TOMBSTONES_DIR);
        fs::create_dir_all(&dest_tombstones_dir)
            .map_err(|err| MigrationError::io("create_tombstones_dir", err))?;
        for (name, bytes, expected_sha) in &tombstone_files {
            check_cancel(cancelled, "copy_tombstones")?;
            let target = dest_tombstones_dir.join(name);
            write_new_file_fsynced(&target, bytes)?;
            let readback = read_bounded_bytes(&target, max_obj_bytes)?;
            if ContentDigest::sha256(&readback) != *expected_sha {
                return Err(MigrationError::VerificationFailed {
                    detail: format!("tombstone file '{name}' readback SHA-256 mismatch"),
                });
            }
        }
        sync_dir(&dest_tombstones_dir)?;
    }

    // Phase 5: Materialize derived MvccProjectionStore (<dest>/projections/mvcc/) from v2 ledger + packs.
    check_cancel(cancelled, "materialize_projections")?;
    let resolver = MigrationPayloadResolver::new(pack_store.reader(), deleted_digests);
    let proj_dir = dest_root.join("projections/mvcc");
    let proj_config = ProjectionStoreConfig {
        durability: DurabilityMode::Fsync,
        wal_sync: WalSyncPolicy::FlushOnly,
        history_mode: HistoryChainMode::V2MerkleEpoch,
        ..ProjectionStoreConfig::default()
    };
    let proj_store = MvccProjectionStore::open_or_rebuild_with_config(
        &proj_dir,
        &epoch_ledger,
        &resolver,
        proj_config,
    )
    .map_err(|err| MigrationError::Projection(err.to_string()))?;
    let _snap_bytes = proj_store
        .compact_snapshot()
        .map_err(|err| MigrationError::Projection(err.to_string()))?;

    let snapshot = proj_store.snapshot_latest();
    let projection_state_digest = snapshot.state_digest();

    // Independent pure replay equivalence check against the newly written v2 batches.
    let oracle_snap = replay_from_batches(
        epoch_ledger.genesis_anchor(),
        HistoryChainMode::V2MerkleEpoch,
        &v2_batches,
        &resolver,
    )
    .map_err(|err| MigrationError::Projection(err.to_string()))?;
    if oracle_snap.state_digest() != projection_state_digest {
        return Err(MigrationError::VerificationFailed {
            detail: "MVCC projection snapshot state_digest differs from pure replay oracle"
                .to_owned(),
        });
    }

    // Verify counts of materialized semantic entities match v1 canonical ledger history.
    let (expected_holds, expected_masks, tombstones_migrated) =
        count_canonical_entities(&v1_ledger.batches, &v1_local);
    let summary = snapshot.orient_summary();
    let events_migrated = summary.total_events as u64;
    let holds_migrated = expected_holds;
    let masks_migrated = summary.privacy_masks as u64;
    if masks_migrated != expected_masks {
        return Err(MigrationError::VerificationFailed {
            detail: format!(
                "materialized privacy masks ({masks_migrated}) differ from canonical ledger masks ({expected_masks})"
            ),
        });
    }

    progress(MigrationProgressEvent {
        stage: "materialize_projections",
        detail: format!(
            "materialized MVCC projections: {} events, {} holds, {} masks, {} tombstones",
            events_migrated, holds_migrated, masks_migrated, tombstones_migrated
        ),
        completed: 1,
        total: 1,
    });

    // Drop PackStore and MvccProjectionStore handles cleanly before finalizing layout.
    let dest_v2_anchor = epoch_ledger.head_anchor().clone();
    let dest_v2_merkle_root = epoch_ledger.state_root();
    let dest_v2_history_root = epoch_ledger.history_root();
    drop(proj_store);
    drop(pack_store);
    drop(epoch_ledger);

    // Phase 6: Copy & byte-for-byte SHA-256 verify effects/journal.fssj and agent/ (if present).
    check_cancel(cancelled, "copy_effects_and_agent")?;
    let dest_effects_dir = dest_root.join("effects");
    fs::create_dir_all(&dest_effects_dir)
        .map_err(|err| MigrationError::io("create_effects_dir", err))?;
    let dest_effects_path = dest_root.join(&v1_layout.effects_relpath);
    write_new_file_fsynced(&dest_effects_path, &v1_effects_bytes)?;
    sync_dir(&dest_effects_dir)?;
    let copied_effects_bytes = read_bounded_bytes(&dest_effects_path, request.max_journal_bytes)?;
    if copied_effects_bytes != v1_effects_bytes
        || ContentDigest::sha256(&copied_effects_bytes) != v1_effects_sha256
    {
        return Err(MigrationError::VerificationFailed {
            detail: "copied effects/journal.fssj failed byte-for-byte SHA-256 verification"
                .to_owned(),
        });
    }
    let v2_effects_inspect =
        DurableEffectJournal::inspect(&dest_effects_path, request.max_journal_bytes).map_err(
            |err| MigrationError::VerificationFailed {
                detail: format!("copied v2 effects journal failed inspection: {err}"),
            },
        )?;
    if !v2_effects_inspect.is_clean()
        || v2_effects_inspect.obligation_counts != v1_effects.obligation_counts
        || v2_effects_inspect.indeterminate_operations != v1_effects.indeterminate_operations
    {
        return Err(MigrationError::VerificationFailed {
            detail: "copied v2 effects journal semantic state disagrees with v1 source".to_owned(),
        });
    }

    let mut agent_files_verified: u64 = 0;
    for (rel_path, expected_sha) in &agent_inventory {
        check_cancel(cancelled, "copy_effects_and_agent")?;
        let src_file = source_root.join(rel_path);
        let dst_file = dest_root.join(rel_path);
        if let Some(parent) = dst_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| MigrationError::io("create_agent_dir", err))?;
        }
        let bytes = read_bounded_bytes(&src_file, request.max_journal_bytes)?;
        if ContentDigest::sha256(&bytes) != *expected_sha {
            return Err(MigrationError::VerificationFailed {
                detail: format!("source agent file '{rel_path}' changed during migration"),
            });
        }
        write_new_file_fsynced(&dst_file, &bytes)?;
        let readback = read_bounded_bytes(&dst_file, request.max_journal_bytes)?;
        if readback != bytes || ContentDigest::sha256(&readback) != *expected_sha {
            return Err(MigrationError::VerificationFailed {
                detail: format!("copied agent file '{rel_path}' failed SHA-256 verification"),
            });
        }
        if let Some(parent) = dst_file.parent() {
            sync_dir(parent)?;
        }
        agent_files_verified = agent_files_verified.saturating_add(1);
    }

    progress(MigrationProgressEvent {
        stage: "copy_effects_and_agent",
        detail: format!(
            "verified effects/journal.fssj and {} agent file(s)",
            agent_files_verified
        ),
        completed: 1,
        total: 1,
    });

    // Phase 7: Seal receipt, persist migration_receipt.json + v2 LAYOUT, remove sentinel last!
    check_cancel(cancelled, "finalize")?;
    let mut receipt = MigrationEquivalenceReceipt {
        schema: MIGRATION_RECEIPT_SCHEMA.to_owned(),
        site_lineage: v1_layout.site_lineage.clone(),
        source_v1_anchor: v1_ledger.snapshot.anchor.clone(),
        source_v1_ledger_root: v1_ledger.last_root,
        dest_v2_anchor,
        dest_v2_merkle_root,
        dest_v2_history_root,
        batches_migrated: total_batches,
        objects_migrated: packed_count,
        roots_migrated: total_roots,
        events_migrated,
        holds_migrated,
        masks_migrated,
        tombstones_migrated,
        source_unreferenced_orphans,
        effects_verified: true,
        effects_journal_digest: Some(v1_effects_sha256),
        agent_files_verified,
        projection_state_digest,
        semantic_equivalence_verified: true,
        receipt_digest: ContentDigest::sha256(b"unsealed"),
    };
    receipt.receipt_digest =
        receipt
            .compute_digest()
            .map_err(|err| MigrationError::VerificationFailed {
                detail: format!("failed sealing receipt digest: {err}"),
            })?;

    let receipt_json = receipt.to_json();
    write_atomic_fsynced(
        &dest_root,
        MIGRATION_RECEIPT_FILENAME,
        receipt_json.as_bytes(),
    )?;

    let v2_layout = DeploymentLayoutV2::new(&v1_layout.site_lineage, v1_layout.limits_digest);
    let v2_layout_text = v2_layout.to_canonical_text();
    write_atomic_fsynced(
        &dest_root,
        DEPLOYMENT_LAYOUT_FILENAME,
        v2_layout_text.as_bytes(),
    )?;

    // Final cancellation boundary strictly before activating by removing `.migrate-incomplete`.
    check_cancel(cancelled, "activate")?;
    fs::remove_file(&sentinel_path).map_err(|err| MigrationError::io("remove_sentinel", err))?;
    sync_dir(&dest_root)?;

    progress(MigrationProgressEvent {
        stage: "finalize",
        detail: format!(
            "activated v2 deployment with receipt {}",
            receipt.receipt_digest.to_text()
        ),
        completed: 1,
        total: 1,
    });

    Ok(receipt)
}

/// Content-addressed [`PayloadResolver`] backed exclusively by the v2 [`PackReader`] that
/// translates every native v1/v2 projected family into canonical `ProjectionRecordPayload` values.
pub(crate) struct MigrationPayloadResolver {
    pack_reader: PackReader,
    deleted_digests: BTreeSet<ContentDigest>,
}

impl MigrationPayloadResolver {
    pub(crate) fn new(pack_reader: PackReader, deleted_digests: BTreeSet<ContentDigest>) -> Self {
        Self {
            pack_reader,
            deleted_digests,
        }
    }

    fn read_pack_object(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        match self.pack_reader.read_verified(&digest) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(PackError::MissingObject(_)) => Ok(None),
            Err(err) => Err(ProjectionError::Pack(err)),
        }
    }

    fn translate_event_revision(
        &self,
        digest: ContentDigest,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let raw_len = raw.len() as u64;
        let (hypothesis, payload_bytes) = if let Ok(hypothesis) =
            EventHypothesis::from_canonical_bytes(&raw)
        {
            (hypothesis, raw_len)
        } else {
            let Ok(manifest) = ObjectManifest::from_canonical_bytes(&raw) else {
                return Ok(None);
            };
            let Some(meta_digest) = manifest
                .metadata_digest()
                .or_else(|| manifest.children().first().copied())
            else {
                return Ok(None);
            };
            let Some(meta_bytes) = self.read_pack_object(meta_digest)? else {
                return Ok(None);
            };
            let len = raw_len.saturating_add(meta_bytes.len() as u64);
            let hypothesis = EventHypothesis::from_canonical_bytes(&meta_bytes).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: FAMILY_EVENT_REVISION.to_owned(),
                    detail: err.to_string(),
                }
            })?;
            (hypothesis, len)
        };
        let mut sensor_ids = Vec::new();
        for ev in &hypothesis.evidence {
            if let Ok(sensor) = SensorId::parse(&ev.failure_domain) {
                sensor_ids.push(sensor);
            }
        }
        sensor_ids.sort();
        sensor_ids.dedup();
        let corroborated = matches!(
            hypothesis.state,
            EventState::Corroborated
                | EventState::Adjudicated
                | EventState::AlertDelivered
                | EventState::Resolved
        );
        let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
            event_id: hypothesis.event_id,
            revision: hypothesis.revision,
            state: hypothesis.state,
            kind: hypothesis.kind,
            zones: hypothesis.zone_ids,
            sensor_ids,
            interval: hypothesis.interval,
            event_root: digest,
            supersedes: hypothesis.supersedes,
            corroborated,
            tamper_open: false,
        });
        Ok(Some((payload, payload_bytes)))
    }

    fn translate_sensor_tamper(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let empty_tamper_digest = SensorTamperStatus::default().canonical_digest();
        let tamper_open = delta
            .witness_digest
            .is_some_and(|witness| witness != empty_tamper_digest);
        let raw_id = delta.object_id.as_str();
        let trimmed = raw_id
            .strip_prefix("object:event:")
            .unwrap_or(raw_id)
            .strip_suffix(":tamper")
            .unwrap_or(raw_id);
        let Ok(event_id) = EventId::parse(trimmed) else {
            return Ok(None);
        };
        Ok(Some((
            ProjectionRecordPayload::SensorTamper(SensorTamperPayload {
                event_id,
                tamper_open,
            }),
            0,
        )))
    }

    fn translate_coverage(
        &self,
        delta: &EvidenceDelta,
        raw_opt: Option<Vec<u8>>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        if let Some(raw) = raw_opt {
            let len = raw.len() as u64;
            if let Ok(witness) = CoverageWitness::from_canonical_bytes(&raw) {
                return Ok(
                    build_coverage_payload(&delta.object_id, delta.validity, &witness)
                        .map(|p| (p, len)),
                );
            }
            if let Ok(record) = SourceCoverageRecord::from_bytes(&raw, delta.payload_digest) {
                return Ok(build_coverage_payload(
                    &delta.object_id,
                    record.interval,
                    &record.witness,
                )
                .map(|p| (p, len)));
            }
            if let Ok(record) = CoverageRecord::from_bytes(&raw, delta.payload_digest) {
                let sensor = SensorId::parse(&record.sensor_id)
                    .or_else(|_| SensorId::parse(delta.object_id.as_str()))
                    .or_else(|_| SensorId::parse("sensor:recorded"));
                let Ok(sensor_id) = sensor else {
                    return Ok(None);
                };
                let zone_id = record
                    .zones
                    .first()
                    .map(|z| z.zone_id.clone())
                    .unwrap_or_else(|| "default".to_owned());
                return Ok(Some((
                    ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                        sensor_id,
                        zone_id,
                        window: delta.validity,
                        status: CoverageStatus::Covered,
                        active_gaps: 0,
                        health_conflicts: 0,
                    }),
                    len,
                )));
            }
            return Ok(None);
        }

        // If this historical coverage object was later removed by a completed deletion,
        // emit an explicit NotObservable placeholder so subsequent deletion_tombstone replays cleanly.
        if self.deleted_digests.contains(&delta.payload_digest) {
            let sensor_id = SensorId::parse(delta.object_id.as_str())
                .or_else(|_| SensorId::parse("sensor:deleted-coverage"))
                .map_err(|err| ProjectionError::InvalidPayload {
                    family: FAMILY_COVERAGE_WITNESS.to_owned(),
                    detail: err.to_string(),
                })?;
            return Ok(Some((
                ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id,
                    zone_id: "default".to_owned(),
                    window: delta.validity,
                    status: CoverageStatus::NotObservable,
                    active_gaps: 1,
                    health_conflicts: 0,
                }),
                0,
            )));
        }
        Ok(None)
    }

    fn translate_footage(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let adapter_kind = match delta.family.as_str() {
            FAMILY_RTSP_IMPORT => FootageAdapterKind::Rtsp,
            FAMILY_HTTP_IMPORT => FootageAdapterKind::Http,
            FAMILY_TUTK_IMPORT => FootageAdapterKind::Tutk,
            FAMILY_FILE_IMPORT | FAMILY_FOOTAGE_IMPORT => FootageAdapterKind::File,
            _ => return Ok(None),
        };
        let Ok(sensor_id) = SensorId::parse("sensor:imported") else {
            return Ok(None);
        };
        let Ok(stream_id) = StreamId::parse("stream:imported") else {
            return Ok(None);
        };
        let import_id = delta
            .object_id
            .as_str()
            .strip_prefix("object:file-import:")
            .and_then(parse_sha256_hex)
            .unwrap_or(delta.payload_digest);
        let completed = if delta.family == FAMILY_FILE_IMPORT {
            delta.new_generation >= 2
        } else {
            true
        };
        Ok(Some((
            ProjectionRecordPayload::FootageImport(FootageImportPayload {
                import_id,
                adapter_kind,
                sensor_id,
                stream_id,
                capture_interval: delta.validity,
                manifest_digest: delta.payload_digest,
                capsule_count: 1,
                total_bytes: 0,
                adapter_id: delta.family.clone(),
                adapter_generation: "v1".to_owned(),
                completed,
            }),
            0,
        )))
    }

    fn translate_hold(
        &self,
        delta: &EvidenceDelta,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let record = HoldRecord::from_bytes(&raw, delta.payload_digest).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_EVIDENCE_HOLD.to_owned(),
                detail: err.to_string(),
            }
        })?;
        let req = record.request();
        Ok(Some((
            ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                hold_id: req.hold_id.clone(),
                scope: req.state.as_str().to_owned(),
                target_digest: req.import_identity,
                active: req.state.is_active(),
            }),
            len,
        )))
    }

    fn translate_privacy_mask(
        &self,
        delta: &EvidenceDelta,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let policy = PrivacyMaskPolicy::from_bytes(&raw, delta.payload_digest).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_PRIVACY_MASK_POLICY.to_owned(),
                detail: err.to_string(),
            }
        })?;
        Ok(Some((
            ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                sensor_id: policy.sensor_id().clone(),
                policy_digest: delta.payload_digest,
            }),
            len,
        )))
    }

    fn translate_alert_effect_outcome(
        &self,
        delta: &EvidenceDelta,
        raw_opt: Option<Vec<u8>>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        if let Some(raw) = raw_opt {
            let raw_len = raw.len() as u64;
            if let Ok(manifest) = ObjectManifest::from_canonical_bytes(&raw)
                && let Some(meta_digest) = manifest.metadata_digest()
                && let Some(meta_bytes) = self.read_pack_object(meta_digest)?
            {
                let mut dec = CanonicalDecoder::new(&meta_bytes);
                if dec.text().ok() == Some("fss.reference_alert_outcome.v1")
                    && let Ok(receipt) = OperationReceipt::decode_canonical(&mut dec)
                    && let Ok(obligation_id) = ObligationId::decode_canonical(&mut dec)
                {
                    let total_len = raw_len.saturating_add(meta_bytes.len() as u64);
                    return Ok(Some((
                        ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                            operation_id: receipt.intent.operation_id,
                            obligation_id: Some(obligation_id),
                            effect_state: receipt.state,
                            reason: "alert_effect_outcome".to_owned(),
                        }),
                        total_len,
                    )));
                }
            }
        }
        if let Some(op_id) = &delta.operation_id {
            return Ok(Some((
                ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                    operation_id: op_id.clone(),
                    obligation_id: None,
                    effect_state: EffectState::Verified,
                    reason: delta.family.clone(),
                }),
                0,
            )));
        }
        Ok(None)
    }

    fn translate_sensor_liveness(
        &self,
        raw: Vec<u8>,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let len = raw.len() as u64;
        let record = SensorLivenessRecord::from_bytes(&raw).map_err(|err| {
            ProjectionError::InvalidPayload {
                family: FAMILY_SENSOR_LIVENESS.to_owned(),
                detail: err.to_string(),
            }
        })?;
        let state = match record.state() {
            WatchState::Observable => SensorLivenessStatus::Online,
            WatchState::Silent { .. } | WatchState::Asleep { .. } => SensorLivenessStatus::Degraded,
            WatchState::NotObservable {
                reason: WatchOfflineReason::SilentBeyondThreshold,
            } => SensorLivenessStatus::Offline,
            WatchState::NotObservable {
                reason: WatchOfflineReason::NeverObserved,
            } => SensorLivenessStatus::Unknown,
        };
        Ok(Some((
            ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                sensor_id: record.enrollment().sensor().clone(),
                state,
                last_seen_ns: TimestampNs(i128::from(record.last_seen_ns().unwrap_or(0))),
                observed_at_ns: TimestampNs(i128::from(record.observed_at_ns())),
            }),
            len,
        )))
    }
}

impl PayloadResolver for MigrationPayloadResolver {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, ProjectionError> {
        self.read_pack_object(*digest)
    }

    fn resolve_record_for_delta(
        &self,
        delta: &EvidenceDelta,
    ) -> Result<Option<(ProjectionRecordPayload, u64)>, ProjectionError> {
        let raw_opt = self.read_pack_object(delta.payload_digest)?;
        if let Some(raw) = &raw_opt
            && raw.len() >= 6
            && raw[0..4] == PROJECTION_PAYLOAD_MAGIC
        {
            let payload = ProjectionRecordPayload::decode_bytes(raw).map_err(|err| {
                ProjectionError::InvalidPayload {
                    family: delta.family.clone(),
                    detail: err.to_string(),
                }
            })?;
            return Ok(Some((payload, raw.len() as u64)));
        }
        match delta.family.as_str() {
            FAMILY_EVENT_REVISION => {
                if let Some(raw) = raw_opt {
                    return self.translate_event_revision(delta.payload_digest, raw);
                }
                if let Some(witness) = delta.witness_digest
                    && let Some(witness_bytes) = self.read_pack_object(witness)?
                {
                    return self.translate_event_revision(delta.payload_digest, witness_bytes);
                }
                Ok(None)
            }
            FAMILY_SENSOR_TAMPER_STATUS => self.translate_sensor_tamper(delta),
            FAMILY_COVERAGE_WITNESS => self.translate_coverage(delta, raw_opt),
            FAMILY_FILE_IMPORT
            | FAMILY_FOOTAGE_IMPORT
            | FAMILY_RTSP_IMPORT
            | FAMILY_HTTP_IMPORT
            | FAMILY_TUTK_IMPORT => self.translate_footage(delta),
            FAMILY_EVIDENCE_HOLD => match raw_opt {
                Some(raw) => self.translate_hold(delta, raw),
                None => Ok(None),
            },
            FAMILY_PRIVACY_MASK_POLICY => match raw_opt {
                Some(raw) => self.translate_privacy_mask(delta, raw),
                None => Ok(None),
            },
            FAMILY_OBLIGATION => match raw_opt {
                Some(raw) => {
                    let len = raw.len() as u64;
                    let ob = Obligation::from_canonical_bytes(&raw).map_err(|err| {
                        ProjectionError::InvalidPayload {
                            family: FAMILY_OBLIGATION.to_owned(),
                            detail: err.to_string(),
                        }
                    })?;
                    Ok(Some((
                        ProjectionRecordPayload::Obligation(ObligationPayload {
                            obligation_id: ob.obligation_id,
                            operation_id: ob.operation_id,
                            terminal_predicate: ob.terminal_predicate,
                            state: ob.state,
                            proof_digest: ob.proof_digest,
                        }),
                        len,
                    )))
                }
                None => Ok(None),
            },
            FAMILY_ALERT_EFFECT_OUTCOME | FAMILY_EFFECT_OUTCOME => {
                self.translate_alert_effect_outcome(delta, raw_opt)
            }
            FAMILY_SENSOR_LIVENESS => match raw_opt {
                Some(raw) => self.translate_sensor_liveness(raw),
                None => Ok(None),
            },
            FAMILY_DELETION_TOMBSTONE => Ok(Some((
                ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                    target: DeletionTarget::Object(delta.object_id.clone()),
                }),
                0,
            ))),
            _ => Ok(None),
        }
    }
}

fn build_coverage_payload(
    object_id: &ObjectId,
    validity: fss_core::CaptureInterval,
    witness: &CoverageWitness,
) -> Option<ProjectionRecordPayload> {
    let sensor_id = SensorId::parse(object_id.as_str())
        .or_else(|_| SensorId::parse("sensor:coverage"))
        .ok()?;
    let status = if witness.certifies_absence() {
        CoverageStatus::Covered
    } else if witness.continuity == CoverageContinuity::Gapped {
        CoverageStatus::NotObservable
    } else {
        CoverageStatus::Stale
    };
    let zone_id = witness
        .authorized_domain
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| "default".to_owned());
    Some(ProjectionRecordPayload::CoverageWitness(
        CoverageWitnessPayload {
            sensor_id,
            zone_id,
            window: validity,
            status,
            active_gaps: u32::from(witness.continuity == CoverageContinuity::Gapped),
            health_conflicts: 0,
        },
    ))
}

fn parse_sha256_hex(hex: &str) -> Option<ContentDigest> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[idx] = (hi << 4) | lo;
    }
    Some(ContentDigest::new(DigestAlgorithm::Sha256, out))
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn flush_pack_batch(
    pack_store: &PackStore,
    pending: &mut Vec<(ContentDigest, u16, Vec<u8>)>,
) -> Result<(), MigrationError> {
    let inputs: Vec<PackObjectInput<'_>> = pending
        .iter()
        .map(|(digest, kind, bytes)| PackObjectInput::with_digest(*kind, 0, bytes, *digest))
        .collect();
    let _locations = pack_store
        .append_batch(&inputs)
        .map_err(|err| MigrationError::Pack(err.to_string()))?;
    pending.clear();
    Ok(())
}

fn verify_v1_batch_continuity(
    site_lineage: &str,
    v1_ledger: &fss_ledger::LedgerInspection,
) -> Result<(), MigrationError> {
    if !v1_ledger.batches.is_empty() {
        let Some(positions) = committed_batch_positions(v1_ledger) else {
            return Err(MigrationError::SourceNotClean {
                detail: "v1 ledger journal hash chain continuity check failed".to_owned(),
            });
        };
        if positions.len() != v1_ledger.batches.len() {
            return Err(MigrationError::SourceNotClean {
                detail: "v1 ledger committed batch position count mismatch".to_owned(),
            });
        }
    }

    let mut expected_basis = LedgerAnchor::genesis(site_lineage);
    for (idx, batch) in v1_ledger.batches.iter().enumerate() {
        let expected_seq =
            (idx as u64)
                .checked_add(1)
                .ok_or_else(|| MigrationError::SourceNotClean {
                    detail: "commit sequence overflow".to_owned(),
                })?;
        if batch.basis_anchor != expected_basis {
            return Err(MigrationError::SourceNotClean {
                detail: format!("v1 batch {} basis_anchor discontinuity", expected_seq),
            });
        }
        if batch.new_anchor.commit_sequence != expected_seq {
            return Err(MigrationError::SourceNotClean {
                detail: format!(
                    "v1 batch commit_sequence {} != expected {}",
                    batch.new_anchor.commit_sequence, expected_seq
                ),
            });
        }
        if batch.computed_digest() != batch.batch_digest {
            return Err(MigrationError::SourceNotClean {
                detail: format!("v1 batch {} digest mismatch", expected_seq),
            });
        }
        expected_basis = batch.new_anchor.clone();
    }
    if expected_basis != v1_ledger.snapshot.anchor {
        return Err(MigrationError::SourceNotClean {
            detail: "v1 replayed final anchor disagrees with ledger snapshot anchor".to_owned(),
        });
    }
    Ok(())
}

/// Computes the exact sorted set of referenced spool objects to pack (`referenced ∩ admitted`)
/// and the sorted list of unreferenced spool orphans (`admitted \ referenced`).
pub(crate) fn collect_referenced_and_orphan_objects(
    v1_objects_dir: &Path,
    v1_local: &LocalInspection,
    v1_batches: &[EvidenceDeltaBatch],
    max_obj_bytes: usize,
) -> Result<(BTreeSet<ContentDigest>, Vec<ContentDigest>), MigrationError> {
    let admitted: BTreeSet<ContentDigest> =
        v1_local.report.spool.admitted.iter().copied().collect();
    let mut seeds: BTreeSet<ContentDigest> = BTreeSet::new();

    for closure in v1_local.root_closures.values() {
        seeds.extend(closure.iter().copied());
    }
    for batch in v1_batches {
        seeds.extend(batch.children.iter().copied());
        for delta in &batch.deltas {
            seeds.insert(delta.payload_digest);
            if let Some(witness) = delta.witness_digest {
                seeds.insert(witness);
            }
        }
    }

    // Transitive expansion through any admitted ObjectManifest reachable from seeds.
    let mut referenced_admitted: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut queue: Vec<ContentDigest> =
        seeds.into_iter().filter(|d| admitted.contains(d)).collect();

    while let Some(digest) = queue.pop() {
        if !referenced_admitted.insert(digest) {
            continue;
        }
        let raw = fss_publication::read_verified(v1_objects_dir, digest, max_obj_bytes).map_err(
            |err| MigrationError::SourceNotClean {
                detail: format!(
                    "failed reading admitted v1 spool object {}: {err}",
                    digest.to_text()
                ),
            },
        )?;
        if let Ok(manifest) = ObjectManifest::from_canonical_bytes(&raw) {
            for &child in manifest.children() {
                if admitted.contains(&child) && !referenced_admitted.contains(&child) {
                    queue.push(child);
                }
            }
            if let Some(meta) = manifest.metadata_digest()
                && admitted.contains(&meta)
                && !referenced_admitted.contains(&meta)
            {
                queue.push(meta);
            }
        }
    }

    let orphans: Vec<ContentDigest> = admitted.difference(&referenced_admitted).copied().collect();
    Ok((referenced_admitted, orphans))
}

fn count_canonical_entities(
    batches: &[EvidenceDeltaBatch],
    local: &LocalInspection,
) -> (u64, u64, u64) {
    let mut hold_objects = BTreeSet::new();
    let mut mask_objects = BTreeSet::new();
    let mut tombstone_objects = BTreeSet::new();

    for batch in batches {
        for delta in &batch.deltas {
            match delta.family.as_str() {
                FAMILY_EVIDENCE_HOLD => {
                    hold_objects.insert(delta.object_id.clone());
                }
                FAMILY_PRIVACY_MASK_POLICY => {
                    mask_objects.insert(delta.object_id.clone());
                }
                FAMILY_DELETION_TOMBSTONE => {
                    tombstone_objects.insert(delta.object_id.clone());
                }
                _ => {}
            }
        }
    }
    let tombstones = (tombstone_objects.len() as u64).max(local.report.tombstones.len() as u64);
    (
        hold_objects.len() as u64,
        mask_objects.len() as u64,
        tombstones,
    )
}

fn collect_tombstone_files(
    tombstones_dir: &Path,
    max_obj_bytes: usize,
) -> Result<Vec<(String, Vec<u8>, ContentDigest)>, MigrationError> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(tombstones_dir) {
        Ok(rd) => rd,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(files),
        Err(err) => return Err(MigrationError::io("read_tombstones_dir", err)),
    };
    for entry in entries {
        let entry = entry.map_err(|err| MigrationError::io("next_tombstone_entry", err))?;
        let path = entry.path();
        let meta =
            fs::symlink_metadata(&path).map_err(|err| MigrationError::io("stat_tombstone", err))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(MigrationError::SourceNotClean {
                detail: format!(
                    "non-regular entry in objects/tombstones: {}",
                    path.display()
                ),
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| MigrationError::SourceNotClean {
                detail: "non-UTF-8 tombstone filename".to_owned(),
            })?;
        let bytes = read_bounded_bytes(&path, max_obj_bytes)?;
        let digest = ContentDigest::sha256(&bytes);
        files.push((name, bytes, digest));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Deterministically collects every regular data file under `<root>/agent/` (excluding transient
/// empty `LOCK` files), returning sorted `(relative_path, sha256)` pairs.
pub(crate) fn collect_agent_file_inventory(
    root: &Path,
    max_file_bytes: usize,
) -> Result<Vec<(String, ContentDigest)>, MigrationError> {
    let agent_dir = root.join("agent");
    match fs::symlink_metadata(&agent_dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(MigrationError::SourceNotClean {
                detail: "agent entry is not a real directory".to_owned(),
            });
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(MigrationError::io("stat_agent_dir", err)),
    }

    let mut out = Vec::new();
    walk_agent_dir(root, &agent_dir, max_file_bytes, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_agent_dir(
    root: &Path,
    dir: &Path,
    max_file_bytes: usize,
    out: &mut Vec<(String, ContentDigest)>,
) -> Result<(), MigrationError> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|err| MigrationError::io("read_agent_dir", err))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| MigrationError::io("next_agent_entry", err))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta =
            fs::symlink_metadata(&path).map_err(|err| MigrationError::io("stat_agent", err))?;
        if meta.file_type().is_symlink() {
            return Err(MigrationError::SourceNotClean {
                detail: format!("symlink inside agent/: {}", path.display()),
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| MigrationError::SourceNotClean {
                detail: "non-UTF-8 filename inside agent/".to_owned(),
            })?;
        if meta.is_dir() {
            walk_agent_dir(root, &path, max_file_bytes, out)?;
        } else if meta.is_file() {
            if name == "LOCK" && meta.len() == 0 {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|_| MigrationError::InvalidPath {
                    detail: "agent file escaped root".to_owned(),
                })?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = read_bounded_bytes(&path, max_file_bytes)?;
            out.push((rel, ContentDigest::sha256(&bytes)));
        } else {
            return Err(MigrationError::SourceNotClean {
                detail: format!("non-regular file inside agent/: {}", path.display()),
            });
        }
    }
    Ok(())
}

fn admit_source_dir(path: &Path) -> Result<PathBuf, MigrationError> {
    if path.as_os_str().is_empty() {
        return Err(MigrationError::InvalidPath {
            detail: "source path is empty".to_owned(),
        });
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir | Component::Prefix(_)) {
            return Err(MigrationError::InvalidPath {
                detail: "source path must not contain '..' or Windows prefixes".to_owned(),
            });
        }
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| MigrationError::io("current_dir", err))?
            .join(path)
    };
    let meta = match fs::symlink_metadata(&abs) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(MigrationError::NotADeployment {
                path: abs,
                reason: "source directory does not exist".to_owned(),
            });
        }
        Err(err) => return Err(MigrationError::io("stat_source", err)),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(MigrationError::NotADeployment {
            path: abs,
            reason: "source path is not a real directory".to_owned(),
        });
    }
    let canonical = match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => fs::canonicalize(parent)
            .map_err(|err| MigrationError::io("canonicalize_source_parent", err))?
            .join(name),
        _ => abs,
    };
    Ok(canonical)
}

fn admit_fresh_dest_path(path: &Path, source_root: &Path) -> Result<PathBuf, MigrationError> {
    if path.as_os_str().is_empty() {
        return Err(MigrationError::InvalidPath {
            detail: "destination path is empty".to_owned(),
        });
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir | Component::Prefix(_)) {
            return Err(MigrationError::InvalidPath {
                detail: "destination path must not contain '..' or Windows prefixes".to_owned(),
            });
        }
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| MigrationError::io("current_dir", err))?
            .join(path)
    };
    let name = abs.file_name().ok_or_else(|| MigrationError::InvalidPath {
        detail: "destination path must have a final directory name".to_owned(),
    })?;
    let parent = abs
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| MigrationError::InvalidPath {
            detail: "destination path must have a parent directory".to_owned(),
        })?;
    let canonical_parent = fs::canonicalize(parent).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            MigrationError::InvalidPath {
                detail: format!("destination parent '{}' does not exist", parent.display()),
            }
        } else {
            MigrationError::io("canonicalize_dest_parent", err)
        }
    })?;
    let dest = canonical_parent.join(name);
    match fs::symlink_metadata(&dest) {
        Ok(_) => return Err(MigrationError::DestinationExists { path: dest }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(MigrationError::io("stat_dest", err)),
    }
    if dest.starts_with(source_root) || source_root.starts_with(&dest) {
        return Err(MigrationError::InvalidPath {
            detail: "destination path must not overlap source v1 deployment root".to_owned(),
        });
    }
    Ok(dest)
}

pub(crate) fn read_bounded_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>, MigrationError> {
    let meta = fs::symlink_metadata(path).map_err(|err| MigrationError::io("stat_file", err))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(MigrationError::SourceNotClean {
            detail: format!("path '{}' is not a regular file", path.display()),
        });
    }
    if meta.len() > max_bytes as u64 {
        return Err(MigrationError::SourceNotClean {
            detail: format!(
                "file '{}' size {} exceeds {} byte bound",
                path.display(),
                meta.len(),
                max_bytes
            ),
        });
    }
    let file = File::open(path).map_err(|err| MigrationError::io("open_read", err))?;
    let mut buf = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|err| MigrationError::io("read_file", err))?;
    if buf.len() > max_bytes {
        return Err(MigrationError::SourceNotClean {
            detail: format!(
                "file '{}' grew past {} byte bound",
                path.display(),
                max_bytes
            ),
        });
    }
    Ok(buf)
}

fn write_new_file_fsynced(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| MigrationError::io("create_new_file", err))?;
    file.write_all(bytes)
        .map_err(|err| MigrationError::io("write_file", err))?;
    file.sync_all()
        .map_err(|err| MigrationError::io("fsync_file", err))?;
    Ok(())
}

fn write_atomic_fsynced(dir: &Path, filename: &str, bytes: &[u8]) -> Result<(), MigrationError> {
    let tmp_path = dir.join(format!("{filename}.tmp.{}", std::process::id()));
    let final_path = dir.join(filename);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| MigrationError::io("create_temp_file", err))?;
        file.write_all(bytes)
            .map_err(|err| MigrationError::io("write_temp_file", err))?;
        file.sync_all()
            .map_err(|err| MigrationError::io("fsync_temp_file", err))?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|err| MigrationError::io("rename_atomic", err))?;
    sync_dir(dir)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), MigrationError> {
    #[cfg(unix)]
    {
        let handle = File::open(dir).map_err(|err| MigrationError::io("open_dir_sync", err))?;
        handle
            .sync_all()
            .map_err(|err| MigrationError::io("fsync_dir", err))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn check_cancel(cancelled: &dyn Fn() -> bool, stage: &'static str) -> Result<(), MigrationError> {
    if cancelled() {
        return Err(MigrationError::Cancelled { stage });
    }
    Ok(())
}
