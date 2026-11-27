#![forbid(unsafe_code)]
//! Retention publication checks precede irreversible canonical query retirement.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::StreamId;
use fss_pack::{MediaCodec, PackObjectInput, VirtualRootRecord};
use fss_reference::ingest::model_pool::FramePixelInput;

use super::*;
use crate::regions::DaemonRegionTree;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) struct TestDirectory(pub(super) PathBuf);

impl TestDirectory {
    pub(super) fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-retention-preparation-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn manifest() -> Result<SiteManifest, DaemonError> {
    SiteManifest::parse_json(
        r#"{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-retention-preparation",
  "ring_cap_bytes": 1048576,
  "retain_hot_ns": 1000,
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [{
    "sensor_id": "sensor:retention",
    "adapter": "synthetic",
    "endpoint": "synthetic://retention",
    "secret_id": "secret:retention:a",
    "priority_tier": "standard",
    "zone_id": "driveway",
    "dimensions": [32, 32],
    "failure_domains": ["power:circuit-a"],
    "gop_frames": 1
  }]
}"#,
    )
}

pub(super) fn ingest(storage: &mut StorageEngine, regions: &DaemonRegionTree) -> TestResult {
    ingest_number(storage, regions, 1)
}

fn ingest_number(
    storage: &mut StorageEngine,
    regions: &DaemonRegionTree,
    sequence: u64,
) -> TestResult {
    ingest_for_sensor(storage, regions, sequence, "sensor:retention")
}

fn ingest_for_sensor(
    storage: &mut StorageEngine,
    regions: &DaemonRegionTree,
    sequence: u64,
    sensor: &str,
) -> TestResult {
    let luma = vec![0; 32 * 32];
    let mut encoded_payload = b"FSSA".to_vec();
    encoded_payload.extend_from_slice(&sequence.to_be_bytes());
    encoded_payload.extend_from_slice(&1_u64.to_be_bytes());
    encoded_payload.extend_from_slice(&luma);
    let source_digest = ContentDigest::sha256(&encoded_payload);
    let frame = CameraFrame {
        sensor_id: SensorId::parse(sensor)?,
        stream_generation: 1,
        stream_id: StreamId::parse("stream:retention:g1")?,
        sequence,
        media_pts_ns: 9 + i128::from(sequence),
        host_receive_ns: 9 + i128::from(sequence),
        rtt_jitter_ns: 0,
        node_clock_uncertainty_ns: 0,
        codec: MediaCodec::H264,
        is_keyframe: true,
        discontinuity_before: false,
        dimensions: [32, 32],
        encoded_payload,
        pixels: FramePixelInput::Luma { pixels: luma },
        source_digest,
        zone_id: "driveway".to_owned(),
        synthetic_detections: Vec::new(),
    };
    assert!(
        storage
            .ingest_frame(
                Arc::new(frame),
                CameraAdapterKind::Synthetic,
                1,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )?
            .is_some()
    );
    Ok(())
}

#[test]
fn stale_pack_reference_refuses_before_canonical_footage_retirement() -> TestResult {
    for (as_metadata, references_import_metadata) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let candidate = storage
            .retention_candidates()
            .values()
            .next()
            .ok_or("missing retained GOP")?
            .clone();
        let original = storage
            .pack_store
            .get_root(&candidate.import_id)?
            .ok_or("missing GOP catalog root")?;
        let media = original.record.root_digest;
        let metadata = original
            .record
            .metadata_digest
            .ok_or("missing GOP metadata")?;
        let RetentionPlanOutcome::Evict(batch) = plan_retention(
            &storage.retention_config,
            &storage.retention_plan_candidates_for_eviction()?,
            TimestampNs(10_000),
        )?
        else {
            return Err("fixture did not select an expired GOP".into());
        };

        // Publish after planning, as an independent catalog owner can do while a
        // maintenance tick is between its reference-pin scan and eviction execution.
        let descriptor_bytes = b"independent catalog descriptor";
        storage.pack_store.append_batch(&[PackObjectInput::new(
            PACK_KIND_METADATA,
            0,
            descriptor_bytes,
        )])?;
        let descriptor = ContentDigest::sha256(descriptor_bytes);
        let reference = if references_import_metadata {
            metadata
        } else {
            media
        };
        storage.pack_store.publish_root(VirtualRootRecord::new(
            "foreign-reference",
            if as_metadata { descriptor } else { reference },
            "retained-evidence",
            1,
            candidate.byte_size,
            1,
            TimestampNs(10),
            as_metadata.then_some(reference),
        )?)?;
        let before = storage.projection.head_anchor();
        let result = storage.execute_eviction_and_compaction(
            &batch,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        );
        let Err(error) = result else {
            return Err("stale plan unexpectedly retired retained footage".into());
        };
        assert!(error.to_string().contains("eviction"));
        assert_eq!(storage.projection.head_anchor(), before);
        assert!(
            storage
                .projection
                .snapshot_latest()
                .get_footage_import(&media)
                .is_some()
        );
        assert!(storage.pack_store.object_tombstone(&media)?.is_none());
        assert!(storage.pack_store.lookup(&media)?.is_some());
        assert!(matches!(
            storage
                .pack_store
                .get_root(&candidate.import_id)?
                .ok_or("missing GOP")?
                .status,
            RootStatus::Live
        ));
        assert!(
            storage
                .retention_candidates()
                .contains_key(&candidate.import_id)
        );
        storage.shutdown_and_flush()?;
    }
    Ok(())
}

pub(super) fn selected_batch(
    storage: &StorageEngine,
) -> Result<RetentionEvictionBatch, Box<dyn std::error::Error>> {
    match plan_retention(
        &storage.retention_config,
        &storage.retention_plan_candidates_for_eviction()?,
        TimestampNs(10_000),
    )? {
        RetentionPlanOutcome::Evict(batch) => Ok(batch),
        RetentionPlanOutcome::QuotaPinned {
            partial_eviction: Some(batch),
            ..
        } => Ok(batch),
        _ => Err("fixture did not select expired source".into()),
    }
}

pub(super) fn targets(storage: &StorageEngine) -> Vec<ContentDigest> {
    storage
        .candidate_roots
        .values()
        .map(|root| root.media_digest)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[test]
fn canonical_retirement_recovers_exact_reason_after_reopen_without_new_commit() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    let tomb = batch.tombstones.first().ok_or("missing tombstone")?.clone();
    let metadata = storage.candidate_roots[&tomb.import_id].metadata_digest;
    storage.commit_retention_deletions(
        &batch,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let committed_head = storage.projection.head_anchor();
    let intent_digests: Vec<_> = storage.retention_intents.keys().copied().collect();
    assert_eq!(intent_digests.len(), 1);
    assert!(matches!(
        storage
            .pack_store
            .get_root(&tomb.import_id)?
            .ok_or("missing root")?
            .status,
        RootStatus::Live
    ));
    assert!(
        storage
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?
            .is_none()
    );
    // Crash cut: canonical retirement succeeded; no catalog/object tombstone was attempted.
    storage.shutdown_and_flush()?;
    let reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.projection.head_anchor(), committed_head);
    assert!(reopened.retention_intents.is_empty());
    assert!(reopened.retention_candidates().is_empty());
    assert_eq!(
        reopened
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?,
        Some(tomb.reason_digest)
    );
    assert!(
        reopened
            .pack_store
            .lookup(&tomb.object_digests[0])?
            .is_none()
    );
    assert!(matches!(
        reopened.pack_store.get_root(&tomb.import_id)?.ok_or("missing tombstone")?.status,
        RootStatus::Tombstoned { reason_digest, .. } if reason_digest == tomb.reason_digest
    ));
    assert!(
        reopened
            .pack_store
            .read_verified_with_budget(&metadata, &PackReadBudget::new(64 * 1024))
            .is_ok()
    );
    assert!(
        reopened
            .pack_store
            .read_verified_with_budget(&intent_digests[0], &PackReadBudget::new(64 * 1024))
            .is_ok()
    );
    reopened.shutdown_and_flush()?;
    let again = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(again.projection.head_anchor(), committed_head);
    assert_eq!(
        again.pack_store.object_tombstone(&tomb.object_digests[0])?,
        Some(tomb.reason_digest)
    );
    again.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn partial_256_target_commit_recovers_only_its_committed_prefix() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    for sequence in 1..=257 {
        ingest_number(&mut storage, &regions, sequence)?;
    }
    let batch = selected_batch(&storage)?;
    let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
    assert_eq!(intents.len(), 257);
    storage.commit_retention_intent_chunk(
        &intents[..256],
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let head = storage.projection.head_anchor();
    let suffix = intents[256].1.source;
    // The next target wave never submitted. It must retain both its import and source.
    storage.shutdown_and_flush()?;
    let reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.projection.head_anchor(), head);
    for (_, intent, _) in &intents[..256] {
        assert!(
            reopened
                .pack_store
                .object_tombstone(&intent.source)?
                .is_some()
        );
        assert!(
            reopened
                .projection
                .snapshot_latest()
                .get_footage_import(&intent.source)
                .is_none()
        );
    }
    assert!(reopened.pack_store.object_tombstone(&suffix)?.is_none());
    assert!(reopened.pack_store.lookup(&suffix)?.is_some());
    assert!(
        reopened
            .projection
            .snapshot_latest()
            .get_footage_import(&suffix)
            .is_some()
    );
    assert_eq!(reopened.retention_candidates().len(), 1);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn lost_retirement_receipt_fences_running_owner_until_canonical_replay() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
    storage.commit_retention_intent_chunk(
        &intents,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let head = storage.projection.head_anchor();
    // Model lost acknowledgement after the real canonical commit: discard only volatile
    // receipt bookkeeping, then deliver an uncertain outcome at the submission boundary.
    storage.retention_intents.clear();
    assert!(
        storage
            .accept_retention_intent_result(
                &intents,
                Err(CombinerError::SinkFailure(
                    "lost durable acknowledgement".to_owned()
                )),
            )
            .is_err()
    );
    assert!(storage.retention_reopen_required);
    assert!(storage.resume_committed_retention_intents().is_err());
    assert!(
        storage
            .commit_retention_deletions(&batch, regions.storage_ledger_cx(), regions.region_tree(),)
            .is_err()
    );
    assert_eq!(storage.projection.head_anchor(), head);
    assert!(
        storage
            .pack_store
            .object_tombstone(&intents[0].1.source)?
            .is_none()
    );
    storage.shutdown_and_flush()?;
    let reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.projection.head_anchor(), head);
    assert!(
        reopened
            .pack_store
            .object_tombstone(&intents[0].1.source)?
            .is_some()
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn hold_published_after_canonical_retirement_defers_recovery_until_release() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    let tomb = batch.tombstones.first().ok_or("missing tombstone")?.clone();
    storage.commit_retention_deletions(
        &batch,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    assert!(storage.set_candidate_hold(
        &tomb.import_id,
        "hold:after-retirement",
        true,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?);
    storage.shutdown_and_flush()?;
    let mut reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.retention_intents.len(), 1);
    assert!(
        reopened
            .pack_store
            .lookup(&tomb.object_digests[0])?
            .is_some()
    );
    assert!(
        reopened
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?
            .is_none()
    );
    assert!(reopened.set_candidate_hold(
        &tomb.import_id,
        "hold:after-retirement",
        false,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?);
    let released_head = reopened.projection.head_anchor();
    reopened.resume_committed_retention_intents()?;
    assert_eq!(reopened.projection.head_anchor(), released_head);
    assert_eq!(
        reopened
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?,
        Some(tomb.reason_digest)
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn new_source_or_metadata_references_defer_exact_intent_recovery() -> TestResult {
    for (as_metadata, import_metadata) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let batch = selected_batch(&storage)?;
        let tomb = batch.tombstones.first().ok_or("missing tombstone")?.clone();
        let meta = storage.candidate_roots[&tomb.import_id].metadata_digest;
        storage.commit_retention_deletions(
            &batch,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        )?;
        let bytes = b"retained independent evidence";
        storage
            .pack_store
            .append_batch(&[PackObjectInput::new(PACK_KIND_METADATA, 0, bytes)])?;
        let referenced = if import_metadata {
            meta
        } else {
            tomb.object_digests[0]
        };
        storage.pack_store.publish_root(VirtualRootRecord::new(
            "foreign-retirement-reference",
            if as_metadata {
                ContentDigest::sha256(bytes)
            } else {
                referenced
            },
            "retained-evidence",
            1,
            1,
            1,
            TimestampNs(10),
            as_metadata.then_some(referenced),
        )?)?;
        storage.shutdown_and_flush()?;
        let mut reopened = StorageEngine::open(&config, Some(&dir.0))?;
        assert!(
            reopened
                .pack_store
                .object_tombstone(&tomb.object_digests[0])?
                .is_none()
        );
        assert!(matches!(
            reopened
                .pack_store
                .get_root(&tomb.import_id)?
                .ok_or("missing root")?
                .status,
            RootStatus::Live
        ));
        reopened.pack_store.tombstone_root(
            "foreign-retirement-reference",
            ContentDigest::sha256(b"release foreign reference"),
        )?;
        reopened.resume_committed_retention_intents()?;
        assert_eq!(
            reopened
                .pack_store
                .object_tombstone(&tomb.object_digests[0])?,
            Some(tomb.reason_digest)
        );
        assert!(
            reopened
                .pack_store
                .read_verified_with_budget(&meta, &PackReadBudget::new(64 * 1024))
                .is_ok()
        );
        reopened.shutdown_and_flush()?;
    }
    Ok(())
}

#[test]
fn staged_intent_and_legacy_absent_row_never_grant_recovery_authority() -> TestResult {
    for delete_legacy_row in [false, true] {
        let dir = TestDirectory::new()?;
        let config = manifest()?;
        let regions =
            DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
        ingest(&mut storage, &regions)?;
        let batch = selected_batch(&storage)?;
        let intents = storage.prepare_retention_intents(&batch, &targets(&storage))?;
        let (digest, intent, bytes) = &intents[0];
        storage
            .pack_store
            .append_batch(&[PackObjectInput::with_digest(
                PACK_KIND_METADATA,
                0,
                bytes,
                *digest,
            )])?;
        if delete_legacy_row {
            let payload = ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                target: DeletionTarget::FootageImport(intent.source),
            })
            .encode_bytes()?;
            let payload_digest = ContentDigest::sha256(&payload);
            storage.combiner.submit(CommitProposal {
                request_digest: payload_digest,
                sensor_scope: "retention:legacy".to_owned(),
                objects: vec![OwnedPackObject::with_digest(
                    PACK_KIND_METADATA,
                    0,
                    payload,
                    payload_digest,
                )],
                batch_id_prefix: "retention-legacy".to_owned(),
                deltas: vec![EvidenceDelta {
                    delta_id: "delta:legacy-retirement".to_owned(),
                    family: FAMILY_DELETION_TOMBSTONE.to_owned(),
                    object_id: ObjectId::parse(format!(
                        "obj:retention-delete:{}",
                        intent.source.to_text()
                    ))?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: CaptureInterval::new(TimestampNs(10_000), TimestampNs(10_000))?,
                    plane: Plane::Authority,
                    payload_digest,
                    witness_digest: None,
                    operation_id: None,
                }],
            })?;
        }
        let head = storage.projection.head_anchor();
        storage.shutdown_and_flush()?;
        let reopened = StorageEngine::open(&config, Some(&dir.0))?;
        assert_eq!(reopened.projection.head_anchor(), head);
        assert!(reopened.retention_intents.is_empty());
        assert!(
            reopened
                .pack_store
                .object_tombstone(&intent.source)?
                .is_none()
        );
        assert!(reopened.pack_store.lookup(&intent.source)?.is_some());
        let candidate = reopened
            .retention_candidates()
            .values()
            .next()
            .ok_or("missing candidate")?;
        if delete_legacy_row {
            assert!(
                candidate
                    .held_by
                    .iter()
                    .any(|pin| pin == UNPROVEN_RETIREMENT_BLOCKER)
            );
        } else {
            assert!(!candidate.is_pinned());
        }
        reopened.shutdown_and_flush()?;
    }
    Ok(())
}

#[test]
fn newer_reimport_and_catalog_identity_cannot_inherit_old_retirement() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    let old_id = batch.tombstones[0].import_id.clone();
    let old = storage
        .pack_store
        .get_root(&old_id)?
        .ok_or("missing root")?
        .record;
    storage.commit_retention_deletions(
        &batch,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let metadata = old.metadata_digest.ok_or("missing metadata")?;
    let payload = storage
        .pack_store
        .read_verified_with_budget(&metadata, &PackReadBudget::new(64 * 1024))?;
    storage.combiner.submit(CommitProposal {
        request_digest: ContentDigest::sha256(b"newer authorized import"),
        sensor_scope: "retention:reimport-test".to_owned(),
        objects: vec![OwnedPackObject::with_digest(
            PACK_KIND_METADATA,
            0,
            payload,
            metadata,
        )],
        batch_id_prefix: "retention-reimport".to_owned(),
        deltas: vec![EvidenceDelta {
            delta_id: "delta:newer-import".to_owned(),
            family: fss_projection_store::FAMILY_FOOTAGE_IMPORT.to_owned(),
            object_id: ObjectId::parse("obj:test:newer-import")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(10))?,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: None,
            operation_id: None,
        }],
    })?;
    let new_id = "gop:retention:1:99999";
    storage.pack_store.publish_root(VirtualRootRecord::new(
        new_id,
        old.root_digest,
        old.kind,
        old.child_count,
        old.total_payload_bytes,
        old.generation + 1,
        old.created_at_ns,
        old.metadata_digest,
    )?)?;
    let head = storage.projection.head_anchor();
    storage.shutdown_and_flush()?;
    let reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.projection.head_anchor(), head);
    assert!(
        reopened
            .projection
            .snapshot_latest()
            .get_footage_import(&old.root_digest)
            .is_some()
    );
    assert!(
        reopened
            .pack_store
            .object_tombstone(&old.root_digest)?
            .is_none()
    );
    for id in [old_id.as_str(), new_id] {
        assert!(matches!(
            reopened
                .pack_store
                .get_root(id)?
                .ok_or("missing live import")?
                .status,
            RootStatus::Live
        ));
    }
    assert_eq!(reopened.retention_intents.len(), 1);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn catalog_prefix_failure_resumes_original_reasons_and_preserves_metadata() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    // Repeated identical bytes produce another immutable root for the same source.
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    assert_eq!(batch.tombstones.len(), 2);
    storage.commit_retention_deletions(
        &batch,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let first = &batch.tombstones[0];
    storage
        .pack_store
        .tombstone_root(&first.import_id, first.reason_digest)?;
    assert!(
        storage
            .pack_store
            .object_tombstone(&first.object_digests[0])?
            .is_none()
    );
    let head = storage.projection.head_anchor();
    storage.shutdown_and_flush()?;
    let reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert_eq!(reopened.projection.head_anchor(), head);
    for tomb in &batch.tombstones {
        assert!(matches!(
            reopened.pack_store.get_root(&tomb.import_id)?.ok_or("missing retired root")?.status,
            RootStatus::Tombstoned { reason_digest, .. } if reason_digest == tomb.reason_digest
        ));
    }
    assert_eq!(
        reopened
            .pack_store
            .object_tombstone(&first.object_digests[0])?,
        Some(first.reason_digest)
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn metadata_hold_protects_source_after_canonical_retirement() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = manifest()?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
    ingest(&mut storage, &regions)?;
    let batch = selected_batch(&storage)?;
    let tomb = batch.tombstones[0].clone();
    let metadata = storage.candidate_roots[&tomb.import_id].metadata_digest;
    storage.commit_retention_deletions(
        &batch,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let (object, delta) = storage.hold_delta(
        "hold:import-metadata".to_owned(),
        "test:metadata".to_owned(),
        metadata,
        true,
        TimestampNs(20),
    )?;
    storage.combiner.submit(CommitProposal {
        request_digest: delta.payload_digest,
        sensor_scope: "retention:metadata-hold".to_owned(),
        objects: vec![object],
        deltas: vec![delta],
        batch_id_prefix: "metadata-hold".to_owned(),
    })?;
    storage.shutdown_and_flush()?;
    let mut reopened = StorageEngine::open(&config, Some(&dir.0))?;
    assert!(
        reopened
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?
            .is_none()
    );
    let (object, delta) = reopened.hold_delta(
        "hold:import-metadata".to_owned(),
        "test:metadata".to_owned(),
        metadata,
        false,
        TimestampNs(30),
    )?;
    reopened.combiner.submit(CommitProposal {
        request_digest: delta.payload_digest,
        sensor_scope: "retention:metadata-hold".to_owned(),
        objects: vec![object],
        deltas: vec![delta],
        batch_id_prefix: "metadata-release".to_owned(),
    })?;
    reopened.refresh_retention_pins();
    reopened.resume_committed_retention_intents()?;
    assert_eq!(
        reopened
            .pack_store
            .object_tombstone(&tomb.object_digests[0])?,
        Some(tomb.reason_digest)
    );
    assert!(
        reopened
            .pack_store
            .read_verified_with_budget(&metadata, &PackReadBudget::new(64 * 1024))
            .is_ok()
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn grouped_metadata_blocker_cannot_be_bypassed_by_legacy_root_cleanup() -> TestResult {
    for retired_count in [1, 2] {
        for catalog_reference in [false, true] {
            let dir = TestDirectory::new()?;
            let config = manifest()?;
            let regions =
                DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
            let mut storage = StorageEngine::open(&config, Some(&dir.0))?;
            ingest(&mut storage, &regions)?;
            // The same source stream/frame is imported under a second sensor identity:
            // media bytes deduplicate, but the two immutable import descriptors differ.
            ingest_for_sensor(&mut storage, &regions, 1, "sensor:retention-alias")?;
            let batch = selected_batch(&storage)?;
            assert_eq!(batch.tombstones.len(), 2);
            let first = batch.tombstones[0].clone();
            let second = batch.tombstones[1].clone();
            assert_eq!(first.object_digests, second.object_digests);
            let meta_a = storage.candidate_roots[&first.import_id].metadata_digest;
            let meta_b = storage.candidate_roots[&second.import_id].metadata_digest;
            assert_ne!(meta_a, meta_b);
            storage.commit_retention_deletions(
                &batch,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )?;
            for tomb in &batch.tombstones[..retired_count] {
                storage
                    .pack_store
                    .tombstone_root(&tomb.import_id, tomb.reason_digest)?;
            }
            if catalog_reference {
                let descriptor = b"grouped source evidence";
                storage.pack_store.append_batch(&[PackObjectInput::new(
                    PACK_KIND_METADATA,
                    0,
                    descriptor,
                )])?;
                storage.pack_store.publish_root(VirtualRootRecord::new(
                    "foreign-group-metadata",
                    ContentDigest::sha256(descriptor),
                    "evidence",
                    1,
                    1,
                    1,
                    TimestampNs(10),
                    Some(meta_b),
                )?)?;
            } else {
                let (object, delta) = storage.hold_delta(
                    "hold:second-root-metadata".to_owned(),
                    "test:group".to_owned(),
                    meta_b,
                    true,
                    TimestampNs(20),
                )?;
                storage.combiner.submit(CommitProposal {
                    request_digest: delta.payload_digest,
                    sensor_scope: "retention:group-hold".to_owned(),
                    objects: vec![object],
                    deltas: vec![delta],
                    batch_id_prefix: "group-hold".to_owned(),
                })?;
            }
            storage.shutdown_and_flush()?;
            let mut reopened = StorageEngine::open(&config, Some(&dir.0))?;
            assert_eq!(reopened.retention_intents.len(), 1);
            assert!(
                reopened
                    .pack_store
                    .object_tombstone(&first.object_digests[0])?
                    .is_none()
            );
            assert!(
                reopened
                    .pack_store
                    .lookup(&first.object_digests[0])?
                    .is_some()
            );
            // Exercise both reconciliation paths repeatedly, including the legacy path.
            reopened.resume_committed_retention_intents()?;
            reopened.resume_pending_retention_deletions()?;
            assert!(
                reopened
                    .pack_store
                    .object_tombstone(&first.object_digests[0])?
                    .is_none()
            );
            if catalog_reference {
                reopened.pack_store.tombstone_root(
                    "foreign-group-metadata",
                    ContentDigest::sha256(b"release group reference"),
                )?;
            } else {
                let (object, delta) = reopened.hold_delta(
                    "hold:second-root-metadata".to_owned(),
                    "test:group".to_owned(),
                    meta_b,
                    false,
                    TimestampNs(30),
                )?;
                reopened.combiner.submit(CommitProposal {
                    request_digest: delta.payload_digest,
                    sensor_scope: "retention:group-hold".to_owned(),
                    objects: vec![object],
                    deltas: vec![delta],
                    batch_id_prefix: "group-release".to_owned(),
                })?;
            }
            reopened.refresh_retention_pins();
            reopened.resume_committed_retention_intents()?;
            assert_eq!(
                reopened
                    .pack_store
                    .object_tombstone(&first.object_digests[0])?,
                Some(first.reason_digest)
            );
            assert!(
                reopened
                    .pack_store
                    .read_verified_with_budget(&meta_a, &PackReadBudget::new(64 * 1024))
                    .is_ok()
            );
            assert!(
                reopened
                    .pack_store
                    .read_verified_with_budget(&meta_b, &PackReadBudget::new(64 * 1024))
                    .is_ok()
            );
            reopened.shutdown_and_flush()?;
        }
    }
    Ok(())
}
