#![forbid(unsafe_code)]
//! Public storage lifecycle contracts: retained custody and canonical pins survive restart,
//! expiration retires footage before reclamation, and derived projections rebuild from history.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, SensorId,
    StreamId, TimestampNs,
};
use fss_daemon::{
    CameraAdapterKind, CameraFrame, DaemonError, DaemonRegionTree, SiteManifest, StorageEngine,
};
use fss_pack::{
    CapacityPressure, ERR_STORAGE_QUOTA_PINNED_001, MediaCodec, RetentionCandidate, RootStatus,
    VirtualRootRecord,
};
use fss_projection_store::ProjectionStore;
use fss_reference::agent_orient::projection_bridge::PROJECTION_SUBDIR;
use fss_reference::ingest::model_pool::FramePixelInput;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SENSOR_A: &str = "sensor:retention-a";
const SENSOR_B: &str = "sensor:retention-b";
const EXPIRED_AT: TimestampNs = TimestampNs(10_000_000);

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "fss-retention-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest(cap_bytes: u64) -> Result<SiteManifest, Box<DaemonError>> {
    SiteManifest::parse_json(&format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-retention-restart",
  "ring_cap_bytes": {cap_bytes},
  "retain_hot_ns": 1000,
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [
    {{
      "sensor_id": "{SENSOR_A}",
      "adapter": "synthetic",
      "endpoint": "synthetic://retention-a",
      "secret_id": "secret:retention:a",
      "priority_tier": "standard",
      "zone_id": "driveway",
      "dimensions": [32, 32],
      "failure_domains": ["power:circuit-a"],
      "gop_frames": 1
    }},
    {{
      "sensor_id": "{SENSOR_B}",
      "adapter": "synthetic",
      "endpoint": "synthetic://retention-b",
      "secret_id": "secret:retention:b",
      "priority_tier": "standard",
      "zone_id": "driveway",
      "dimensions": [32, 32],
      "failure_domains": ["power:circuit-b"],
      "gop_frames": 1
    }}
  ]
}}"#
    ))
    .map_err(Box::new)
}

fn frame(
    sensor: &str,
    sequence: u64,
    at_ns: i128,
    payload_bytes: usize,
) -> Result<Arc<CameraFrame>, Box<dyn std::error::Error>> {
    // These are explicitly synthetic custody bytes, matching the daemon's synthetic driver.
    // No decoder or model outcome is claimed by this storage lifecycle contract.
    let luma = vec![0; 32 * 32];
    let mut encoded_payload = b"FSSA".to_vec();
    encoded_payload.extend_from_slice(&1_u64.to_be_bytes());
    encoded_payload.extend_from_slice(&sequence.to_be_bytes());
    encoded_payload.extend_from_slice(&luma);
    encoded_payload.resize(encoded_payload.len().saturating_add(payload_bytes), 0x5a);
    let source_digest = ContentDigest::sha256(&encoded_payload);
    Ok(Arc::new(CameraFrame {
        sensor_id: SensorId::parse(sensor)?,
        stream_generation: 1,
        stream_id: StreamId::parse(format!("stream:{sensor}:g1"))?,
        sequence,
        media_pts_ns: at_ns,
        host_receive_ns: at_ns,
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
    }))
}

fn ingest(
    storage: &mut StorageEngine,
    regions: &DaemonRegionTree,
    sensor: &str,
    sequence: u64,
    at_ns: i128,
    payload_bytes: usize,
) -> Result<RetentionCandidate, Box<dyn std::error::Error>> {
    let previous: BTreeSet<_> = storage.retention_candidates().keys().cloned().collect();
    let receipt = storage.ingest_frame(
        frame(sensor, sequence, at_ns, payload_bytes)?,
        CameraAdapterKind::Synthetic,
        1,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    assert!(receipt.is_some(), "a complete one-frame GOP must commit");
    assert_eq!(storage.retention_candidates().len(), previous.len() + 1);
    storage
        .retention_candidates()
        .values()
        .find(|candidate| !previous.contains(&candidate.import_id))
        .cloned()
        .ok_or_else(|| "committed GOP did not register a retention candidate".into())
}

fn media_digest(
    candidate: &RetentionCandidate,
) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    candidate
        .object_digests
        .first()
        .copied()
        .ok_or_else(|| "retained GOP is missing its source media digest".into())
}

#[test]
fn reopen_rebuilds_occupancy_and_never_reuses_committed_gop_ids() -> TestResult {
    let dir = TempDirGuard::new("occupancy")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let old = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let old_digest = media_digest(&old)?;
    let old_row = storage
        .projection()
        .snapshot_latest()
        .get_footage_import(&old_digest)
        .cloned()
        .ok_or("committed footage must be queryable")?;
    let before = storage.head_snapshot()?;
    assert!(
        before.ring_used_bytes > old.byte_size,
        "canonical projection metadata also occupies protected storage"
    );
    let flushed = storage.shutdown_and_flush()?;
    assert_eq!(flushed.head_commit_sequence, before.commit_sequence);

    // The daemon must recover from canonical packs and ledger, with no MVCC cache available.
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    let recovered = reopened.head_snapshot()?;
    assert_eq!(recovered.ring_used_bytes, before.ring_used_bytes);
    assert_eq!(recovered.history_root, before.history_root);
    assert_eq!(recovered.state_root, before.state_root);
    assert_eq!(
        reopened.retention_candidates().get(&old.import_id),
        Some(&old)
    );
    assert_eq!(
        reopened
            .projection()
            .snapshot_latest()
            .get_footage_import(&old_digest),
        Some(&old_row)
    );

    // A process-local stream/frame counter can restart at one. Committed root IDs cannot.
    let new = ingest(&mut reopened, &regions, SENSOR_A, 1, 2_000_000, 128)?;
    assert_ne!(new.import_id, old.import_id);
    assert_ne!(media_digest(&new)?, old_digest);
    assert_eq!(reopened.retention_candidates().len(), 2);
    assert!(reopened.head_snapshot()?.commit_sequence > before.commit_sequence);
    assert!(
        reopened
            .projection()
            .snapshot_latest()
            .get_footage_import(&old_digest)
            .is_some()
    );
    assert!(reopened.shutdown_and_flush()?.verified_batches >= 2);
    Ok(())
}

#[test]
fn durable_hold_blocks_restart_ingest_until_release_and_retirement_rebuilds() -> TestResult {
    let dir = TempDirGuard::new("hold-release")?;
    let manifest = manifest(4096)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let candidate = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 8192)?;
    let digest = media_digest(&candidate)?;
    let root = storage
        .pack_store()
        .get_root(&candidate.import_id)?
        .ok_or("committed GOP root is missing")?;
    let metadata_digest = root
        .record
        .metadata_digest
        .ok_or("committed GOP metadata is missing")?;
    let metadata_bytes = storage.pack_store().read_verified(&metadata_digest)?;
    let hold_id = "hold:retention-restart";

    // The compatibility boolean API must now commit a real hold, not a process-local pin.
    assert!(storage.pin_candidate_hold(&candidate.import_id, hold_id));
    let pinned_occupancy = storage.head_snapshot()?.ring_used_bytes;
    storage.shutdown_and_flush()?;

    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    let head = reopened.head_snapshot()?;
    assert_eq!(head.ring_used_bytes, pinned_occupancy);
    assert_eq!(head.pressure, CapacityPressure::Critical);
    assert!(head.quota_pinned);
    assert_eq!(
        reopened.ingest_paused_reason(),
        Some(ERR_STORAGE_QUOTA_PINNED_001)
    );
    let blocked_ingest = reopened.ingest_frame(
        frame(SENSOR_A, 2, 2_000_000, 128)?,
        CameraAdapterKind::Synthetic,
        1,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    );
    assert!(matches!(
        blocked_ingest,
        Err(DaemonError::StorageQuotaPinned { .. })
    ));
    let held = reopened
        .projection()
        .snapshot_latest()
        .get_hold(hold_id)
        .cloned()
        .ok_or("hold did not survive restart")?;
    assert!(held.active);
    assert_eq!(held.target_digest, digest);
    let protected = reopened.run_maintenance_tick(
        regions.storage_ledger_cx(),
        regions.region_tree(),
        EXPIRED_AT,
        false,
    )?;
    assert_eq!(protected.evicted_imports, 0);
    assert!(protected.quota_pinned);
    assert!(reopened.pack_store().lookup(&digest)?.is_some());

    assert!(reopened.set_candidate_hold(
        &candidate.import_id,
        hold_id,
        false,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?);
    let retired = reopened.run_maintenance_tick(
        regions.storage_ledger_cx(),
        regions.region_tree(),
        EXPIRED_AT,
        false,
    )?;
    assert_eq!(retired.evicted_imports, 1);
    assert!(!retired.quota_pinned);
    assert!(reopened.retention_candidates().is_empty());
    assert!(
        reopened
            .projection()
            .snapshot_latest()
            .get_footage_import(&digest)
            .is_none()
    );
    assert!(reopened.pack_store().object_tombstone(&digest)?.is_some());
    assert!(reopened.pack_store().lookup(&digest)?.is_none());
    assert!(matches!(
        reopened
            .pack_store()
            .get_root(&candidate.import_id)?
            .ok_or("retired root must retain its tombstone")?
            .status,
        RootStatus::Tombstoned { .. }
    ));
    assert_eq!(
        reopened.pack_store().read_verified(&metadata_digest)?,
        metadata_bytes
    );
    let retired_head = reopened.head_snapshot()?;
    assert!(retired_head.ring_used_bytes > 0);
    reopened.shutdown_and_flush()?;

    // Historical import metadata is still a canonical replay input after source reclamation.
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let rebuilt = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert_eq!(
        rebuilt.head_snapshot()?.history_root,
        retired_head.history_root
    );
    assert_eq!(rebuilt.head_snapshot()?.state_root, retired_head.state_root);
    assert!(rebuilt.retention_candidates().is_empty());
    let snapshot = rebuilt.projection().snapshot_latest();
    assert!(snapshot.get_footage_import(&digest).is_none());
    assert!(
        !snapshot
            .get_hold(hold_id)
            .ok_or("canonical hold release must replay")?
            .active
    );
    assert!(rebuilt.pack_store().lookup(&digest)?.is_none());
    assert_eq!(
        rebuilt.pack_store().read_verified(&metadata_digest)?,
        metadata_bytes
    );
    rebuilt.shutdown_and_flush()?;
    Ok(())
}

fn corroborated_event(
    first: ContentDigest,
    second: ContentDigest,
) -> Result<EventHypothesis, Box<dyn std::error::Error>> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:retention-restart")?,
        revision: 1,
        supersedes: None,
        state: EventState::Corroborated,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(1_000_001))?,
        uncertainty_reason: None,
        zone_ids: vec!["driveway".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::with_calibration(
            0.90,
            0.99,
            ContentDigest::sha256(b"retention-test-calibration"),
        )?,
        evidence: [(first, "power:circuit-a"), (second, "power:circuit-b")]
            .into_iter()
            .map(|(digest, domain)| EventEvidence {
                digest,
                class: EvidenceClass::Observed,
                failure_domain: domain.to_owned(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: None,
                identity_digest: Some(ContentDigest::sha256(domain.as_bytes())),
            })
            .collect(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"retention-test-policy"),
            fingerprint: ContentDigest::sha256(b"retention-test-corroboration"),
            abstained: false,
            abstention_reason: None,
        },
    };
    // A valid corroborated fixture requires distinct supporting failure domains.
    event.verify()?;
    Ok(event)
}

#[test]
fn event_pins_remain_on_original_media_when_newer_gops_exist_after_restart() -> TestResult {
    let dir = TempDirGuard::new("event-pins")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let old_a = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let old_b = ingest(&mut storage, &regions, SENSOR_B, 1, 1_000_001, 128)?;
    let old_a_digest = media_digest(&old_a)?;
    let old_b_digest = media_digest(&old_b)?;
    let event = corroborated_event(old_a_digest, old_b_digest)?;
    let receipt = storage.commit_event_hypothesis(
        &event,
        vec![SensorId::parse(SENSOR_A)?, SensorId::parse(SENSOR_B)?],
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let original_holds: Vec<_> = storage
        .projection()
        .snapshot_latest()
        .holds()
        .filter(|hold| hold.active)
        .cloned()
        .collect();
    assert_eq!(original_holds.len(), 2);
    for hold in &original_holds {
        assert_eq!(hold.committed_sequence, receipt.commit_sequence);
        assert!([old_a_digest, old_b_digest].contains(&hold.target_digest));
    }
    storage.shutdown_and_flush()?;

    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    let new_a = ingest(&mut reopened, &regions, SENSOR_A, 1, 2_000_000, 128)?;
    let new_b = ingest(&mut reopened, &regions, SENSOR_B, 1, 2_000_001, 128)?;
    reopened.shutdown_and_flush()?;

    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    for old in [&old_a, &old_b] {
        let retained = reopened
            .retention_candidates()
            .get(&old.import_id)
            .ok_or("event source was lost during restart")?;
        assert_eq!(
            retained.active_event_ids,
            vec![event.event_id.as_str().to_owned()]
        );
    }
    for new in [&new_a, &new_b] {
        assert!(
            !reopened
                .retention_candidates()
                .get(&new.import_id)
                .ok_or("newly retained GOP is missing")?
                .is_pinned()
        );
    }
    let snapshot = reopened.projection().snapshot_latest();
    for original in &original_holds {
        assert_eq!(snapshot.get_hold(&original.hold_id), Some(original));
    }

    let event_hold = original_holds
        .iter()
        .find(|hold| hold.target_digest == old_a_digest)
        .ok_or("event source is missing its canonical pin")?;
    assert!(
        reopened
            .set_candidate_hold(
                &old_a.import_id,
                &event_hold.hold_id,
                false,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )
            .is_err(),
        "ordinary hold release cannot erase an event evidence pin"
    );
    let report = reopened.run_maintenance_tick(
        regions.storage_ledger_cx(),
        regions.region_tree(),
        EXPIRED_AT,
        false,
    )?;
    assert_eq!(report.evicted_imports, 2);
    assert_eq!(reopened.retention_candidates().len(), 2);
    let snapshot = reopened.projection().snapshot_latest();
    for old_digest in [old_a_digest, old_b_digest] {
        assert!(snapshot.get_footage_import(&old_digest).is_some());
        assert!(reopened.pack_store().lookup(&old_digest)?.is_some());
    }
    for new in [&new_a, &new_b] {
        assert!(snapshot.get_footage_import(&media_digest(new)?).is_none());
        assert!(!reopened.retention_candidates().contains_key(&new.import_id));
    }
    assert_eq!(
        snapshot
            .get_event(&event.event_id)
            .ok_or("event revision must remain queryable")?
            .state,
        EventState::Corroborated
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn legacy_gop_unknown_hold_state_blocks_automatic_expiry() -> TestResult {
    let dir = TempDirGuard::new("legacy")?;
    let manifest = manifest(4096)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let source = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 8192)?;
    let digest = media_digest(&source)?;
    let mut legacy_record = storage
        .pack_store()
        .get_root(&source.import_id)?
        .ok_or("new media root is missing")?
        .record;
    let legacy_id = "gop:legacy-retention:1:99";
    legacy_record.root_id = legacy_id.to_owned();
    legacy_record.kind = "media-gop-v1".to_owned();
    // Model an existing legacy root through the public catalog protocol, with exactly the
    // same verified source and metadata closure. No journal bytes/private layouts are patched.
    storage
        .pack_store()
        .supersede_root(&source.import_id, legacy_record)?;
    storage.shutdown_and_flush()?;

    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert_eq!(reopened.retention_candidates().len(), 1);
    let legacy = reopened
        .retention_candidates()
        .get(legacy_id)
        .ok_or("legacy GOP was not recovered")?;
    assert!(
        legacy
            .held_by
            .iter()
            .any(|hold| hold == "recovery:legacy-hold-state-unverified")
    );
    assert!(reopened.is_quota_pinned());
    assert_eq!(reopened.projection().snapshot_latest().holds().count(), 0);
    let report = reopened.run_maintenance_tick(
        regions.storage_ledger_cx(),
        regions.region_tree(),
        EXPIRED_AT,
        false,
    )?;
    assert_eq!(report.evicted_imports, 0);
    assert!(report.quota_pinned);
    assert!(reopened.pack_store().lookup(&digest)?.is_some());
    assert!(reopened.pack_store().object_tombstone(&digest)?.is_none());
    assert!(
        reopened
            .projection()
            .snapshot_latest()
            .get_footage_import(&digest)
            .is_some()
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn foreign_catalog_source_and_metadata_aliases_block_expiry_until_retired() -> TestResult {
    for (label, media_as_metadata) in [("source-alias", false), ("metadata-alias", true)] {
        let dir = TempDirGuard::new(label)?;
        let manifest = manifest(4096)?;
        let regions =
            DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
        let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
        let candidate = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 8192)?;
        let digest = media_digest(&candidate)?;
        let record = storage
            .pack_store()
            .get_root(&candidate.import_id)?
            .ok_or("daemon GOP root is missing")?
            .record;
        let metadata_digest = record
            .metadata_digest
            .ok_or("daemon GOP metadata is missing")?;
        let source_bytes = storage.pack_store().read_verified(&digest)?;
        let footage = storage
            .projection()
            .snapshot_latest()
            .get_footage_import(&digest)
            .cloned()
            .ok_or("daemon footage must initially be queryable")?;

        // Another catalog owner can refer to this source either as its root object or as
        // attached metadata. Neither foreign root belongs to the daemon candidate inventory.
        let alias_id = format!("foreign:{label}");
        let (root_digest, metadata_alias, total_payload_bytes) = if media_as_metadata {
            (metadata_digest, Some(digest), record.total_payload_bytes)
        } else {
            (digest, None, candidate.byte_size)
        };
        storage.pack_store().publish_root(VirtualRootRecord::new(
            alias_id.clone(),
            root_digest,
            "evidence-alias-v1",
            1,
            total_payload_bytes,
            1,
            candidate.capture_end_ns,
            metadata_alias,
        )?)?;
        assert!(!storage.retention_candidates().contains_key(&alias_id));
        storage.shutdown_and_flush()?;

        let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
        let before = reopened.head_snapshot()?;
        let protected = reopened.run_maintenance_tick(
            regions.storage_ledger_cx(),
            regions.region_tree(),
            EXPIRED_AT,
            false,
        )?;
        assert_eq!(protected.evicted_imports, 0, "{label}");
        assert_eq!(protected.pressure, CapacityPressure::Critical, "{label}");
        assert!(protected.quota_pinned, "{label}");
        assert!(protected.pinned_bytes >= candidate.byte_size, "{label}");
        assert_eq!(
            reopened.head_snapshot()?.commit_sequence,
            before.commit_sequence,
            "a live alias must prevent canonical retirement, not merely physical deletion"
        );
        assert_eq!(
            reopened
                .projection()
                .snapshot_latest()
                .get_footage_import(&digest),
            Some(&footage),
            "{label}"
        );
        assert_eq!(
            reopened.pack_store().read_verified(&digest)?,
            source_bytes,
            "{label}"
        );
        assert!(reopened.pack_store().object_tombstone(&digest)?.is_none());
        assert!(
            reopened
                .retention_candidates()
                .get(&candidate.import_id)
                .ok_or("aliased source must remain a retention candidate")?
                .held_by
                .iter()
                .any(|hold| hold == "retention:live-catalog-reference"),
            "{label}"
        );

        // Removing the foreign catalog reference must clear its derived blocker on the next
        // maintenance pass, allowing ordinary expiration without restarting the daemon.
        reopened.pack_store().tombstone_root(
            &alias_id,
            ContentDigest::sha256(b"retention-test-release-foreign-catalog-alias"),
        )?;
        let retired = reopened.run_maintenance_tick(
            regions.storage_ledger_cx(),
            regions.region_tree(),
            EXPIRED_AT,
            false,
        )?;
        assert_eq!(retired.evicted_imports, 1, "{label}");
        assert!(!retired.quota_pinned, "{label}");
        assert!(reopened.retention_candidates().is_empty());
        assert!(
            reopened
                .projection()
                .snapshot_latest()
                .get_footage_import(&digest)
                .is_none(),
            "{label}"
        );
        assert!(reopened.pack_store().object_tombstone(&digest)?.is_some());
        assert!(reopened.pack_store().lookup(&digest)?.is_none());
        reopened.shutdown_and_flush()?;
    }
    Ok(())
}

#[test]
fn cancelled_gop_flush_keeps_source_frames_for_an_authorized_retry() -> TestResult {
    let dir = TempDirGuard::new("cancelled-gop")?;
    let manifest = manifest(1_048_576)?;
    let mut regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let source_a = frame(SENSOR_A, 1, 1_000_000, 128)?;
    let source_b = frame(SENSOR_A, 2, 2_000_000, 128)?;
    for source in [&source_a, &source_b] {
        assert!(
            storage
                .ingest_frame(
                    Arc::clone(source),
                    CameraAdapterKind::Synthetic,
                    3,
                    regions.storage_ledger_cx(),
                    regions.region_tree(),
                )?
                .is_none()
        );
    }
    regions.request_shutdown(TimestampNs(3_000_000))?;
    let sensor_id = SensorId::parse(SENSOR_A)?;
    assert!(matches!(
        storage.flush_camera_gop(
            &sensor_id,
            CameraAdapterKind::Synthetic,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        ),
        Err(DaemonError::Combiner(
            fss_projection_store::CombinerError::Cancelled
        ))
    ));
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);

    let fresh_regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(4_000_000))?;
    let receipt = storage.flush_camera_gop(
        &sensor_id,
        CameraAdapterKind::Synthetic,
        fresh_regions.storage_ledger_cx(),
        fresh_regions.region_tree(),
    )?;
    assert!(receipt.is_some(), "the cancelled flush must retain its source GOP");
    assert_eq!(storage.retention_candidates().len(), 1);
    let candidate = storage
        .retention_candidates()
        .values()
        .next()
        .ok_or("retry did not retain a GOP")?;
    let source = storage.pack_store().read_verified(&media_digest(candidate)?)?;
    let chunk = fss_pack::MediaChunkView::parse(&source)?;
    assert_eq!(chunk.frame_count(), 2);
    assert_eq!(chunk.frame_bytes_verified(0)?, source_a.encoded_payload.as_slice());
    assert_eq!(chunk.frame_bytes_verified(1)?, source_b.encoded_payload.as_slice());
    assert!(
        storage
            .flush_camera_gop(
                &sensor_id,
                CameraAdapterKind::Synthetic,
                fresh_regions.storage_ledger_cx(),
                fresh_regions.region_tree(),
            )?
            .is_none(),
        "a successful retry must consume the buffer exactly once"
    );
    assert_eq!(storage.shutdown_and_flush()?.verified_batches, 1);
    Ok(())
}

#[test]
fn catalog_conflict_after_gop_commit_never_reappends_the_import() -> TestResult {
    let dir = TempDirGuard::new("catalog-conflict")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    // Another publisher occupies the exact initially reserved ID after the daemon opened.
    let foreign_bytes = b"independent publication";
    let foreign_digest = ContentDigest::sha256(foreign_bytes);
    let _ = storage.pack_store().append_batch(&[fss_pack::PackObjectInput::new(
        fss_pack::PACK_KIND_METADATA,
        0,
        foreign_bytes,
    )])?;
    let _ = storage.pack_store().publish_root(VirtualRootRecord::new(
        "gop:sensor_retention-a:1:1",
        foreign_digest,
        "independent-publication",
        1,
        foreign_bytes.len() as u64,
        1,
        TimestampNs(0),
        None,
    )?)?;

    assert!(
        storage
            .ingest_frame(
                frame(SENSOR_A, 1, 1_000_000, 128)?,
                CameraAdapterKind::Synthetic,
                1,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )
            .is_err()
    );
    let committed = storage.head_snapshot()?;
    assert_eq!(committed.commit_sequence, 1, "the failure follows canonical commit");
    let sensor_id = SensorId::parse(SENSOR_A)?;
    for _ in 0..2 {
        assert!(
            storage
                .flush_camera_gop(
                    &sensor_id,
                    CameraAdapterKind::Synthetic,
                    regions.storage_ledger_cx(),
                    regions.region_tree(),
                )
                .is_err(),
            "an unresolved catalog conflict must remain explicit"
        );
        assert_eq!(storage.head_snapshot()?.history_root, committed.history_root);
        assert_eq!(storage.head_snapshot()?.commit_sequence, committed.commit_sequence);
    }
    assert!(storage.retention_candidates().is_empty());
    assert!(matches!(
        storage.shutdown_and_flush(),
        Err(DaemonError::ShutdownViolation { .. })
    ));
    assert!(
        StorageEngine::open(&manifest, Some(dir.path())).is_err(),
        "recovery must refuse a colliding live descriptor instead of hiding the import"
    );
    Ok(())
}

#[test]
fn restart_completes_missing_gop_catalog_root_without_another_canonical_commit() -> TestResult {
    let dir = TempDirGuard::new("missing-root")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let journal = dir.path().join("objects/roots/catalog.fssr");
    let previous_catalog_len = fs::metadata(&journal)?.len();
    let mut candidate = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let digest = media_digest(&candidate)?;
    let original = storage.pack_store().read_verified(&digest)?;
    let mut expected_root = storage
        .pack_store()
        .get_root(&candidate.import_id)?
        .ok_or("committed GOP root is missing")?
        .record;
    let committed = storage.head_snapshot()?;
    storage.shutdown_and_flush()?;
    // Without a catalog descriptor, the canonical import alone cannot prove this was not a
    // legacy GOP with an in-memory hold. Recovery keeps that uncertainty explicitly pinned.
    expected_root.kind = "media-gop-v1".to_owned();
    candidate
        .held_by
        .push("recovery:legacy-hold-state-unverified".to_owned());

    // Retain the durable packs and ledger but remove just the catalog publication tail:
    // the exact on-disk boundary of a crash after ledger fsync and before root append.
    assert!(!dir.path().join("objects/roots/catalog.snap").exists());
    fs::OpenOptions::new()
        .write(true)
        .open(&journal)?
        .set_len(previous_catalog_len)?;
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;

    for _ in 0..2 {
        let reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
        assert_eq!(reopened.head_snapshot()?.history_root, committed.history_root);
        assert_eq!(reopened.head_snapshot()?.commit_sequence, committed.commit_sequence);
        assert_eq!(reopened.retention_candidates().len(), 1);
        assert_eq!(
            reopened.retention_candidates().get(&candidate.import_id),
            Some(&candidate)
        );
        assert_eq!(reopened.pack_store().read_verified(&digest)?, original);
        let recovered_root = reopened
            .pack_store()
            .get_root(&candidate.import_id)?
            .ok_or("recovery did not complete the catalog publication")?;
        assert_eq!(recovered_root.record, expected_root);
        assert!(matches!(recovered_root.status, RootStatus::Live));
        assert_eq!(reopened.pack_store().live_root_count()?, 1);
        assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 1);
    }
    Ok(())
}

#[test]
fn missing_catalog_tail_does_not_revive_canonically_retired_footage() -> TestResult {
    let dir = TempDirGuard::new("retired-missing-root")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let journal = dir.path().join("objects/roots/catalog.fssr");
    let previous_catalog_len = fs::metadata(&journal)?.len();
    let candidate = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let digest = media_digest(&candidate)?;
    let maintenance = storage.run_maintenance_tick(
        regions.storage_ledger_cx(),
        regions.region_tree(),
        EXPIRED_AT,
        false,
    )?;
    assert_eq!(maintenance.evicted_imports, 1);
    let retired = storage.head_snapshot()?;
    storage.shutdown_and_flush()?;
    assert!(!dir.path().join("objects/roots/catalog.snap").exists());
    fs::OpenOptions::new()
        .write(true)
        .open(&journal)?
        .set_len(previous_catalog_len)?;
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;

    let reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert_eq!(reopened.head_snapshot()?.history_root, retired.history_root);
    assert!(reopened.retention_candidates().is_empty());
    assert!(reopened.projection().snapshot_latest().get_footage_import(&digest).is_none());
    assert!(reopened.pack_store().object_tombstone(&digest)?.is_some());
    assert!(reopened.pack_store().lookup(&digest)?.is_none());
    assert_eq!(reopened.pack_store().live_root_count()?, 0);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn storage_shutdown_refuses_unpublished_buffered_source() -> TestResult {
    let dir = TempDirGuard::new("unflushed-shutdown")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert!(
        storage
            .ingest_frame(
                frame(SENSOR_A, 1, 1_000_000, 128)?,
                CameraAdapterKind::Synthetic,
                3,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )?
            .is_none()
    );
    assert!(matches!(
        storage.shutdown_and_flush(),
        Err(DaemonError::ShutdownViolation { .. })
    ));
    Ok(())
}

#[test]
fn missing_duplicate_gop_root_is_not_revived_by_a_later_same_content_import() -> TestResult {
    let dir = TempDirGuard::new("duplicate-missing-root")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let journal = dir.path().join("objects/roots/catalog.fssr");
    let previous_catalog_len = fs::metadata(&journal)?.len();
    let older = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let newer = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let digest = media_digest(&newer)?;
    assert_eq!(media_digest(&older)?, digest);
    assert_ne!(older.import_id, newer.import_id);
    let committed = storage.head_snapshot()?;
    assert_eq!(committed.commit_sequence, 2);
    storage.shutdown_and_flush()?;

    fs::OpenOptions::new()
        .write(true)
        .open(&journal)?
        .set_len(previous_catalog_len)?;
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert_eq!(reopened.head_snapshot()?.history_root, committed.history_root);
    assert_eq!(reopened.retention_candidates().len(), 1);
    assert!(reopened.retention_candidates().contains_key(&newer.import_id));
    assert!(reopened.pack_store().get_root(&older.import_id)?.is_none());
    assert!(matches!(
        reopened
            .pack_store()
            .get_root(&newer.import_id)?
            .ok_or("current import publication was not recovered")?
            .status,
        RootStatus::Live
    ));
    let snapshot = reopened.projection().snapshot_latest();
    let current = snapshot
        .get_footage_import(&digest)
        .ok_or("current import disappeared during root recovery")?;
    assert_eq!(current.committed_sequence, 2);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 2);
    Ok(())
}

#[test]
fn gop_recovery_preserves_a_superseded_root_with_an_active_import() -> TestResult {
    let dir = TempDirGuard::new("superseded-root")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let candidate = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let mut replacement = storage
        .pack_store()
        .get_root(&candidate.import_id)?
        .ok_or("original GOP root is missing")?
        .record;
    replacement.root_id = "external:replacement".to_owned();
    replacement.generation += 1;
    let _ = storage
        .pack_store()
        .supersede_root(&candidate.import_id, replacement.clone())?;
    let committed = storage.head_snapshot()?;
    storage.shutdown_and_flush()?;

    let reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    assert_eq!(reopened.head_snapshot()?.history_root, committed.history_root);
    assert!(reopened.retention_candidates().is_empty());
    assert!(matches!(
        reopened
            .pack_store()
            .get_root(&candidate.import_id)?
            .ok_or("superseded catalog history was removed")?
            .status,
        RootStatus::Superseded { .. }
    ));
    let replacement_entry = reopened
        .pack_store()
        .get_root(&replacement.root_id)?
        .ok_or("replacement root disappeared during recovery")?;
    assert_eq!(replacement_entry.record, replacement);
    assert!(matches!(replacement_entry.status, RootStatus::Live));
    assert_eq!(reopened.pack_store().live_root_count()?, 1);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 1);
    Ok(())
}
