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
use fss_projection_store::{CoverageStatus, ProjectionStore, SensorLivenessStatus};
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
    manifest_with_camera_fields(cap_bytes, "", "")
}

fn manifest_with_camera_fields(
    cap_bytes: u64,
    camera_a: &str,
    camera_b: &str,
) -> Result<SiteManifest, Box<DaemonError>> {
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
      {camera_a}"sensor_id": "{SENSOR_A}",
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
      {camera_b}"sensor_id": "{SENSOR_B}",
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
fn manifest_scoped_retention_survives_restart_and_preserves_held_footage() -> TestResult {
    let dir = TempDirGuard::new("sensor-policy")?;
    let config = manifest_with_camera_fields(
        1_048_576,
        r#""max_sensor_bytes":5100,"#,
        r#""retain_hot_ns":10000,"#,
    )?;
    let regions =
        DaemonRegionTree::initialize(&config, "principal:retention-test", TimestampNs(0))?;
    let cx = regions.storage_ledger_cx();
    let tree = regions.region_tree();
    let mut storage = StorageEngine::open(&config, Some(dir.path()))?;
    let quiet = ingest(&mut storage, &regions, SENSOR_B, 1, 10, 1024)?;
    let held = ingest(&mut storage, &regions, SENSOR_A, 1, 20, 1024)?;
    let older = ingest(&mut storage, &regions, SENSOR_A, 2, 30, 1024)?;
    let newer = ingest(&mut storage, &regions, SENSOR_A, 3, 40, 1024)?;
    assert!(held.byte_size + newer.byte_size <= 5100);
    assert!(held.byte_size + older.byte_size + newer.byte_size > 5100);
    assert!(storage.set_candidate_hold(&held.import_id, "hold:sensor-quota", true, cx, tree)?);
    storage.shutdown_and_flush()?;
    let mut storage = StorageEngine::open(&config, Some(dir.path()))?;

    let first = storage.run_maintenance_tick(cx, tree, TimestampNs(40), false)?;
    assert_eq!(first.evicted_imports, 1);
    assert!(
        !storage
            .retention_candidates()
            .contains_key(&older.import_id)
    );
    assert!(
        storage
            .retention_candidates()
            .contains_key(&quiet.import_id)
    );
    assert!(
        storage
            .retention_candidates()
            .contains_key(&newer.import_id)
    );
    // Camera A inherits the site duration. Camera B has its own deadline.
    let aged = storage.run_maintenance_tick(cx, tree, TimestampNs(1040), false)?;
    assert_eq!(aged.evicted_imports, 1);
    assert!(
        !storage
            .retention_candidates()
            .contains_key(&newer.import_id)
    );
    assert!(storage.retention_candidates().contains_key(&held.import_id));
    assert!(
        storage
            .retention_candidates()
            .contains_key(&quiet.import_id)
    );
    let deadline = storage.run_maintenance_tick(cx, tree, TimestampNs(10010), false)?;
    assert_eq!(deadline.evicted_imports, 1);
    assert!(
        !storage
            .retention_candidates()
            .contains_key(&quiet.import_id)
    );
    assert!(storage.retention_candidates().contains_key(&held.import_id));
    Ok(())
}

#[test]
fn retention_overrides_bind_the_manifest_and_refuse_malformed_values() -> TestResult {
    let cap = 1_048_576;
    let base = manifest(cap)?.digest();
    let bytes = r#""max_sensor_bytes":5100,"#;
    let time = r#""retain_hot_ns":10000,"#;
    assert_ne!(base, manifest_with_camera_fields(cap, bytes, "")?.digest());
    assert_ne!(base, manifest_with_camera_fields(cap, time, "")?.digest());
    assert_ne!(
        manifest_with_camera_fields(cap, bytes, time)?.digest(),
        manifest_with_camera_fields(cap, time, bytes)?.digest()
    );
    for invalid in [
        r#""max_sensor_bytes":0,"#,
        r#""max_sensor_bytes":null,"#,
        r#""retain_hot_ns":null,"#,
        r#""retain_hot_ns":-1,"#,
        r#""retain_hot_ns":"1d","#,
    ] {
        assert!(manifest_with_camera_fields(cap, invalid, "").is_err());
    }
    Ok(())
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
fn delayed_event_pins_every_source_gop_in_its_interval_before_newer_footage() -> TestResult {
    let dir = TempDirGuard::new("delayed-event-window")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let mut expected = BTreeSet::new();
    for (sensor, sequence, at) in [
        (SENSOR_A, 1, 1_000_000),
        (SENSOR_B, 2, 1_000_001),
        (SENSOR_A, 3, 1_000_002),
        (SENSOR_B, 4, 1_000_003),
    ] {
        expected.insert(media_digest(&ingest(
            &mut storage,
            &regions,
            sensor,
            sequence,
            at,
            128,
        )?)?);
    }
    let newer_a = ingest(&mut storage, &regions, SENSOR_A, 5, 2_000_000, 128)?;
    let newer_b = ingest(&mut storage, &regions, SENSOR_B, 6, 2_000_001, 128)?;
    let first_source = frame(SENSOR_A, 1, 1_000_000, 128)?.source_digest;
    let second_source = frame(SENSOR_B, 4, 1_000_003, 128)?.source_digest;
    let mut event = corroborated_event(first_source, second_source)?;
    event.interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(1_000_003))?;
    for evidence in &mut event.evidence {
        evidence.capsule_digest = Some(evidence.digest);
    }
    let receipt = storage.commit_event_hypothesis(
        &event,
        vec![SensorId::parse(SENSOR_A)?, SensorId::parse(SENSOR_B)?],
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    let snapshot = storage.projection().snapshot_latest();
    let holds: Vec<_> = snapshot.holds().filter(|hold| hold.active).collect();
    assert_eq!(holds.len(), 4);
    assert_eq!(
        holds
            .iter()
            .map(|hold| hold.target_digest)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(
        holds
            .iter()
            .all(|hold| hold.committed_sequence == receipt.commit_sequence)
    );
    assert!(
        storage.retention_candidates()[&newer_a.import_id]
            .active_event_ids
            .is_empty()
    );
    assert!(
        storage.retention_candidates()[&newer_b.import_id]
            .active_event_ids
            .is_empty()
    );
    storage.shutdown_and_flush()?;

    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let mut reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    let _ = reopened.maintenance_tick(EXPIRED_AT)?;
    let retained: BTreeSet<_> = reopened
        .retention_candidates()
        .values()
        .map(media_digest)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        retained, expected,
        "only the actual event window survives expiry"
    );
    assert_eq!(
        reopened
            .projection()
            .snapshot_latest()
            .holds()
            .filter(|hold| hold.active)
            .count(),
        4
    );
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn corroboration_publishes_and_pins_partial_source_gops_before_the_event() -> TestResult {
    let dir = TempDirGuard::new("event-partial-gop")?;
    let manifest = manifest(1_048_576)?;
    let mut regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let source_a = frame(SENSOR_A, 1, 1_000_000, 128)?;
    let source_b = frame(SENSOR_B, 2, 1_000_001, 128)?;
    for source in [&source_a, &source_b] {
        assert!(
            storage
                .ingest_frame(
                    Arc::clone(source),
                    CameraAdapterKind::Synthetic,
                    32,
                    regions.storage_ledger_cx(),
                    regions.region_tree(),
                )?
                .is_none()
        );
    }
    assert!(storage.retention_candidates().is_empty());
    let mut event = corroborated_event(source_a.source_digest, source_b.source_digest)?;
    for evidence in &mut event.evidence {
        evidence.capsule_digest = Some(evidence.digest);
    }
    // Revoked authority cannot publish buffered source as a side effect of event pinning.
    regions.request_shutdown(TimestampNs(2_000_000))?;
    let sensors = vec![SensorId::parse(SENSOR_A)?, SensorId::parse(SENSOR_B)?];
    assert!(matches!(
        storage.commit_event_hypothesis(
            &event,
            sensors.clone(),
            regions.storage_ledger_cx(),
            regions.region_tree(),
        ),
        Err(DaemonError::Combiner(
            fss_projection_store::CombinerError::Cancelled
        ))
    ));
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
    let fresh_regions = DaemonRegionTree::initialize(
        &manifest,
        "principal:retention-test",
        TimestampNs(3_000_000),
    )?;
    let receipt = storage.commit_event_hypothesis(
        &event,
        sensors,
        fresh_regions.storage_ledger_cx(),
        fresh_regions.region_tree(),
    )?;
    assert_eq!(storage.retention_candidates().len(), 2);
    let snapshot = storage.projection().snapshot_latest();
    let holds: Vec<_> = snapshot.holds().filter(|hold| hold.active).collect();
    assert_eq!(holds.len(), 2);
    for hold in holds {
        assert_eq!(hold.committed_sequence, receipt.commit_sequence);
        let source = snapshot
            .get_footage_import(&hold.target_digest)
            .ok_or("event hold lacks a canonical source import")?;
        assert!(source.committed_sequence < receipt.commit_sequence);
    }
    assert!(storage.retention_candidates().values().all(|candidate| {
        candidate.active_event_ids == vec![event.event_id.as_str().to_owned()]
    }));
    storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn missing_event_source_refuses_corroboration_without_substituting_other_footage() -> TestResult {
    let dir = TempDirGuard::new("event-missing-source")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let first = ingest(&mut storage, &regions, SENSOR_A, 1, 1_000_000, 128)?;
    let second = ingest(&mut storage, &regions, SENSOR_B, 2, 1_000_001, 128)?;
    let mut event = corroborated_event(media_digest(&first)?, media_digest(&second)?)?;
    event.evidence[0].capsule_digest = Some(ContentDigest::sha256(b"unretained-source-frame"));
    let before = storage.head_snapshot()?;
    for missing_citation in [true, false] {
        if !missing_citation {
            event.evidence[0].capsule_digest = None;
            event.interval = CaptureInterval::new(TimestampNs(0), TimestampNs(1))?;
        }
        assert!(matches!(
            storage.commit_event_hypothesis(
                &event,
                vec![SensorId::parse(SENSOR_A)?, SensorId::parse(SENSOR_B)?],
                regions.storage_ledger_cx(),
                regions.region_tree(),
            ),
            Err(DaemonError::Combiner(
                fss_projection_store::CombinerError::InvalidProposal(_)
            ))
        ));
        let after = storage.head_snapshot()?;
        assert_eq!(after.commit_sequence, before.commit_sequence);
        assert_eq!(after.history_root, before.history_root);
        assert_eq!(after.state_root, before.state_root);
        assert_eq!(storage.projection().snapshot_latest().holds().count(), 0);
        assert!(
            storage
                .retention_candidates()
                .values()
                .all(|candidate| { candidate.active_event_ids.is_empty() })
        );
    }
    storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn repeated_source_bytes_resolve_inside_event_window_without_accepting_outside_frames() -> TestResult
{
    let dir = TempDirGuard::new("event-repeated-source")?;
    let manifest = manifest(1_048_576)?;
    let regions =
        DaemonRegionTree::initialize(&manifest, "principal:retention-test", TimestampNs(0))?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let early = frame(SENSOR_A, 1, 999_998, 128)?;
    let outside = frame(SENSOR_A, 2, 999_999, 128)?;
    let mut repeated = (*early).clone();
    repeated.sequence = 3;
    repeated.media_pts_ns = 1_000_000;
    repeated.host_receive_ns = 1_000_000;
    for source in [Arc::clone(&early), Arc::clone(&outside), Arc::new(repeated)] {
        let _ = storage.ingest_frame(
            source,
            CameraAdapterKind::Synthetic,
            3,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        )?;
    }
    let second = ingest(&mut storage, &regions, SENSOR_B, 4, 1_000_001, 128)?;
    let mut event = corroborated_event(outside.source_digest, media_digest(&second)?)?;
    event.evidence[0].capsule_digest = Some(outside.source_digest);
    let sensors = vec![SensorId::parse(SENSOR_A)?, SensorId::parse(SENSOR_B)?];
    let before = storage.head_snapshot()?;
    assert!(matches!(
        storage.commit_event_hypothesis(
            &event,
            sensors.clone(),
            regions.storage_ledger_cx(),
            regions.region_tree(),
        ),
        Err(DaemonError::Combiner(
            fss_projection_store::CombinerError::InvalidProposal(_)
        ))
    ));
    assert_eq!(
        storage.head_snapshot()?.commit_sequence,
        before.commit_sequence
    );
    event.evidence[0].digest = early.source_digest;
    event.evidence[0].capsule_digest = Some(early.source_digest);
    let _ = storage.commit_event_hypothesis(
        &event,
        sensors,
        regions.storage_ledger_cx(),
        regions.region_tree(),
    )?;
    assert_eq!(
        storage
            .projection()
            .snapshot_latest()
            .holds()
            .filter(|hold| hold.active)
            .count(),
        2
    );
    storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn health_transition_evidence_survives_restart_and_projection_rebuild() -> TestResult {
    let dir = TempDirGuard::new("health-receipts")?;
    let manifest = manifest(1_048_576)?;
    let regions = DaemonRegionTree::initialize(&manifest, "principal:health-test", TimestampNs(0))?;
    let sensor = SensorId::parse(SENSOR_A)?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    // Storage treats these as opaque canonical receipts. The health-screen integration
    // separately proves their sensor, generation, policy, and exact source bindings.
    let receipts: [&[u8]; 2] = [
        b"health:test:source-1:degraded",
        b"health:test:source-2:clear",
    ];
    let mut digests = Vec::new();
    for (index, evidence) in receipts.into_iter().enumerate() {
        let degraded = index == 0;
        let status = if degraded {
            CoverageStatus::NotObservable
        } else {
            CoverageStatus::Covered
        };
        let committed = storage.commit_health_coverage_and_liveness(
            &sensor,
            "driveway",
            status,
            if degraded {
                SensorLivenessStatus::Degraded
            } else {
                SensorLivenessStatus::Online
            },
            u32::from(degraded),
            u32::from(degraded),
            TimestampNs(10 + index as i128),
            TimestampNs(10 + index as i128),
            evidence,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        )?;
        let digest = ContentDigest::sha256(evidence);
        assert_eq!(storage.pack_store().read_verified(&digest)?, evidence);
        let snapshot = storage.projection().snapshot_latest();
        let coverage = snapshot
            .get_coverage(&sensor, "driveway")
            .ok_or("coverage absent")?;
        assert_eq!(coverage.status, status);
        assert_eq!(coverage.health_conflicts, u32::from(degraded));
        assert_eq!(coverage.committed_sequence, committed.commit_sequence);
        digests.push(digest);
    }
    storage.shutdown_and_flush()?;

    let inspection =
        fss_ledger::inspect_epochs_readonly(&dir.path().join("ledger"), &manifest.site_id)?;
    assert_eq!(inspection.batches.len(), 2);
    for (batch, expected_witness) in inspection.batches.iter().zip(&digests) {
        assert_eq!(batch.deltas.len(), 2);
        for delta in &batch.deltas {
            assert_eq!(delta.witness_digest, Some(*expected_witness));
        }
    }
    fs::remove_dir_all(dir.path().join(PROJECTION_SUBDIR))?;
    let reopened = StorageEngine::open(&manifest, Some(dir.path()))?;
    for (evidence, digest) in receipts.into_iter().zip(&digests) {
        assert_eq!(reopened.pack_store().read_verified(digest)?, evidence);
    }
    let snapshot = reopened.projection().snapshot_latest();
    let coverage = snapshot
        .get_coverage(&sensor, "driveway")
        .ok_or("rebuilt coverage absent")?;
    assert_eq!(coverage.status, CoverageStatus::Covered);
    assert_eq!(coverage.health_conflicts, 0);
    assert_eq!(coverage.active_gaps, 0);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn refused_health_transition_publishes_neither_state_nor_receipt() -> TestResult {
    let dir = TempDirGuard::new("health-refusal")?;
    let manifest = manifest(1_048_576)?;
    let mut regions =
        DaemonRegionTree::initialize(&manifest, "principal:health-test", TimestampNs(0))?;
    let sensor = SensorId::parse(SENSOR_A)?;
    let mut storage = StorageEngine::open(&manifest, Some(dir.path()))?;
    let oversized = vec![0x5a; 64 * 1024 + 1];
    for evidence in [&[][..], oversized.as_slice()] {
        let result = storage.commit_health_coverage_and_liveness(
            &sensor,
            "driveway",
            CoverageStatus::NotObservable,
            SensorLivenessStatus::Degraded,
            1,
            1,
            TimestampNs(10),
            TimestampNs(10),
            evidence,
            regions.storage_ledger_cx(),
            regions.region_tree(),
        );
        assert!(matches!(result, Err(DaemonError::InvalidConfig { .. })));
        assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
        assert!(
            storage
                .pack_store()
                .lookup(&ContentDigest::sha256(evidence))?
                .is_none()
        );
    }
    regions.request_shutdown(TimestampNs(11))?;
    let evidence = b"health:test:cancelled-before-publication";
    assert!(
        storage
            .commit_health_coverage_and_liveness(
                &sensor,
                "driveway",
                CoverageStatus::NotObservable,
                SensorLivenessStatus::Degraded,
                1,
                1,
                TimestampNs(12),
                TimestampNs(12),
                evidence,
                regions.storage_ledger_cx(),
                regions.region_tree(),
            )
            .is_err()
    );
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
    assert!(
        storage
            .pack_store()
            .lookup(&ContentDigest::sha256(evidence))?
            .is_none()
    );
    assert!(
        storage
            .projection()
            .snapshot_latest()
            .get_coverage(&sensor, "driveway")
            .is_none()
    );
    storage.shutdown_and_flush()?;
    Ok(())
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

    let fresh_regions = DaemonRegionTree::initialize(
        &manifest,
        "principal:retention-test",
        TimestampNs(4_000_000),
    )?;
    let receipt = storage.flush_camera_gop(
        &sensor_id,
        CameraAdapterKind::Synthetic,
        fresh_regions.storage_ledger_cx(),
        fresh_regions.region_tree(),
    )?;
    assert!(
        receipt.is_some(),
        "the cancelled flush must retain its source GOP"
    );
    assert_eq!(storage.retention_candidates().len(), 1);
    let candidate = storage
        .retention_candidates()
        .values()
        .next()
        .ok_or("retry did not retain a GOP")?;
    let source = storage
        .pack_store()
        .read_verified(&media_digest(candidate)?)?;
    let chunk = fss_pack::MediaChunkView::parse(&source)?;
    assert_eq!(chunk.frame_count(), 2);
    assert_eq!(
        chunk.frame_bytes_verified(0)?,
        source_a.encoded_payload.as_slice()
    );
    assert_eq!(
        chunk.frame_bytes_verified(1)?,
        source_b.encoded_payload.as_slice()
    );
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
    let _ = storage
        .pack_store()
        .append_batch(&[fss_pack::PackObjectInput::new(
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
    assert_eq!(
        committed.commit_sequence, 1,
        "the failure follows canonical commit"
    );
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
        assert_eq!(
            storage.head_snapshot()?.history_root,
            committed.history_root
        );
        assert_eq!(
            storage.head_snapshot()?.commit_sequence,
            committed.commit_sequence
        );
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
        assert_eq!(
            reopened.head_snapshot()?.history_root,
            committed.history_root
        );
        assert_eq!(
            reopened.head_snapshot()?.commit_sequence,
            committed.commit_sequence
        );
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
    assert!(
        reopened
            .projection()
            .snapshot_latest()
            .get_footage_import(&digest)
            .is_none()
    );
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
    assert_eq!(
        reopened.head_snapshot()?.history_root,
        committed.history_root
    );
    assert_eq!(reopened.retention_candidates().len(), 1);
    assert!(
        reopened
            .retention_candidates()
            .contains_key(&newer.import_id)
    );
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
    assert_eq!(
        reopened.head_snapshot()?.history_root,
        committed.history_root
    );
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
