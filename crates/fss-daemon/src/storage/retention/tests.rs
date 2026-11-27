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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, std::io::Error> {
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

fn manifest() -> Result<SiteManifest, DaemonError> {
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

fn ingest(storage: &mut StorageEngine, regions: &DaemonRegionTree) -> TestResult {
    let luma = vec![0; 32 * 32];
    let mut encoded_payload = b"FSSA".to_vec();
    encoded_payload.extend_from_slice(&1_u64.to_be_bytes());
    encoded_payload.extend_from_slice(&1_u64.to_be_bytes());
    encoded_payload.extend_from_slice(&luma);
    let source_digest = ContentDigest::sha256(&encoded_payload);
    let frame = CameraFrame {
        sensor_id: SensorId::parse("sensor:retention")?,
        stream_generation: 1,
        stream_id: StreamId::parse("stream:retention:g1")?,
        sequence: 1,
        media_pts_ns: 10,
        host_receive_ns: 10,
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
        )? else {
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
