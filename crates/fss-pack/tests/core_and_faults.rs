#![forbid(unsafe_code)]
//! Unit and contract tests for `fss-pack` framing, dedup, catalog, media chunks, and read bounds.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{CanonicalEncode, ClockBasis, ContentDigest, DigestAlgorithm, TimestampNs};
use fss_object::{ObjectManifest, VerifiedObjectCatalog};
use fss_pack::{
    DurabilityMode, MEDIA_FRAME_FLAG_CONFIG, MEDIA_FRAME_FLAG_KEYFRAME, MediaChunkBuilder,
    MediaChunkView, MediaCodec, PACK_KIND_METADATA, PACK_KIND_OBJECT_MANIFEST,
    PACK_KIND_RAW_PAYLOAD, PACK_RECORD_HEADER_LEN, PACK_RECORD_TRAILER_LEN, PackConfig, PackError,
    PackObjectInput, PackObjectState, PackReadBudget, PackStore, QuotaPolicy, QuotaResource,
    QuotaStatus, RootStatus, VirtualRootRecord, crc32c,
};
use fss_publication::SlotName;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempStoreDir {
    path: PathBuf,
}

impl TempStoreDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-pack-core-{label}-{}-{id}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempStoreDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_config(target_pack_bytes: u64) -> PackConfig {
    PackConfig {
        target_pack_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs: 8,
        ..PackConfig::default()
    }
}

#[test]
fn group_commit_dedup_and_sealed_footer_verification() -> TestResult {
    let dir = TempStoreDir::new("dedup-seal")?;
    // Two 248-byte payloads + 54-byte framing each = 604 bytes <= 700, so `a` and `b` commit
    // in one pack with 1 fsync, and adding `c` (906 > 700) triggers clean seal + rotation.
    let store = PackStore::open(&dir.path, test_config(700))?;

    let a = b"alpha-sensor-frame-payload-0001".repeat(8);
    let b = b"beta-sensor-frame-payload-0002".repeat(8);
    let c = b"gamma-sensor-frame-payload-0003".repeat(8);
    let da = ContentDigest::sha256(&a);
    let db = ContentDigest::sha256(&b);
    let dc = ContentDigest::sha256(&c);

    // Intra-batch deduplication: `a` appears twice, written only once with 1 fsync.
    let locs = store.append_batch(&[
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &a, da),
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 1, &b, db),
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &a, da),
    ])?;
    assert_eq!(locs.len(), 3);
    assert_eq!(locs[0], locs[2]);
    assert_ne!(locs[0].offset, locs[1].offset);
    assert_eq!(store.telemetry_snapshot()?.pack_fsync_count, 1);

    // Appending `c` pushes over target_pack_bytes=512, triggering clean seal + rotation.
    let locs2 = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_METADATA, 0, &c),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &a),
    ])?;
    assert_eq!(locs2[1].pack_id, locs[0].pack_id);
    assert_eq!(locs2[1].offset, locs[0].offset);
    assert_eq!(locs2[1].state, PackObjectState::Sealed);
    assert_ne!(locs2[0].pack_id, locs[0].pack_id);

    let footer = store.verify_pack(locs[0].pack_id)?;
    assert_eq!(footer.entries.len(), 2);

    // Pure duplicates perform ZERO writes and ZERO fsyncs.
    let before_fsyncs = store.telemetry_snapshot()?.pack_fsync_count;
    let dup_locs = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &a),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &b),
        PackObjectInput::new(PACK_KIND_METADATA, 0, &c),
    ])?;
    assert_eq!(dup_locs[0].pack_id, locs[0].pack_id);
    assert_eq!(store.telemetry_snapshot()?.pack_fsync_count, before_fsyncs);

    assert_eq!(store.read_verified(&da)?, a);
    assert_eq!(store.read_verified(&db)?, b);
    assert_eq!(store.read_verified(&dc)?, c);
    store.require_all_verified(&[da, db, dc])?;

    let sealed = store.seal_active_pack()?;
    assert!(sealed.is_some());
    drop(store);

    // FullSync (macOS F_FULLFSYNC via std File::sync_all) durability verification.
    let full_sync_cfg = PackConfig {
        durability: DurabilityMode::FullSync,
        ..test_config(512)
    };
    let reopened = PackStore::open(&dir.path, full_sync_cfg)?;
    let d = b"full-sync-payload".repeat(4);
    let dd = ContentDigest::sha256(&d);
    let _ = reopened.append_batch(&[PackObjectInput::with_digest(
        PACK_KIND_RAW_PAYLOAD,
        0,
        &d,
        dd,
    )])?;
    assert_eq!(reopened.read_verified(&dd)?, d);
    Ok(())
}

#[test]
fn corruption_detection_catches_crc_and_sha256_and_footer_tampering() -> TestResult {
    let dir = TempStoreDir::new("corrupt-detect")?;
    let store = PackStore::open(&dir.path, test_config(1024 * 1024))?;

    let payload = b"immutable-evidential-payload-bytes-42".repeat(4);
    let digest = ContentDigest::sha256(&payload);
    let locs = store.append_batch(&[PackObjectInput::with_digest(
        PACK_KIND_RAW_PAYLOAD,
        0,
        &payload,
        digest,
    )])?;
    let loc = locs[0];
    let sealed = store.seal_active_pack()?.ok_or("expected sealed pack")?;
    assert_eq!(sealed.pack_id, loc.pack_id);

    // Case 1: Flip 1 byte in the payload -> read_verified catches CRC32C mismatch.
    let pack_path = dir
        .path
        .join("objects")
        .join("packs")
        .join(loc.pack_id.file_name());
    let mut raw = fs::read(&pack_path)?;
    let flip_pos = (loc.offset as usize) + PACK_RECORD_HEADER_LEN + 5;
    raw[flip_pos] ^= 0xFF;
    fs::write(&pack_path, &raw)?;

    assert!(matches!(
        store.read_verified(&digest),
        Err(PackError::CrcMismatch { .. })
    ));
    assert!(matches!(
        store.verify_pack(loc.pack_id),
        Err(PackError::DigestMismatch { .. })
    ));

    // Case 2: Recompute valid CRC32C over tampered payload -> read_verified catches SHA-256 mismatch.
    let rec_len = (loc.len as usize) + PACK_RECORD_HEADER_LEN + PACK_RECORD_TRAILER_LEN;
    let crc_offset = (loc.offset as usize) + rec_len - PACK_RECORD_TRAILER_LEN;
    let forged_crc = crc32c(&raw[loc.offset as usize..crc_offset]);
    raw[crc_offset..crc_offset + 4].copy_from_slice(&forged_crc.to_be_bytes());
    fs::write(&pack_path, &raw)?;

    assert!(matches!(
        store.read_verified(&digest),
        Err(PackError::DigestMismatch { .. })
    ));
    Ok(())
}

#[test]
fn virtual_root_publish_supersede_tombstone_quotas_and_compaction() -> TestResult {
    let dir = TempStoreDir::new("catalog-lifecycle")?;
    let mut cfg = test_config(1024 * 1024);
    cfg.quota = QuotaPolicy {
        soft_max_live_roots: Some(2),
        hard_max_live_roots: Some(3),
        soft_max_total_bytes: None,
        hard_max_total_bytes: None,
        auto_compact_every: 100,
    };
    let store = PackStore::open(&dir.path, cfg)?;

    let p1 = b"root-object-one";
    let p2 = b"root-object-two";
    let p3 = b"root-object-three";
    let p4 = b"root-object-four";
    let d1 = ContentDigest::sha256(p1);
    let d2 = ContentDigest::sha256(p2);
    let d3 = ContentDigest::sha256(p3);
    let d4 = ContentDigest::sha256(p4);

    let manifest = ObjectManifest::new("event-clip-v1", [d1], Some(d2))?;
    let manifest_bytes = manifest.canonical_bytes();
    let _ = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, p1),
        PackObjectInput::new(PACK_KIND_METADATA, 0, p2),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, p3),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, p4),
        PackObjectInput::new(PACK_KIND_OBJECT_MANIFEST, 0, &manifest_bytes),
    ])?;

    let slot1 = SlotName::parse("cam1-event-0001")?;
    let r1 = VirtualRootRecord::from_manifest(
        &slot1,
        &manifest,
        (p1.len() + p2.len()) as u64,
        1,
        TimestampNs(100),
    )?;
    assert_eq!(r1.record_digest().algorithm(), DigestAlgorithm::Sha256);

    let pub1 = store.publish_root(r1)?;
    assert_eq!(pub1.quota_status, QuotaStatus::WithinPolicy);
    assert_eq!(store.live_root_count()?, 1);

    let r2 = VirtualRootRecord::new(
        "cam1-event-0002",
        d2,
        "clip",
        1,
        15,
        1,
        TimestampNs(200),
        None,
    )?;
    assert_eq!(
        store.publish_root(r2)?.quota_status,
        QuotaStatus::WithinPolicy
    );

    let r3 = VirtualRootRecord::new(
        "cam1-event-0003",
        d3,
        "clip",
        1,
        17,
        1,
        TimestampNs(300),
        None,
    )?;
    assert!(matches!(
        store.publish_root(r3)?.quota_status,
        QuotaStatus::SoftLimitExceeded {
            resource: QuotaResource::LiveRoots,
            current: 3,
            soft_limit: 2
        }
    ));

    let r4 = VirtualRootRecord::new(
        "cam1-event-0004",
        d4,
        "clip",
        1,
        16,
        1,
        TimestampNs(400),
        None,
    )?;
    assert!(matches!(
        store.publish_root(r4.clone()),
        Err(PackError::QuotaExceeded {
            resource: QuotaResource::LiveRoots,
            ..
        })
    ));

    let r2_v2 = VirtualRootRecord::new(
        "cam1-event-0002-v2",
        d4,
        "clip",
        1,
        16,
        2,
        TimestampNs(450),
        None,
    )?;
    let sup = store.supersede_root("cam1-event-0002", r2_v2)?;
    assert_eq!(sup.entry.predecessor.as_deref(), Some("cam1-event-0002"));
    assert_eq!(store.live_root_count()?, 3);
    let old_r2 = store
        .get_root("cam1-event-0002")?
        .ok_or("old root must stay retained")?;
    assert!(matches!(
        old_r2.status,
        RootStatus::Superseded {
            ref superseded_by,
            ..
        } if superseded_by == "cam1-event-0002-v2"
    ));

    assert!(matches!(
        store.supersede_root("cam1-event-0002", r4),
        Err(PackError::RootNotLive(_))
    ));

    let reason_a = ContentDigest::sha256(b"retention-expired-v1");
    let reason_b = ContentDigest::sha256(b"legal-hold-conflict");
    let tomb = store.tombstone_root("cam1-event-0003", reason_a)?;
    assert!(matches!(tomb.status, RootStatus::Tombstoned { .. }));
    assert_eq!(store.live_root_count()?, 2);
    assert_eq!(store.tombstone_root("cam1-event-0003", reason_a)?, tomb);
    assert!(matches!(
        store.tombstone_root("cam1-event-0003", reason_b),
        Err(PackError::TombstoneConflict { .. })
    ));

    let page1 = store.list_roots(None, 2)?;
    assert_eq!(page1.entries.len(), 2);
    assert!(page1.has_more);
    let page2 = store.list_roots(page1.next_cursor.as_deref(), 2)?;
    assert_eq!(page2.entries.len(), 2);
    assert!(!page2.has_more);
    assert_eq!(store.list_live_roots(None, 10)?.entries.len(), 2);

    let compact = store.compact_catalog()?;
    assert_eq!(compact.total_entries, 4);
    assert_eq!(compact.live_entries, 2);
    drop(store);

    let reopened = PackStore::open(&dir.path, cfg)?;
    assert_eq!(reopened.live_root_count()?, 2);
    assert_eq!(reopened.recovery_report().catalog.total_entries, 4);
    assert!(matches!(
        reopened
            .get_root("cam1-event-0003")?
            .ok_or("tombstone missing")?
            .status,
        RootStatus::Tombstoned { reason_digest, .. } if reason_digest == reason_a
    ));
    Ok(())
}

#[test]
fn media_chunk_round_trip_and_per_frame_verification() -> TestResult {
    for codec in [MediaCodec::H264, MediaCodec::H265, MediaCodec::Mjpeg] {
        let mut builder =
            MediaChunkBuilder::new("cam-driveway-01", codec, ClockBasis::DeviceMonotonic)?;
        let mut expected_frames = Vec::new();
        for i in 0_u64..12 {
            let payload: Vec<u8> = (0_usize..256)
                .map(|j| ((i as usize).wrapping_mul(31).wrapping_add(j) & 0xFF) as u8)
                .collect();
            let flags = if i == 0 {
                MEDIA_FRAME_FLAG_KEYFRAME | MEDIA_FRAME_FLAG_CONFIG
            } else {
                0
            };
            let receipt = builder.push_frame(
                1000 + i,
                TimestampNs(1_000_000 + (i as i128) * 50_000_000),
                flags,
                &payload,
            )?;
            assert_eq!(receipt.frame_index, i as usize);
            expected_frames.push((payload, receipt.digest));
        }

        let built = builder.build()?;
        let view = MediaChunkView::parse(&built.bytes)?;
        assert_eq!(view.codec(), codec);
        assert_eq!(view.stream_id(), "cam-driveway-01");
        assert_eq!(view.chunk_digest(), built.chunk_digest);
        view.verify_all_frames()?;

        for (idx, (payload, digest)) in expected_frames.iter().enumerate() {
            assert_eq!(view.frame_bytes_verified(idx)?, payload.as_slice());
            assert_eq!(view.find_by_digest(*digest), Some(idx));
        }

        let mut tampered = built.bytes.clone();
        let last_idx = tampered.len() - 1;
        tampered[last_idx] ^= 0x55;
        let tampered_view = MediaChunkView::parse(&tampered)?;
        assert!(matches!(
            tampered_view.frame_bytes_verified(11),
            Err(PackError::DigestMismatch { .. })
        ));
    }
    Ok(())
}

#[test]
fn bounded_read_limits_and_cumulative_read_budget_enforced() -> TestResult {
    let dir = TempStoreDir::new("read-bounds")?;
    let mut cfg = test_config(1024 * 1024);
    cfg.max_object_bytes = 256;
    cfg.max_read_bytes = 256 + 54;
    let store = PackStore::open(&dir.path, cfg)?;

    let too_big = vec![0xAB_u8; 300];
    assert!(matches!(
        store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &too_big)]),
        Err(PackError::ObjectTooLarge { .. })
    ));

    let p1 = vec![0x11_u8; 200];
    let p2 = vec![0x22_u8; 200];
    let d1 = ContentDigest::sha256(&p1);
    let d2 = ContentDigest::sha256(&p2);
    let _ = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p1),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p2),
    ])?;

    let budget = PackReadBudget::new(300);
    assert_eq!(store.read_verified_with_budget(&d1, &budget)?, p1);
    assert_eq!(budget.used_bytes(), 254);
    assert!(matches!(
        store.read_verified_with_budget(&d2, &budget),
        Err(PackError::ReadLimitExceeded { .. })
    ));

    drop(store);
    let tighter = PackConfig {
        max_read_bytes: 128,
        ..cfg
    };
    let reopened = PackStore::open(&dir.path, tighter)?;
    assert!(matches!(
        reopened.read_verified(&d1),
        Err(PackError::ReadLimitExceeded { .. })
    ));
    Ok(())
}
