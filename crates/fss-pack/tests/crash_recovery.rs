#![forbid(unsafe_code)]
//! Crash-cut, torn-tail, index-rebuild, lock, and authority-cancellation tests for `fss-pack`.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs,
};
use fss_pack::{
    DurabilityMode, IndexRebuildReason, PACK_KIND_MEDIA_CHUNK, PACK_KIND_RAW_PAYLOAD, PackConfig,
    PackCutPoint, PackError, PackObjectInput, PackStore, VirtualRootRecord,
};
use fss_runtime::authority::AuthorityCx;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static RECOVERY_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRecoveryDir {
    path: PathBuf,
}

impl TempRecoveryDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = RECOVERY_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-pack-rec-{label}-{}-{id}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRecoveryDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn recovery_config(target_pack_bytes: u64) -> PackConfig {
    PackConfig {
        target_pack_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs: 8,
        ..PackConfig::default()
    }
}

#[test]
fn crash_cut_after_pack_fsync_before_root_publish_leaves_zero_visible_roots() -> TestResult {
    let dir = TempRecoveryDir::new("crash-root-last")?;
    let store = PackStore::open(&dir.path, recovery_config(1024 * 1024))?;

    let chunk_bytes = b"simulated-gop-chunk-payload".repeat(16);
    let chunk_digest = ContentDigest::sha256(&chunk_bytes);
    let root = VirtualRootRecord::new(
        "cam-front:gop:000001",
        chunk_digest,
        "media-gop-v1",
        1,
        chunk_bytes.len() as u64,
        1,
        TimestampNs(1_700_000_000),
        None,
    )?;

    let res = store.publish_graph_with_cut_point(
        &[PackObjectInput::with_digest(
            PACK_KIND_MEDIA_CHUNK,
            0,
            &chunk_bytes,
            chunk_digest,
        )],
        root,
        PackCutPoint::AfterPackSyncBeforeRootAppend,
    );
    assert!(matches!(
        res,
        Err(PackError::InjectedCrash(
            PackCutPoint::AfterPackSyncBeforeRootAppend
        ))
    ));
    drop(store);

    // Reopen after crash: children ARE durable and verified, ZERO partial/visible roots exist!
    let reopened = PackStore::open(&dir.path, recovery_config(1024 * 1024))?;
    assert_eq!(reopened.read_verified(&chunk_digest)?, chunk_bytes);
    assert_eq!(reopened.get_root("cam-front:gop:000001")?, None);
    assert_eq!(reopened.live_root_count()?, 0);
    Ok(())
}

#[test]
fn truncated_and_torn_active_pack_tail_and_catalog_tail_recover_cleanly() -> TestResult {
    let dir = TempRecoveryDir::new("torn-tail")?;
    let store = PackStore::open(&dir.path, recovery_config(1024 * 1024))?;

    let p1 = b"committed-object-1".repeat(8);
    let p2 = b"committed-object-2".repeat(8);
    let d1 = ContentDigest::sha256(&p1);
    let d2 = ContentDigest::sha256(&p2);
    let locs = store.append_batch(&[
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p1),
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p2),
    ])?;
    let active_pack_id = locs[0].pack_id;

    let r1 = VirtualRootRecord::new(
        "root-1",
        d1,
        "raw",
        1,
        p1.len() as u64,
        1,
        TimestampNs(10),
        None,
    )?;
    let _ = store.publish_root(r1)?;
    drop(store);

    // Inject torn partial FSSP record at end of active packfile.
    let pack_path = dir
        .path
        .join("objects")
        .join("packs")
        .join(active_pack_id.file_name());
    {
        let mut f = OpenOptions::new().append(true).open(&pack_path)?;
        f.write_all(b"FSSP\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80partial-torn")?;
        f.sync_all()?;
    }

    // Also inject torn trailing bytes into catalog.fssr.
    let journal_path = dir.path.join("objects").join("roots").join("catalog.fssr");
    {
        let mut jf = OpenOptions::new().append(true).open(&journal_path)?;
        jf.write_all(b"FSSR\x00\x01\x00\x01torn-frame-bytes")?;
        jf.sync_all()?;
    }

    let reopened = PackStore::open(&dir.path, recovery_config(1024 * 1024))?;
    assert!(reopened.recovery_report().packs.truncated_tail_bytes > 0);
    assert!(reopened.recovery_report().catalog.truncated_journal_bytes > 0);
    assert_eq!(reopened.read_verified(&d1)?, p1);
    assert_eq!(reopened.read_verified(&d2)?, p2);
    assert_eq!(reopened.live_root_count()?, 1);

    let p3 = b"post-recovery-object-3".repeat(4);
    let d3 = ContentDigest::sha256(&p3);
    let _ = reopened.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p3)])?;
    assert_eq!(reopened.read_verified(&d3)?, p3);
    Ok(())
}

#[test]
fn missing_corrupt_and_stale_index_deterministically_rebuilds_from_packs() -> TestResult {
    let dir = TempRecoveryDir::new("index-rebuild")?;
    let store = PackStore::open(&dir.path, recovery_config(512))?;

    let mut items = Vec::new();
    for i in 0_u32..10 {
        let payload = format!("indexed-object-payload-{i:04}")
            .repeat(12)
            .into_bytes();
        let digest = ContentDigest::sha256(&payload);
        let locs = store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &payload,
            digest,
        )])?;
        items.push((digest, payload, locs[0]));
    }
    let _ = store.save_index_snapshot()?;
    let index_path = dir
        .path
        .join("objects")
        .join("index")
        .join("pack-index.fssi");
    assert!(index_path.exists());
    drop(store);

    // 1. Fresh open with valid matching index -> loaded without rebuild.
    {
        let s = PackStore::open(&dir.path, recovery_config(512))?;
        assert_eq!(s.recovery_report().packs.index_rebuild_reason, None);
    }

    // 2. Delete pack-index.fssi -> deterministic rebuild with IndexRebuildReason::Missing.
    fs::remove_file(&index_path)?;
    {
        let s = PackStore::open(&dir.path, recovery_config(512))?;
        assert_eq!(
            s.recovery_report().packs.index_rebuild_reason,
            Some(IndexRebuildReason::Missing)
        );
        for (digest, payload, orig_loc) in &items {
            let loc = s.lookup(digest)?.ok_or("missing rebuilt location")?;
            assert_eq!(loc.pack_id, orig_loc.pack_id);
            assert_eq!(loc.offset, orig_loc.offset);
            assert_eq!(loc.len, orig_loc.len);
            assert_eq!(s.read_verified(digest)?, *payload);
        }
    }

    // 3. Corrupt pack-index.fssi bytes -> deterministic rebuild with IndexRebuildReason::Corrupt.
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&index_path)?;
        let mut raw = Vec::new();
        f.read_to_end(&mut raw)?;
        raw[10] ^= 0xFF;
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&raw)?;
        f.sync_all()?;
    }
    {
        let s = PackStore::open(&dir.path, recovery_config(512))?;
        assert_eq!(
            s.recovery_report().packs.index_rebuild_reason,
            Some(IndexRebuildReason::Corrupt)
        );
        assert_eq!(s.recovery_report().packs.indexed_objects, items.len());
    }

    // 4. Stale index -> deterministic rebuild with IndexRebuildReason::StaleInventory.
    let stale_snapshot = fs::read(&index_path)?;
    let extra = b"extra-after-snapshot".repeat(16);
    let extra_digest = ContentDigest::sha256(&extra);
    {
        let s = PackStore::open(&dir.path, recovery_config(512))?;
        let _ = s.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &extra)])?;
    }
    fs::write(&index_path, &stale_snapshot)?;
    {
        let s = PackStore::open(&dir.path, recovery_config(512))?;
        assert_eq!(
            s.recovery_report().packs.index_rebuild_reason,
            Some(IndexRebuildReason::StaleInventory)
        );
        assert_eq!(s.read_verified(&extra_digest)?, extra);
    }
    Ok(())
}

#[test]
fn exclusive_lock_and_authority_cancellation_are_enforced() -> TestResult {
    let dir = TempRecoveryDir::new("lock-and-cx")?;
    let store = PackStore::open(&dir.path, recovery_config(4096))?;

    assert!(matches!(
        PackStore::open(&dir.path, recovery_config(4096)),
        Err(PackError::StoreLocked)
    ));

    let budgets = BudgetVector::builder().tokens(64).bytes(4096).build()?;
    let spec = RootAuthoritySpec {
        trace_id: "trace:pack-test".to_owned(),
        operation_id: OperationId::parse("op:pack:write:1")?,
        principal: "operator:local".to_owned(),
        capabilities: vec!["CAP-MEDIA-DECODE-001".to_owned()],
        deadline: Some(TimestampNs(1_000_000)),
        priority: 10,
        budgets,
        privacy_scope: "owner-private".to_owned(),
        retention_scope: "standard".to_owned(),
        anchor_universe: ContentDigest::sha256(b"pack-test-universe"),
        generation: 1,
    };
    let (cx, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:pack-test")?,
        RegionKind::Process,
        budgets,
        TimestampNs(1),
    )?;
    cx.request_cancellation(&mut tree, TimestampNs(2))?;

    let payload = b"must-not-be-written";
    let res = store.append_batch_with_authority(
        &cx,
        &tree,
        &[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload)],
    );
    assert!(matches!(res, Err(PackError::Cancelled)));
    assert_eq!(store.lookup(&ContentDigest::sha256(payload))?, None);
    Ok(())
}
