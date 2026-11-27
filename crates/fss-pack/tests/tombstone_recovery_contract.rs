#![forbid(unsafe_code)]
//! Deletion-log recovery must never turn corrupt committed history into readable evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::ContentDigest;
use fss_pack::{
    DurabilityMode, OBJECT_TOMBSTONE_RECORD_LEN, ObjectTombstoneLog, PACK_KIND_RAW_PAYLOAD,
    PackConfig, PackError, PackObjectInput, PackStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Tombstone = (ContentDigest, ContentDigest);

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Result<Self, std::io::Error> {
        let serial = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-tombstone-recovery-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn seed_log(path: &Path) -> Result<([Tombstone; 3], Vec<u8>), Box<dyn std::error::Error>> {
    let rows = [
        (
            ContentDigest::sha256(b"source-a"),
            ContentDigest::sha256(b"reason-a"),
        ),
        (
            ContentDigest::sha256(b"source-b"),
            ContentDigest::sha256(b"reason-b"),
        ),
        (
            ContentDigest::sha256(b"source-c"),
            ContentDigest::sha256(b"reason-c"),
        ),
    ];
    let mut log = ObjectTombstoneLog::open(path, DurabilityMode::Fsync)?;
    assert_eq!(log.append_batch(&rows)?, rows.len());
    drop(log);
    let bytes = fs::read(path)?;
    assert_eq!(bytes.len(), rows.len() * OBJECT_TOMBSTONE_RECORD_LEN);
    Ok((rows, bytes))
}

#[test]
fn complete_corrupt_records_fail_closed_without_truncating_history() -> TestResult {
    let dir = TestDir::new()?;
    let path = dir.0.join("deletions.fssr");
    let (_, pristine) = seed_log(&path)?;

    // Corrupt first, middle, and final complete frames, including each semantic field.
    // A complete final frame is no more safely discardable than an interior one.
    for record in 0..3 {
        for field_offset in [0, 4, 6, 8, 40, 72] {
            let mut damaged = pristine.clone();
            damaged[record * OBJECT_TOMBSTONE_RECORD_LEN + field_offset] ^= 0x80;
            fs::write(&path, &damaged)?;
            let opened = ObjectTombstoneLog::open(&path, DurabilityMode::Fsync);
            assert!(
                matches!(&opened, Err(PackError::CorruptCatalog { .. })),
                "record={record} field_offset={field_offset}: {opened:?}"
            );
            assert_eq!(
                fs::read(&path)?,
                damaged,
                "failed recovery must preserve every byte for repair"
            );
        }
    }
    Ok(())
}

#[test]
fn every_incomplete_append_recovers_the_verified_prefix_and_can_resume() -> TestResult {
    let dir = TestDir::new()?;
    let path = dir.0.join("deletions.fssr");
    let (rows, pristine) = seed_log(&path)?;
    let prefix_len = 2 * OBJECT_TOMBSTONE_RECORD_LEN;

    for tail_len in 1..OBJECT_TOMBSTONE_RECORD_LEN {
        fs::write(&path, &pristine[..prefix_len + tail_len])?;
        let mut recovered = ObjectTombstoneLog::open(&path, DurabilityMode::Fsync)?;
        assert_eq!(recovered.len(), 2, "tail_len={tail_len}");
        assert_eq!(recovered.get(&rows[0].0), Some(rows[0].1));
        assert_eq!(recovered.get(&rows[1].0), Some(rows[1].1));
        assert_eq!(recovered.get(&rows[2].0), None);
        assert_eq!(fs::read(&path)?, pristine[..prefix_len]);

        // Retrying already durable deletions must retain the first reason and append only
        // the interrupted record, at the recovered offset.
        let changed_reason = ContentDigest::sha256(b"later-reason");
        assert_eq!(recovered.append_batch(&[(rows[0].0, changed_reason)])?, 0);
        assert_eq!(recovered.get(&rows[0].0), Some(rows[0].1));
        assert_eq!(recovered.append_batch(&[rows[2]])?, 1);
        drop(recovered);
        assert_eq!(fs::read(&path)?, pristine);
        let reopened = ObjectTombstoneLog::open(&path, DurabilityMode::Fsync)?;
        assert_eq!(reopened.len(), 3);
        assert_eq!(reopened.get(&rows[2].0), Some(rows[2].1));
    }
    Ok(())
}

#[test]
fn corrupt_prefix_with_incomplete_tail_is_preserved_for_explicit_repair() -> TestResult {
    let dir = TestDir::new()?;
    let path = dir.0.join("deletions.fssr");
    let (_, pristine) = seed_log(&path)?;
    let mut damaged = pristine[..2 * OBJECT_TOMBSTONE_RECORD_LEN + 17].to_vec();
    damaged[OBJECT_TOMBSTONE_RECORD_LEN + 8] ^= 1;
    fs::write(&path, &damaged)?;

    assert!(matches!(
        ObjectTombstoneLog::open(&path, DurabilityMode::Fsync),
        Err(PackError::CorruptCatalog { .. })
    ));
    assert_eq!(fs::read(&path)?, damaged);
    Ok(())
}

#[test]
fn pack_store_refuses_reopen_instead_of_resurrecting_deleted_source_bytes() -> TestResult {
    let dir = TestDir::new()?;
    let deleted_bytes = b"retained source later deleted";
    let live_bytes = b"independent retained source";
    let deleted = ContentDigest::sha256(deleted_bytes);
    let live = ContentDigest::sha256(live_bytes);
    let reason = ContentDigest::sha256(b"authorized deletion");
    {
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        let _ = store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, deleted_bytes, deleted),
            PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, live_bytes, live),
        ])?;
        let _ = store.seal_active_pack()?;
    }

    let path = dir.0.join("objects/roots/object-tombstones.fssr");
    {
        let mut log = ObjectTombstoneLog::open(&path, DurabilityMode::Fsync)?;
        assert_eq!(log.append_batch(&[(deleted, reason)])?, 1);
    }
    let pristine = fs::read(&path)?;
    let mut damaged = pristine.clone();
    damaged[72] ^= 1;
    fs::write(&path, &damaged)?;

    assert!(matches!(
        PackStore::open(&dir.0, PackConfig::default()),
        Err(PackError::CorruptCatalog { .. })
    ));
    assert_eq!(fs::read(&path)?, damaged);

    // Restore the exact verified log as an explicit repair fixture. Recovery then retains
    // the deletion while leaving unrelated evidence usable.
    fs::write(&path, &pristine)?;
    let recovered = PackStore::open(&dir.0, PackConfig::default())?;
    assert!(matches!(
        recovered.read_verified(&deleted),
        Err(PackError::EvidenceDeleted { digest, reason_digest })
            if digest == deleted && reason_digest == reason
    ));
    assert_eq!(recovered.read_verified(&live)?, live_bytes);
    Ok(())
}

#[test]
fn missing_deletion_history_blocks_rebuild_until_original_log_is_restored() -> TestResult {
    let dir = TestDir::new()?;
    let payload = b"source bytes still in a sealed pack";
    let digest = ContentDigest::sha256(payload);
    let reason = ContentDigest::sha256(b"authorized erasure");
    let log_path = dir.0.join("objects/roots/object-tombstones.fssr");
    {
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload)])?;
        store.seal_active_pack()?;
    }
    let mut log = ObjectTombstoneLog::open(&log_path, DurabilityMode::Fsync)?;
    log.append_batch(&[(digest, reason)])?;
    drop(log);
    let saved = fs::read(&log_path)?;
    fs::remove_file(&log_path)?;
    for _ in 0..2 {
        assert!(matches!(
            PackStore::open(&dir.0, PackConfig::default()),
            Err(PackError::CorruptCatalog { .. })
        ));
        assert!(!log_path.try_exists()?);
    }
    fs::write(&log_path, saved)?;
    let recovered = PackStore::open(&dir.0, PackConfig::default())?;
    assert!(
        matches!(recovered.read_verified(&digest), Err(PackError::EvidenceDeleted { reason_digest, .. }) if reason_digest == reason)
    );
    Ok(())
}

#[test]
fn missing_history_distinguishes_empty_bootstrap_from_partial_store() -> TestResult {
    for populated_dir in ["packs", "index", "roots"] {
        let dir = TestDir::new()?;
        let objects = dir.0.join("objects");
        let retained = objects.join(populated_dir);
        fs::create_dir_all(&retained)?;
        fs::write(retained.join("retained-artifact"), b"must survive")?;
        assert!(matches!(
            PackStore::open(&dir.0, PackConfig::default()),
            Err(PackError::CorruptCatalog { .. })
        ));
        assert!(!objects.join("roots/object-tombstones.fssr").try_exists()?);
        assert_eq!(
            fs::read(retained.join("retained-artifact"))?,
            b"must survive"
        );
        fs::remove_file(retained.join("retained-artifact"))?;
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        assert!(
            store
                .object_tombstone(&ContentDigest::sha256(b"new"))?
                .is_none()
        );
    }
    Ok(())
}
