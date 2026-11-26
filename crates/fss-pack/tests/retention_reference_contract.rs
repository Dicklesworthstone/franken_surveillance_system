#![forbid(unsafe_code)]
//! A stale eviction plan cannot destroy direct bytes of a surviving catalog publication.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{ContentDigest, TimestampNs};
use fss_pack::{
    PACK_KIND_RAW_PAYLOAD, PackConfig, PackError, PackObjectInput, PackStore, RetentionCandidate,
    RetentionEvictionBatch, RetentionPlanOutcome, RetentionRingConfig, RootStatus,
    VirtualRootRecord, plan_retention,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, std::io::Error> {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-retention-references-{}-{serial}",
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

fn append(store: &PackStore, bytes: &[u8]) -> Result<ContentDigest, PackError> {
    store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, bytes)])?;
    Ok(ContentDigest::sha256(bytes))
}

fn root(
    id: &str,
    digest: ContentDigest,
    metadata: Option<ContentDigest>,
) -> Result<VirtualRootRecord, PackError> {
    VirtualRootRecord::new(
        id,
        digest,
        "evidence-v1",
        1,
        64,
        1,
        TimestampNs(1),
        metadata,
    )
}

fn candidate(id: &str, digests: &[ContentDigest]) -> RetentionCandidate {
    RetentionCandidate {
        import_id: id.to_owned(),
        sensor_id: "sensor:retention".to_owned(),
        capture_end_ns: TimestampNs(1),
        byte_size: 64,
        object_digests: digests.to_vec(),
        is_derived_proxy: false,
        held_by: Vec::new(),
        active_obligation_ids: Vec::new(),
        active_event_ids: Vec::new(),
    }
}

fn eviction(candidates: &[RetentionCandidate]) -> Result<RetentionEvictionBatch, PackError> {
    let config = RetentionRingConfig::new(1, 1_000_000, 1_000_000, 75, 95)?;
    match plan_retention(&config, candidates, TimestampNs(100))? {
        RetentionPlanOutcome::Evict(batch) => Ok(batch),
        _ => Err(PackError::RetentionPolicyViolation {
            detail: "fixture did not produce an eviction".to_owned(),
        }),
    }
}

fn assert_refused_without_mutation(
    store: &PackStore,
    batch: &RetentionEvictionBatch,
    roots: &[&str],
    digests: &[ContentDigest],
    expected: fn(&PackError) -> bool,
) -> TestResult {
    let catalog_before = roots
        .iter()
        .map(|id| store.get_root(id))
        .collect::<Result<Vec<_>, _>>()?;
    let index_before = digests
        .iter()
        .map(|digest| store.lookup(digest))
        .collect::<Result<Vec<_>, _>>()?;
    let deleted_before = digests
        .iter()
        .map(|digest| store.object_tombstone(digest))
        .collect::<Result<Vec<_>, _>>()?;
    let telemetry_before = store.telemetry_snapshot()?;
    let Err(error) = store.commit_eviction_tombstones(batch, Some(1)) else {
        return Err("eviction unexpectedly destroyed referenced bytes".into());
    };
    assert!(expected(&error), "unexpected refusal: {error}");
    assert_eq!(store.telemetry_snapshot()?, telemetry_before);
    for (id, before) in roots.iter().zip(catalog_before) {
        assert_eq!(store.get_root(id)?, before);
    }
    for ((digest, location), deleted) in digests.iter().zip(index_before).zip(deleted_before) {
        assert_eq!(store.lookup(digest)?, location);
        assert_eq!(store.object_tombstone(digest)?, deleted);
    }
    Ok(())
}

fn reference_conflict(error: &PackError) -> bool {
    matches!(error, PackError::RetentionPolicyViolation { .. })
}

#[test]
fn new_root_or_metadata_reference_invalidates_an_older_eviction_plan() -> TestResult {
    for as_metadata in [false, true] {
        let dir = TestDirectory::new()?;
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        let shared = append(&store, b"shared source evidence")?;
        let other = append(&store, b"new publication descriptor")?;
        store.publish_root(root("old", shared, None)?)?;
        let batch = eviction(&[candidate("old", &[shared])])?;
        let new = if as_metadata {
            root("new", other, Some(shared))?
        } else {
            root("new", shared, None)?
        };
        store.publish_root(new)?;
        assert_refused_without_mutation(
            &store,
            &batch,
            &["old", "new"],
            &[shared, other],
            reference_conflict,
        )?;
        drop(store);
        let reopened = PackStore::open(&dir.0, PackConfig::default())?;
        for id in ["old", "new"] {
            assert!(matches!(
                reopened.get_root(id)?.ok_or("root disappeared")?.status,
                RootStatus::Live
            ));
        }
        assert_eq!(reopened.read_verified(&shared)?, b"shared source evidence");
    }
    Ok(())
}

#[test]
fn superseded_target_does_not_exempt_its_live_successor() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let shared = append(&store, b"retained predecessor evidence")?;
    let successor = append(&store, b"successor descriptor")?;
    store.publish_root(root("old", shared, None)?)?;
    let batch = eviction(&[candidate("old", &[shared])])?;
    store.supersede_root("old", root("new", successor, Some(shared))?)?;
    assert_refused_without_mutation(
        &store,
        &batch,
        &["old", "new"],
        &[shared, successor],
        reference_conflict,
    )?;
    Ok(())
}

#[test]
fn later_reference_conflict_refuses_every_root_in_the_eviction_batch() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let first = append(&store, b"first planned deletion")?;
    let last = append(&store, b"last planned deletion")?;
    let survivor = append(&store, b"surviving descriptor")?;
    store.publish_roots_batch(&[root("a-first", first, None)?, root("z-last", last, None)?])?;
    let batch = eviction(&[candidate("a-first", &[first]), candidate("z-last", &[last])])?;
    assert_eq!(batch.tombstones[0].import_id, "a-first");
    store.publish_root(root("survivor", survivor, Some(last))?)?;
    // The first deletion is valid by itself, but the later conflict refuses the whole batch.
    assert_refused_without_mutation(
        &store,
        &batch,
        &["a-first", "z-last", "survivor"],
        &[first, last, survivor],
        reference_conflict,
    )?;
    Ok(())
}

#[test]
fn protection_scan_reaches_survivors_beyond_the_first_catalog_page() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let target = append(&store, b"protected on a later page")?;
    let filler = append(&store, b"other roots")?;
    store.publish_root(root("a-target", target, None)?)?;
    let batch = eviction(&[candidate("a-target", &[target])])?;
    let mut records = (0..512)
        .map(|index| root(&format!("middle:{index:04}"), filler, None))
        .collect::<Result<Vec<_>, _>>()?;
    records.push(root("z-survivor", filler, Some(target))?);
    store.publish_roots_batch(&records)?;
    assert!(store.list_live_roots(None, 512)?.has_more);
    assert_refused_without_mutation(
        &store,
        &batch,
        &["a-target", "z-survivor"],
        &[target, filler],
        reference_conflict,
    )?;
    Ok(())
}

#[test]
fn absent_retirement_id_cannot_exempt_a_live_reference() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let target = append(&store, b"root outside the retention candidate set")?;
    store.publish_root(root("live", target, None)?)?;
    let batch = eviction(&[candidate("absent", &[target])])?;
    assert_refused_without_mutation(
        &store,
        &batch,
        &["absent", "live"],
        &[target],
        reference_conflict,
    )?;
    Ok(())
}

#[test]
fn duplicate_imports_and_prior_reason_conflicts_refuse_before_any_catalog_write() -> TestResult {
    for duplicate in [false, true] {
        let dir = TestDirectory::new()?;
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        let first = append(&store, b"still live when a later tombstone conflicts")?;
        let last = append(&store, b"second retirement")?;
        store.publish_roots_batch(&[root("a-first", first, None)?, root("z-last", last, None)?])?;
        let mut batch = eviction(&[candidate("a-first", &[first]), candidate("z-last", &[last])])?;
        let different_reason = ContentDigest::sha256(b"a different deletion decision");
        if duplicate {
            let mut repeated = batch.tombstones[0].clone();
            repeated.reason_digest = different_reason;
            batch.tombstones.push(repeated);
        } else {
            store.tombstone_root("z-last", different_reason)?;
        }
        assert_refused_without_mutation(
            &store,
            &batch,
            &["a-first", "z-last"],
            &[first, last],
            |error| {
                matches!(
                    error,
                    PackError::RetentionPolicyViolation { .. }
                        | PackError::TombstoneConflict { .. }
                )
            },
        )?;
    }
    Ok(())
}

#[test]
fn retiring_all_direct_references_allows_deletion_and_exact_replay() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let shared = append(&store, b"shared bytes retired together")?;
    let descriptor = append(&store, b"descriptor retired together")?;
    store.publish_roots_batch(&[
        root("first", shared, None)?,
        root("second", descriptor, Some(shared))?,
    ])?;
    let batch = eviction(&[
        candidate("first", &[shared]),
        candidate("second", &[descriptor, shared]),
    ])?;
    let proof = store.commit_eviction_tombstones(&batch, Some(1))?;
    proof.verify()?;
    for digest in [shared, descriptor] {
        assert!(proof.covers_digest(&digest));
        assert!(store.object_tombstone(&digest)?.is_some());
        assert!(store.lookup(&digest)?.is_none());
        assert!(matches!(
            store.read_verified(&digest),
            Err(PackError::EvidenceDeleted { .. })
        ));
    }
    for id in ["first", "second"] {
        assert!(matches!(
            store
                .get_root(id)?
                .ok_or("retired root disappeared")?
                .status,
            RootStatus::Tombstoned { .. }
        ));
    }
    let fsyncs = store.telemetry_snapshot()?.catalog_fsync_count;
    assert_eq!(store.commit_eviction_tombstones(&batch, Some(1))?, proof);
    assert_eq!(store.telemetry_snapshot()?.catalog_fsync_count, fsyncs);
    Ok(())
}

#[test]
fn unreferenced_object_only_retention_records_remain_supported() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let digest = append(&store, b"object with no catalog publication")?;
    let batch = eviction(&[candidate("object-only", &[digest])])?;
    let proof = store.commit_eviction_tombstones(&batch, Some(1))?;
    proof.verify()?;
    assert!(proof.covers_digest(&digest));
    assert!(store.get_root("object-only")?.is_none());
    assert!(store.object_tombstone(&digest)?.is_some());
    assert!(store.lookup(&digest)?.is_none());
    Ok(())
}
