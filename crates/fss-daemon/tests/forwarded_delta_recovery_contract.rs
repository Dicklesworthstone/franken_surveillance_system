#![forbid(unsafe_code)]
//! Production storage retry contracts with synthetic canonical metadata. No camera,
//! decoder, hardware, or full release qualification is implied by these fixtures.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_daemon::{SiteManifest, StorageEngine};
use fss_ledger::{
    EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger, decode_batch, encode_batch,
};
use fss_pack::{PACK_KIND_METADATA, PackObjectInput};
use fss_projection_store::CanonicalBatchSource;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-forwarded-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest() -> Result<SiteManifest, Box<dyn std::error::Error>> {
    Ok(SiteManifest::parse_json(
        r#"{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-forward-recovery",
  "ring_cap_bytes": 1048576,
  "retain_hot_ns": 1000000000,
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [{
    "sensor_id": "sensor:forward",
    "adapter": "synthetic",
    "endpoint": "synthetic://forward",
    "secret_id": "secret:test:forward",
    "priority_tier": "standard",
    "zone_id": "test",
    "dimensions": [32, 32],
    "failure_domains": ["power:test"],
    "gop_frames": 1
  }]
}"#,
    )?)
}

fn batch(storage: &StorageEngine) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    prepared_batch(storage, "recovery")
}

fn prepared_batch(
    storage: &StorageEngine,
    label: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let payload = b"synthetic canonical forwarding metadata";
    storage
        .pack_store()
        .append_batch(&[PackObjectInput::new(PACK_KIND_METADATA, 0, payload)])?;
    // The live daemon owns v2 Merkle authority. A v1 flat-state oracle batch is
    // intentionally incompatible with exact canonical forwarding.
    let preparation = TempDir::new()?;
    let oracle = MerkleEpochLedger::open(
        preparation.0.join("ledger"),
        "site-forward-recovery",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let batch = oracle.prepare_batch(
        BatchId::parse(format!("batch:forward:{label}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:forward:{label}"),
            family: "synthetic_forward_metadata".to_owned(),
            object_id: ObjectId::parse(format!("obj:forward:{label}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(payload),
            witness_digest: None,
            operation_id: None,
        }],
        [ContentDigest::sha256(payload)],
    )?;
    Ok(encode_batch(&batch)?)
}

#[test]
fn forwarding_receipt_survives_new_writer_handles_and_storage_restart() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let key = ContentDigest::sha256(b"retry-key");
    let request = ContentDigest::sha256(&bytes);
    let first_writer = storage.forward_writer();
    assert!(first_writer.supports_durable_idempotency());
    let original = first_writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(!original.replayed);
    assert_eq!(original.commit_sequence, 1);

    let second_writer = storage.forward_writer();
    let replay = second_writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(replay.replayed);
    assert_eq!(replay.commit_sequence, original.commit_sequence);
    assert_eq!(replay.history_root, original.history_root);
    assert_eq!(replay.state_root, original.state_root);
    assert_eq!(storage.head_snapshot()?.commit_sequence, 1);
    drop(first_writer);
    drop(second_writer);
    storage.shutdown_and_flush()?;

    let reopened = StorageEngine::open(&manifest, Some(&dir.0))?;
    let writer = reopened.forward_writer();
    assert_eq!(
        writer.forward_delta_batch_idempotent(key, request, &bytes)?,
        replay
    );
    let conflict = writer
        .forward_delta_batch_idempotent(key, ContentDigest::sha256(b"other context"), &bytes)
        .expect_err("changed request identity cannot replay");
    assert_eq!(conflict.error_id(), "ERR-IDEMPOTENCY-CONFLICT-001");
    let mut changed = decode_batch(&bytes)?;
    changed.batch_id = BatchId::parse("batch:forward:changed")?;
    changed.batch_digest = changed.computed_digest();
    let changed_bytes = encode_batch(&changed)?;
    let conflict = writer
        .forward_delta_batch_idempotent(key, request, &changed_bytes)
        .expect_err("direct callers cannot reuse a digest with different valid batch bytes");
    assert_eq!(conflict.error_id(), "ERR-IDEMPOTENCY-CONFLICT-001");
    assert_eq!(reopened.head_snapshot()?.commit_sequence, 1);
    drop(writer);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn exact_current_head_recovers_a_missing_completion_without_another_append() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let key = ContentDigest::sha256(b"interrupted-receipt-key");
    let request = ContentDigest::sha256(&bytes);
    let writer = storage.forward_writer();
    let original = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    drop(writer);
    storage.shutdown_and_flush()?;

    // Reproduce the persisted cut after ledger commit but before completion publication.
    // This is a deterministic disk-state fixture, not a claim of a killed-process test.
    let completion = dir
        .0
        .join("forwarded-requests")
        .join(format!("{:02x}", key.bytes()[0]))
        .join(format!("{}.committed", key.to_text().replace(':', "_")));
    fs::remove_file(&completion)?;
    fs::remove_dir_all(dir.0.join("projections/mvcc"))?;

    let reopened = StorageEngine::open(&manifest, Some(&dir.0))?;
    let writer = reopened.forward_writer();
    let recovered = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(recovered.replayed);
    assert_eq!(recovered.commit_sequence, original.commit_sequence);
    assert_eq!(recovered.history_root, original.history_root);
    assert_eq!(recovered.state_root, original.state_root);
    let completion_bytes = fs::read(&completion)?;
    assert_eq!(
        writer.forward_delta_batch_idempotent(key, request, &bytes)?,
        recovered
    );
    assert_eq!(fs::read(&completion)?, completion_bytes);
    let head = reopened.head_snapshot()?;
    assert_eq!(head.commit_sequence, original.commit_sequence);
    assert_eq!(head.history_root, original.history_root);
    assert_eq!(head.state_root, original.state_root);
    drop(writer);
    reopened.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn malformed_wire_bytes_do_not_reserve_a_fresh_key() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let key = ContentDigest::sha256(b"invalid-wire");
    let request = ContentDigest::sha256(&bytes);
    let writer = storage.forward_writer();
    assert!(
        writer
            .forward_delta_batch_idempotent(key, request, b"truncated")
            .is_err()
    );
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
    let receipt = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(!receipt.replayed);
    assert_eq!(receipt.commit_sequence, 1);
    drop(writer);
    storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn completion_from_a_later_ledger_cannot_replay_against_an_older_head() -> TestResult {
    let source = TempDir::new()?;
    let target = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&source.0))?;
    let bytes = batch(&storage)?;
    let key = ContentDigest::sha256(b"copied-future-receipt");
    let request = ContentDigest::sha256(&bytes);
    let writer = storage.forward_writer();
    assert_eq!(
        writer
            .forward_delta_batch_idempotent(key, request, &bytes)?
            .commit_sequence,
        1
    );
    drop(writer);
    storage.shutdown_and_flush()?;

    let target_storage = StorageEngine::open(&manifest, Some(&target.0))?;
    let shard = format!("{:02x}", key.bytes()[0]);
    let source_dir = source.0.join("forwarded-requests").join(&shard);
    let target_dir = target.0.join("forwarded-requests").join(&shard);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&target_dir)?;
    let stem = key.to_text().replace(':', "_");
    for suffix in ["reserved", "committed"] {
        let name = format!("{stem}.{suffix}");
        fs::copy(source_dir.join(&name), target_dir.join(&name))?;
    }
    let writer = target_storage.forward_writer();
    let error = writer
        .forward_delta_batch_idempotent(key, request, &bytes)
        .expect_err("a completion beyond this ledger head is not a verified replay");
    assert_eq!(error.error_id(), "ERR-OP-RECONCILIATION-REQUIRED-001");
    assert_eq!(target_storage.head_snapshot()?.commit_sequence, 0);
    drop(writer);
    target_storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn forwarding_preserves_the_exact_batch_and_rejects_stale_independent_writes() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let stale = prepared_batch(&storage, "independent")?;
    let expected = decode_batch(&bytes)?;
    let writer = storage.forward_writer();
    let receipt = writer.forward_delta_batch(&bytes)?;
    assert_eq!(receipt.0, expected.new_anchor.commit_sequence);
    assert_eq!(receipt.2, expected.new_anchor.state_root);
    assert!(
        writer.forward_delta_batch(&stale).is_err(),
        "a valid but stale batch cannot be rebased merely because its object is new"
    );
    assert_eq!(storage.head_snapshot()?.commit_sequence, 1);
    drop(writer);
    storage.shutdown_and_flush()?;

    let ledger = MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site-forward-recovery",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(ledger.read_batches_range(1, 1)?, vec![expected]);
    assert!(
        ledger
            .get_object(&ObjectId::parse("obj:forward:independent")?)
            .is_none()
    );
    Ok(())
}

#[test]
fn forwarding_refuses_an_unretained_declared_child_before_advancing_authority() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let mut offered = decode_batch(&batch(&storage)?)?;
    let child = b"independent forwarded closure member";
    offered.children.push(ContentDigest::sha256(child));
    offered.children.sort_unstable();
    offered.batch_digest = offered.computed_digest();
    let bytes = encode_batch(&offered)?;
    let writer = storage.forward_writer();
    assert!(writer.forward_delta_batch(&bytes).is_err());
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
    storage
        .pack_store()
        .append_batch(&[PackObjectInput::new(PACK_KIND_METADATA, 0, child)])?;
    assert_eq!(writer.forward_delta_batch(&bytes)?.0, 1);
    drop(writer);
    storage.shutdown_and_flush()?;
    Ok(())
}

fn request_record_path(root: &std::path::Path, key: ContentDigest, suffix: &str) -> PathBuf {
    root.join("forwarded-requests")
        .join(format!("{:02x}", key.bytes()[0]))
        .join(format!("{}.{suffix}", key.to_text().replace(':', "_")))
}

#[test]
fn historical_pending_recovers_the_original_receipt_after_advance_and_restart() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let first = decode_batch(&bytes)?;
    let key = ContentDigest::sha256(b"historical-pending");
    let request = ContentDigest::sha256(&bytes);
    let writer = storage.forward_writer();
    let original = writer.forward_delta_batch_idempotent(key, request, &bytes)?;

    let preparation = TempDir::new()?;
    let mut oracle = MerkleEpochLedger::open(
        preparation.0.join("ledger"),
        "site-forward-recovery",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    oracle.append_batch(first.clone())?;
    let mut delta = first.deltas[0].clone();
    delta.object_id = ObjectId::parse("obj:forward:after-pending")?;
    delta.delta_id = "delta:forward:after-pending".to_owned();
    let next = oracle.prepare_batch(
        BatchId::parse("batch:forward:after-pending")?,
        vec![delta],
        first.children.clone(),
    )?;
    let _ = writer.forward_delta_batch(&encode_batch(&next)?)?;
    let before = storage.head_snapshot()?;
    assert_eq!(before.commit_sequence, 2);
    drop(writer);
    storage.shutdown_and_flush()?;
    // Reproduce an interrupted completion followed by another canonical commit.
    // The projection is rebuilt so the recovery proof must survive a fresh storage open.
    let completion = request_record_path(&dir.0, key, "committed");
    fs::remove_file(&completion)?;
    fs::remove_dir_all(dir.0.join("projections/mvcc"))?;
    let pending = request_record_path(&dir.0, key, "reserved");
    let pending_bytes = fs::read(&pending)?;

    let reopened = StorageEngine::open(&manifest, Some(&dir.0))?;
    let writer = reopened.forward_writer();
    let recovered = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(recovered.replayed);
    assert_eq!(recovered.commit_sequence, original.commit_sequence);
    assert_eq!(recovered.history_root, original.history_root);
    assert_eq!(recovered.state_root, original.state_root);
    let completion_bytes = fs::read(&completion)?;
    assert_eq!(
        writer.forward_delta_batch_idempotent(key, request, &bytes)?,
        recovered
    );
    assert_eq!(fs::read(&completion)?, completion_bytes);
    assert_eq!(fs::read(&pending)?, pending_bytes);
    let after = reopened.head_snapshot()?;
    assert_eq!(after.commit_sequence, before.commit_sequence);
    assert_eq!(after.history_root, before.history_root);
    assert_eq!(after.state_root, before.state_root);
    drop(writer);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 2);

    let reopened = StorageEngine::open(&manifest, Some(&dir.0))?;
    let writer = reopened.forward_writer();
    assert_eq!(
        writer.forward_delta_batch_idempotent(key, request, &bytes)?,
        recovered
    );
    assert_eq!(reopened.head_snapshot()?.commit_sequence, 2);
    drop(writer);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 2);
    Ok(())
}

#[test]
fn copied_pending_reservation_cannot_authorize_a_fresh_dispatch() -> TestResult {
    let source = TempDir::new()?;
    let target = TempDir::new()?;
    let manifest = manifest()?;
    let source_storage = StorageEngine::open(&manifest, Some(&source.0))?;
    let bytes = batch(&source_storage)?;
    let key = ContentDigest::sha256(b"pending-without-commit");
    let request = ContentDigest::sha256(&bytes);
    let writer = source_storage.forward_writer();
    let _ = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    drop(writer);
    source_storage.shutdown_and_flush()?;

    let storage = StorageEngine::open(&manifest, Some(&target.0))?;
    // Retain the same source bytes, so failure cannot be mistaken for missing payload custody.
    assert_eq!(batch(&storage)?, bytes);
    let source_pending = request_record_path(&source.0, key, "reserved");
    let target_pending = request_record_path(&target.0, key, "reserved");
    let parent = target_pending.parent().ok_or("missing retry shard")?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    fs::copy(source_pending, &target_pending)?;
    let before = fs::read(&target_pending)?;
    let writer = storage.forward_writer();
    let error = writer
        .forward_delta_batch_idempotent(key, request, &bytes)
        .expect_err("a pending claim is never permission to dispatch");
    assert_eq!(error.error_id(), "ERR-OP-RECONCILIATION-REQUIRED-001");
    assert_eq!(storage.head_snapshot()?.commit_sequence, 0);
    assert_eq!(fs::read(target_pending)?, before);
    assert!(!request_record_path(&target.0, key, "committed").exists());
    drop(writer);
    storage.shutdown_and_flush()?;
    Ok(())
}

#[test]
fn exact_head_recovery_does_not_replace_a_corrupt_completion_or_change_its_request() -> TestResult {
    let dir = TempDir::new()?;
    let manifest = manifest()?;
    let storage = StorageEngine::open(&manifest, Some(&dir.0))?;
    let bytes = batch(&storage)?;
    let key = ContentDigest::sha256(b"corrupt-head-completion");
    let request = ContentDigest::sha256(&bytes);
    let writer = storage.forward_writer();
    let original = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    drop(writer);
    storage.shutdown_and_flush()?;
    let completion = request_record_path(&dir.0, key, "committed");
    let mut corrupt = fs::read(&completion)?;
    corrupt[20] ^= 0x80;
    fs::write(&completion, &corrupt)?;

    let reopened = StorageEngine::open(&manifest, Some(&dir.0))?;
    let writer = reopened.forward_writer();
    let error = writer
        .forward_delta_batch_idempotent(key, request, &bytes)
        .expect_err("an exact head cannot replace corrupt retry custody");
    assert_eq!(error.error_id(), "ERR-OP-RECONCILIATION-REQUIRED-001");
    assert_eq!(fs::read(&completion)?, corrupt);
    fs::remove_file(&completion)?;
    let error = writer
        .forward_delta_batch_idempotent(key, ContentDigest::sha256(b"changed principal"), &bytes)
        .expect_err("recovery needs the exact original request identity");
    assert_eq!(error.error_id(), "ERR-IDEMPOTENCY-CONFLICT-001");
    assert!(!completion.exists());
    let recovered = writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    assert!(recovered.replayed);
    assert_eq!(recovered.history_root, original.history_root);
    assert_eq!(
        reopened.head_snapshot()?.commit_sequence,
        original.commit_sequence
    );
    drop(writer);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 1);
    Ok(())
}

#[test]
fn historical_completion_refuses_another_fork_with_the_same_batch() -> TestResult {
    let source = TempDir::new()?;
    let target = TempDir::new()?;
    let manifest = manifest()?;
    let source_storage = StorageEngine::open(&manifest, Some(&source.0))?;
    let target_storage = StorageEngine::open(&manifest, Some(&target.0))?;
    let first_bytes = batch(&source_storage)?;
    assert_eq!(batch(&target_storage)?, first_bytes);
    let first = decode_batch(&first_bytes)?;
    let mut forked_first = first.clone();
    forked_first.batch_id = BatchId::parse("batch:forward:forked-first")?;
    forked_first.batch_digest = forked_first.computed_digest();
    assert_eq!(forked_first.new_anchor, first.new_anchor);

    let source_writer = source_storage.forward_writer();
    let target_writer = target_storage.forward_writer();
    let source_first = source_writer.forward_delta_batch(&first_bytes)?;
    let target_first = target_writer.forward_delta_batch(&encode_batch(&forked_first)?)?;
    assert_eq!(source_first.2, target_first.2);
    assert_ne!(source_first.1, target_first.1);

    let preparation = TempDir::new()?;
    let mut oracle = MerkleEpochLedger::open(
        preparation.0.join("ledger"),
        "site-forward-recovery",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    oracle.append_batch(first.clone())?;
    let mut delta = first.deltas[0].clone();
    delta.object_id = ObjectId::parse("obj:forward:shared-fork-batch")?;
    delta.delta_id = "delta:forward:shared-fork-batch".to_owned();
    let shared = oracle.prepare_batch(
        BatchId::parse("batch:forward:shared-fork-batch")?,
        vec![delta],
        first.children.clone(),
    )?;
    let bytes = encode_batch(&shared)?;
    let key = ContentDigest::sha256(b"copied-historical-fork-completion");
    let request = ContentDigest::sha256(&bytes);
    let source_receipt = source_writer.forward_delta_batch_idempotent(key, request, &bytes)?;
    let target_receipt = target_writer.forward_delta_batch(&bytes)?;
    // Both histories contain exactly the same batch and authority state. Only their
    // ancestry (and therefore the receipt's history root) distinguishes the outcome.
    assert_eq!(source_receipt.commit_sequence, target_receipt.0);
    assert_eq!(source_receipt.state_root, target_receipt.2);
    assert_ne!(source_receipt.history_root, target_receipt.1);

    oracle.append_batch(shared.clone())?;
    let mut delta = shared.deltas[0].clone();
    delta.object_id = ObjectId::parse("obj:forward:after-fork")?;
    delta.delta_id = "delta:forward:after-fork".to_owned();
    let next = oracle.prepare_batch(
        BatchId::parse("batch:forward:after-fork")?,
        vec![delta],
        shared.children.clone(),
    )?;
    let _ = target_writer.forward_delta_batch(&encode_batch(&next)?)?;
    let before = target_storage.head_snapshot()?;
    assert_eq!(before.commit_sequence, 3);
    assert_eq!(source_receipt.commit_sequence, 2);
    drop(source_writer);
    drop(target_writer);
    source_storage.shutdown_and_flush()?;
    target_storage.shutdown_and_flush()?;

    // Model a mixed restoration: valid retry custody copied from a different
    // history while the target canonical ledger retains its own verified fork.
    let target_pending = request_record_path(&target.0, key, "reserved");
    let parent = target_pending.parent().ok_or("missing retry shard")?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    for suffix in ["reserved", "committed"] {
        fs::copy(
            request_record_path(&source.0, key, suffix),
            request_record_path(&target.0, key, suffix),
        )?;
    }
    let completion = request_record_path(&target.0, key, "committed");
    let pending_bytes = fs::read(&target_pending)?;
    let completion_bytes = fs::read(&completion)?;
    fs::remove_dir_all(target.0.join("projections/mvcc"))?;

    let reopened = StorageEngine::open(&manifest, Some(&target.0))?;
    let writer = reopened.forward_writer();
    let error = writer
        .forward_delta_batch_idempotent(key, request, &bytes)
        .expect_err("matching batch identity and state do not establish the receipt's lineage");
    assert_eq!(error.error_id(), "ERR-OP-RECONCILIATION-REQUIRED-001");
    assert_eq!(fs::read(&target_pending)?, pending_bytes);
    assert_eq!(fs::read(&completion)?, completion_bytes);
    let after = reopened.head_snapshot()?;
    assert_eq!(after.commit_sequence, before.commit_sequence);
    assert_eq!(after.history_root, before.history_root);
    assert_eq!(after.state_root, before.state_root);
    drop(writer);
    assert_eq!(reopened.shutdown_and_flush()?.verified_batches, 3);
    Ok(())
}
