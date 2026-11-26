#![forbid(unsafe_code)]
//! Receipt recovery must refuse a poisoned materialized publication, including older receipts.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger, ReceiptProofBudget};
use fss_pack::{PACK_KIND_METADATA, PackConfig, PackObjectInput, PackStore};

use crate::{
    CombinerError, CommitCombiner, CommitCombinerConfig, CommitSink, LedgerPackProjectionSink,
    MvccProjectionStore, ProjectionError, ProjectionStore, ProjectionStoreConfig,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-poisoned-receipt-publication-{}-{}",
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

fn prepare(
    sink: &LedgerPackProjectionSink,
    label: &str,
) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
    let payload = b"receipt publication fixture";
    sink.pack_store()
        .append_batch(&[PackObjectInput::new(PACK_KIND_METADATA, 0, payload)])?;
    let digest = ContentDigest::sha256(payload);
    Ok(sink.ledger().prepare_batch(
        BatchId::parse(format!("batch:poisoned-receipt:{label}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:poisoned-receipt:{label}"),
            family: "synthetic_receipt_metadata".to_owned(),
            object_id: ObjectId::parse(format!("object:poisoned-receipt:{label}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        [digest],
    )?)
}

#[test]
fn poisoned_publication_refuses_current_and_historical_receipt_recovery() -> TestResult {
    let dir = TempDir::new()?;
    let ledger = MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:poisoned-receipts",
        EpochLedgerConfig {
            checkpoint_stride: 0,
            ..EpochLedgerConfig::default()
        },
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(dir.0.join("packs"), PackConfig::default())?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.0.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig {
            max_retained_snapshots: 1,
            snapshot_stride: 0,
            ..ProjectionStoreConfig::default()
        },
    )?);
    let mut sink = LedgerPackProjectionSink::new(ledger, packs, Arc::clone(&projection));
    let first = prepare(&sink, "first")?;
    let first_outcome = sink.commit_exact_batch(first.clone())?;
    let second = prepare(&sink, "second")?;
    let second_outcome = sink.commit_exact_batch(second.clone())?;
    let canonical_head = sink.ledger().head_anchor().clone();
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let stats = combiner.stats()?;
    assert!(matches!(
        projection.snapshot_at(1),
        Err(ProjectionError::SnapshotEvicted { .. })
    ));
    let proof = combiner
        .receipt_for_exact_batch(&first, ReceiptProofBudget::default())?
        .ok_or("historical receipt should be provable without an old MVCC snapshot")?;
    assert_eq!(proof.receipt.sequence, first_outcome.commit_sequence);
    assert_eq!(proof.head_anchor, canonical_head);
    let head = combiner
        .receipt_for_exact_head(&second)?
        .ok_or("current receipt should be published before the poison fault")?;
    assert_eq!(head.sequence, second_outcome.commit_sequence);

    let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), ProjectionError> {
            let _guard = projection
                .read_state
                .write()
                .map_err(|_| ProjectionError::LockPoisoned)?;
            // Resume an intentional unwind while holding the guard to simulate publication panic.
            std::panic::resume_unwind(Box::new("receipt publication fault"));
        },
    ));
    assert!(fault.is_err());
    assert!(projection.read_state.is_poisoned());
    // The diagnostic accessor still preserves its established best-effort behavior.
    assert_eq!(projection.head_anchor().commit_sequence, 2);
    for batch in [&first, &second] {
        assert!(matches!(
            combiner.receipt_for_exact_batch(batch, ReceiptProofBudget::default()),
            Err(CombinerError::Projection(ProjectionError::LockPoisoned))
        ));
    }
    assert!(matches!(
        combiner.receipt_for_exact_head(&second),
        Err(CombinerError::Projection(ProjectionError::LockPoisoned))
    ));
    assert!(combiner.receipt_for_exact_head(&first)?.is_none());
    assert_eq!(combiner.stats()?, stats);
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().head_anchor(), &canonical_head);
    Ok(())
}
