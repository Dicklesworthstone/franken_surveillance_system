#![forbid(unsafe_code)]
//! Receipt recovery proves canonical history and publication through its current head.

use super::*;
use fss_ledger::{ReceiptProofBudget, ReceiptProofUsage};
use fss_projection_store::PackStorePayloadResolver;

#[test]
fn serialized_head_recovery_requires_exact_materialized_publication() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let batch = prepare(&sink, "projection-recovery")?;
    let (mut ledger, packs, projection) = sink.into_parts();
    let expected = ledger.append_batch(batch.clone())?;
    let combiner = CommitCombiner::new(
        LedgerPackProjectionSink::new(ledger, packs, Arc::clone(&projection)),
        CommitCombinerConfig::default(),
    )?;
    assert!(matches!(
        combiner.receipt_for_exact_head(&batch),
        Err(CombinerError::Projection(_))
    ));
    assert_eq!(projection.head_anchor().commit_sequence, 0);
    assert_eq!(combiner.stats()?.proposals_committed, 0);
    let sink = combiner.into_sink()?;
    {
        let resolver = PackStorePayloadResolver::new(sink.pack_store());
        let _ = sink.projection().apply_delta_batch(&batch, &resolver)?;
    }
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    assert_eq!(combiner.receipt_for_exact_head(&batch)?, Some(expected));
    assert_eq!(combiner.stats()?.proposals_committed, 0);
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().commit_sequence(), 1);
    Ok(())
}

#[test]
fn historical_receipt_proof_is_bounded_and_does_not_append() -> TestResult {
    let dir = TempDir::new()?;
    let mut sink = open_sink(&dir)?;
    let first = prepare(&sink, "historical-receipt")?;
    let expected = sink.commit_exact_batch(first.clone())?;
    let second = prepare(&sink, "after-historical-receipt")?;
    let latest = sink.commit_exact_batch(second.clone())?;
    let head = sink.ledger().head_anchor().clone();
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;

    let proof = combiner
        .receipt_for_exact_batch(&first, ReceiptProofBudget::default())?
        .ok_or("missing historical receipt proof")?;
    assert_eq!(proof.receipt.sequence, expected.commit_sequence);
    assert_eq!(proof.receipt.batch_id, first.batch_id);
    assert_eq!(proof.receipt.batch_digest, first.batch_digest);
    assert_eq!(proof.receipt.anchor, first.new_anchor);
    assert_eq!(proof.receipt.history_root, expected.history_root);
    assert_eq!(proof.head_anchor, head);
    assert_eq!(proof.head_history_root, latest.history_root);
    assert_eq!(proof.head_batch_digest, second.batch_digest);
    assert!(proof.usage.epochs_scanned > 0);
    assert!(proof.usage.records_verified >= 2);
    assert!(proof.usage.bytes_read > 0);

    assert!(
        combiner
            .receipt_for_exact_batch(
                &first,
                ReceiptProofBudget {
                    max_records: 1,
                    ..ReceiptProofBudget::default()
                },
            )
            .is_err()
    );
    let current = combiner
        .receipt_for_exact_batch(
            &second,
            ReceiptProofBudget {
                max_epochs: 0,
                max_records: 0,
                max_bytes: 0,
            },
        )?
        .ok_or("missing current-head receipt")?;
    assert_eq!(current.receipt.sequence, latest.commit_sequence);
    assert_eq!(current.usage, ReceiptProofUsage::default());
    assert_eq!(combiner.stats()?.proposals_committed, 0);
    assert_eq!(combiner.pending_len()?, 0);
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().head_anchor(), &head);
    assert_eq!(sink.ledger().read_batches_range(1, 2)?, vec![first, second]);
    Ok(())
}

#[test]
fn historical_recovery_waits_for_publication_of_the_current_head() -> TestResult {
    let dir = TempDir::new()?;
    let mut sink = open_sink(&dir)?;
    let first = prepare(&sink, "published-historical")?;
    let expected = sink.commit_exact_batch(first.clone())?;
    let second = prepare(&sink, "unpublished-successor")?;
    let (mut ledger, packs, projection) = sink.into_parts();
    let latest = ledger.append_batch(second.clone())?;
    let combiner = CommitCombiner::new(
        LedgerPackProjectionSink::new(ledger, packs, Arc::clone(&projection)),
        CommitCombinerConfig::default(),
    )?;
    assert!(matches!(
        combiner.receipt_for_exact_batch(&first, ReceiptProofBudget::default()),
        Err(CombinerError::Projection(_))
    ));
    // Publishing the target alone cannot establish complete publication of the
    // authenticated suffix. The derived view must catch up to the verified head.
    assert_eq!(
        projection.head_anchor().commit_sequence,
        expected.commit_sequence
    );
    assert_eq!(combiner.stats()?.proposals_committed, 0);
    let sink = combiner.into_sink()?;
    {
        let resolver = PackStorePayloadResolver::new(sink.pack_store());
        let _ = sink.projection().apply_delta_batch(&second, &resolver)?;
    }
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let proof = combiner
        .receipt_for_exact_batch(&first, ReceiptProofBudget::default())?
        .ok_or("historical publication should be provable after replay")?;
    assert_eq!(proof.receipt.sequence, expected.commit_sequence);
    assert_eq!(proof.receipt.history_root, expected.history_root);
    assert_eq!(proof.head_anchor, latest.anchor);
    assert_eq!(proof.head_history_root, latest.history_root);
    assert_eq!(combiner.stats()?.proposals_committed, 0);
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().commit_sequence(), latest.sequence);
    Ok(())
}
