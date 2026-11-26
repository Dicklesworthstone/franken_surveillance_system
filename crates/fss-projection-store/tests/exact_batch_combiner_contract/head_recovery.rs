#![forbid(unsafe_code)]
//! A missing completion requires exact materialized publication at the canonical head.

use super::*;
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
