//! Staged durable appends preserve the visible prefix at every journal cut point.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    ObjectId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger,
    IncompleteTailPolicy, JournalError,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:staged-append-reconciliation";

fn path_for(phase: AppendPhase) -> Result<PathBuf, Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("staged-append-reconciliation");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{phase:?}-{}.journal", std::process::id()));
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn next_batch(
    ledger: &DurableReferenceLedger,
    index: usize,
) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    Ok(ledger.prepare_batch(
        BatchId::parse(format!("batch:{index}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:{index}"),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(format!("object:{index}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(format!("payload:{index}").as_bytes()),
            witness_digest: None,
            operation_id: None,
        }],
        [],
    )?)
}

fn exercise_cut(phase: AppendPhase) -> TestResult {
    let path = path_for(phase)?;
    let mut ledger = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    assert_eq!(ledger.retained_snapshot_count(), 1);
    for index in 0..32 {
        let batch = next_batch(&ledger, index)?;
        ledger.append(batch)?;
        assert_eq!(ledger.retained_snapshot_count(), 1);
    }
    let before = ledger.current().clone();
    let history = ledger.batches().to_vec();
    let root_before = ledger.journal_root();
    let bytes_before = fs::read(&path)?;
    let batch = next_batch(&ledger, 32)?;
    ledger.fail_journal_after_phase(phase);
    match ledger.append(batch.clone()) {
        Err(DurableLedgerError::Journal(JournalError::AppendIndeterminate {
            sequence: 33,
            phase: observed,
            ..
        })) => assert_eq!(observed, phase),
        other => return Err(format!("expected indeterminate {phase:?}, got {other:?}").into()),
    }
    assert_eq!(ledger.current(), &before);
    assert_eq!(ledger.retained_snapshot_count(), 1);
    assert_eq!(ledger.batches(), history.as_slice());
    assert_eq!(ledger.journal_root(), root_before);
    assert_eq!(ledger.pending_append_sequence(), Some(33));
    assert!(matches!(
        ledger.append(batch.clone()),
        Err(DurableLedgerError::Journal(JournalError::ReconciliationRequired {
            sequence: 33
        }))
    ));
    assert!(matches!(
        ledger.verify_storage(),
        Err(DurableLedgerError::Journal(JournalError::ReconciliationRequired {
            sequence: 33
        }))
    ));

    let after_write = fs::read(&path)?;
    let incomplete = matches!(phase, AppendPhase::BodyWrite | AppendPhase::BodySync);
    if incomplete {
        // A refusal cannot consume the detached stage or expose any of its state.
        for _ in 0..2 {
            assert!(matches!(
                ledger.reconcile_pending(IncompleteTailPolicy::Reject),
                Err(DurableLedgerError::Journal(JournalError::IncompleteTail { .. }))
            ));
            assert_eq!(ledger.pending_append_sequence(), Some(33));
            assert_eq!(ledger.current(), &before);
            assert_eq!(ledger.retained_snapshot_count(), 1);
            assert_eq!(ledger.batches(), history.as_slice());
            assert_eq!(fs::read(&path)?, after_write);
        }
        assert_eq!(
            ledger.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            DurableAppendReconciliation::NotCommitted { sequence: 33 }
        );
        assert_eq!(ledger.current(), &before);
        assert_eq!(ledger.retained_snapshot_count(), 1);
        assert_eq!(ledger.batches(), history.as_slice());
        assert_eq!(fs::read(&path)?, bytes_before);
        ledger.append(batch.clone())?;
    } else {
        assert_eq!(
            ledger.reconcile_pending(IncompleteTailPolicy::Reject)?,
            DurableAppendReconciliation::Committed {
                sequence: 33,
                batch_id: batch.batch_id.clone(),
            }
        );
        assert_eq!(fs::read(&path)?, after_write);
    }

    assert_eq!(ledger.pending_append_sequence(), None);
    assert_eq!(ledger.retained_snapshot_count(), 1);
    assert_eq!(ledger.current().anchor, batch.new_anchor);
    assert_eq!(ledger.batches().len(), 33);
    let committed_snapshot = ledger.current().clone();
    let committed_history = ledger.batches().to_vec();
    let committed_bytes = fs::read(&path)?;
    assert!(matches!(
        ledger.append(batch),
        Err(DurableLedgerError::Contract(ContractError::StaleAnchor))
    ));
    assert_eq!(fs::read(&path)?, committed_bytes);
    assert_eq!(ledger.current(), &committed_snapshot);
    assert_eq!(ledger.verify_storage()?, ledger.journal_root());

    let oracle = ReferenceLedger::replay(SITE, committed_history.iter().cloned())?;
    assert_eq!(oracle.current(), &committed_snapshot);
    drop(ledger);
    let mut reopened = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.current(), &committed_snapshot);
    assert_eq!(reopened.retained_snapshot_count(), 1);
    assert_eq!(reopened.batches(), committed_history.as_slice());
    assert_eq!(reopened.verify_storage()?, reopened.journal_root());
    assert_eq!(reopened.retained_snapshot_count(), 1);
    drop(reopened);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn body_write_failure_keeps_only_the_canonical_prefix_visible() -> TestResult {
    exercise_cut(AppendPhase::BodyWrite)
}

#[test]
fn body_sync_failure_keeps_only_the_canonical_prefix_visible() -> TestResult {
    exercise_cut(AppendPhase::BodySync)
}

#[test]
fn commit_write_failure_publishes_only_after_exact_reconciliation() -> TestResult {
    exercise_cut(AppendPhase::CommitWrite)
}

#[test]
fn lost_commit_ack_publishes_only_after_exact_reconciliation() -> TestResult {
    exercise_cut(AppendPhase::CommitSync)
}
