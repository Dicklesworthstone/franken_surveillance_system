use std::error::Error;
use std::fs;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, ReferenceLedger,
    TimestampNs,
};

use crate::{
    AppendPhase, DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger,
    IncompleteTailPolicy, JournalError,
};

fn sample_batch() -> Result<fss_core::EvidenceDeltaBatch, Box<dyn Error>> {
    let ledger = ReferenceLedger::new("test-site");
    let delta = EvidenceDelta {
        delta_id: "delta:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:camera:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(b"payload"),
        witness_digest: Some(ContentDigest::sha256(b"witness")),
        operation_id: None,
    };
    Ok(ledger.prepare_batch(
        BatchId::parse("batch:1")?,
        vec![delta],
        [ContentDigest::sha256(b"child")],
    )?)
}

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fss-ledger-{}-{name}.journal", std::process::id()))
}

#[test]
fn lost_ack_installs_prevalidated_candidate_once() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("durable-lost-ack");
    let _ = fs::remove_file(&path);
    let mut durable =
        DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
    let batch = sample_batch()?;
    let expected_batch_id = batch.batch_id.clone();
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        durable.append(batch),
        Err(DurableLedgerError::Journal(
            JournalError::AppendIndeterminate {
                sequence: 1,
                phase: AppendPhase::CommitSync,
                ..
            }
        ))
    ));
    assert_eq!(durable.batches().len(), 0);
    assert_eq!(durable.pending_append_sequence(), Some(1));
    assert_eq!(
        durable.reconcile_pending(IncompleteTailPolicy::Reject)?,
        DurableAppendReconciliation::Committed {
            sequence: 1,
            batch_id: expected_batch_id,
        }
    );
    assert_eq!(durable.batches().len(), 1);
    assert_eq!(durable.pending_append_sequence(), None);
    assert!(matches!(
        durable.reconcile_pending(IncompleteTailPolicy::Reject),
        Err(DurableLedgerError::Journal(JournalError::NoPendingAppend))
    ));
    drop(durable);
    let reopened = DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.batches().len(), 1);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn incomplete_append_can_be_retried_without_duplicate() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("durable-incomplete-retry");
    let _ = fs::remove_file(&path);
    let mut durable =
        DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
    let batch = sample_batch()?;
    durable.fail_journal_after_phase(AppendPhase::BodyWrite);
    assert!(matches!(
        durable.append(batch.clone()),
        Err(DurableLedgerError::Journal(
            JournalError::AppendIndeterminate {
                sequence: 1,
                phase: AppendPhase::BodyWrite,
                ..
            }
        ))
    ));
    assert_eq!(
        durable.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        DurableAppendReconciliation::NotCommitted { sequence: 1 }
    );
    assert_eq!(durable.batches().len(), 0);
    durable.append(batch)?;
    assert_eq!(durable.batches().len(), 1);
    assert_eq!(durable.verify_storage()?, durable.journal_root());
    drop(durable);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn lost_ack_replays_after_process_restart() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("durable-lost-ack-restart");
    let _ = fs::remove_file(&path);
    {
        let mut durable =
            DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
        durable.fail_journal_after_phase(AppendPhase::CommitSync);
        assert!(matches!(
            durable.append(sample_batch()?),
            Err(DurableLedgerError::Journal(
                JournalError::AppendIndeterminate {
                    sequence: 1,
                    phase: AppendPhase::CommitSync,
                    ..
                }
            ))
        ));
        assert_eq!(durable.batches().len(), 0);
    }
    {
        let mut reopened =
            DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.batches().len(), 1);
        assert_eq!(reopened.verify_storage()?, reopened.journal_root());
    }
    let _ = fs::remove_file(path);
    Ok(())
}
