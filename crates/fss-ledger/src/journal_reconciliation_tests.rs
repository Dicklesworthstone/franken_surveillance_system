use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use crate::{
    AppendPhase, AppendReconciliation, IncompleteTailPolicy, Journal, JournalError,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fss-ledger-{}-{name}.journal", std::process::id()))
}

#[test]
fn lost_commit_ack_blocks_retry_until_exact_reconciliation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("lost-commit-ack");
    let _ = fs::remove_file(&path);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.fail_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        journal.append(11, b"one"),
        Err(JournalError::AppendIndeterminate {
            sequence: 1,
            phase: AppendPhase::CommitSync,
            ..
        })
    ));
    assert_eq!(journal.pending_sequence(), Some(1));
    assert!(matches!(
        journal.append(11, b"one"),
        Err(JournalError::ReconciliationRequired { sequence: 1 })
    ));
    assert!(matches!(
        journal.verify(),
        Err(JournalError::ReconciliationRequired { sequence: 1 })
    ));

    match journal.reconcile_pending(IncompleteTailPolicy::Reject)? {
        AppendReconciliation::Committed(record) => {
            assert_eq!(record.sequence(), 1);
            assert_eq!(record.payload(), b"one");
        }
        AppendReconciliation::NotCommitted { .. } => {
            return Err("lost commit acknowledgement was not reconciled as committed".into());
        }
    }
    assert_eq!(journal.pending_sequence(), None);
    assert_eq!(journal.verify()?.records().len(), 1);
    assert_eq!(journal.append(12, b"two")?.sequence(), 2);
    assert_eq!(journal.verify()?.records().len(), 2);
    drop(journal);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn incomplete_append_requires_explicit_truncation_before_retry() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("incomplete-append-reconcile");
    let _ = fs::remove_file(&path);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.fail_after_phase(AppendPhase::BodyWrite);
    assert!(matches!(
        journal.append(11, b"one"),
        Err(JournalError::AppendIndeterminate {
            sequence: 1,
            phase: AppendPhase::BodyWrite,
            ..
        })
    ));
    assert!(matches!(
        journal.reconcile_pending(IncompleteTailPolicy::Reject),
        Err(JournalError::IncompleteTail { offset: 0 })
    ));
    assert_eq!(
        journal.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        AppendReconciliation::NotCommitted { sequence: 1 }
    );
    assert_eq!(journal.pending_sequence(), None);
    assert_eq!(journal.append(11, b"one")?.sequence(), 1);
    assert_eq!(journal.verify()?.records().len(), 1);
    drop(journal);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn stale_writer_detects_external_length_change_before_append() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("stale-writer");
    let _ = fs::remove_file(&path);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(11, b"one")?;
    let mut raw = OpenOptions::new().append(true).open(&path)?;
    raw.write_all(b"external")?;
    raw.sync_all()?;
    assert!(matches!(
        journal.append(12, b"two"),
        Err(JournalError::ExternalMutation { .. })
    ));
    drop(raw);
    drop(journal);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn lost_commit_ack_survives_handle_loss_without_duplicate() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("lost-ack-handle-loss");
    let _ = fs::remove_file(&path);
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.fail_after_phase(AppendPhase::CommitSync);
        assert!(matches!(
            journal.append(11, b"one"),
            Err(JournalError::AppendIndeterminate {
                sequence: 1,
                phase: AppendPhase::CommitSync,
                ..
            })
        ));
    }
    {
        let mut reopened = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.verify()?.records().len(), 1);
        assert_eq!(reopened.append(12, b"two")?.sequence(), 2);
        assert_eq!(reopened.verify()?.records().len(), 2);
    }
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn incomplete_append_survives_handle_loss_as_explicit_tail() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("incomplete-handle-loss");
    let _ = fs::remove_file(&path);
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.fail_after_phase(AppendPhase::BodyWrite);
        assert!(matches!(
            journal.append(11, b"one"),
            Err(JournalError::AppendIndeterminate {
                sequence: 1,
                phase: AppendPhase::BodyWrite,
                ..
            })
        ));
    }
    assert!(matches!(
        Journal::open(&path, IncompleteTailPolicy::Reject),
        Err(JournalError::IncompleteTail { offset: 0 })
    ));
    {
        let mut repaired = Journal::open(&path, IncompleteTailPolicy::Truncate)?;
        assert_eq!(repaired.verify()?.records().len(), 0);
        assert_eq!(repaired.append(11, b"one")?.sequence(), 1);
        assert_eq!(repaired.verify()?.records().len(), 1);
    }
    let _ = fs::remove_file(path);
    Ok(())
}
