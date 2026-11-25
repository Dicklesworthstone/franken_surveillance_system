#![forbid(unsafe_code)]
//! Writer ownership and ambiguous-append recovery for the production v2 ledger.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::storage_adapter::{
    FrankenSqliteStorageAdapter, MerkleEpochStorage, StorageAuthorityScope, StorageCommitState,
    StorageError, StorageGuidance, StorageMigrationPlan, StorageRecoveryOutcome,
    StorageSchemaVersion,
};
use fss_ledger::{
    AppendPhase, EpochAppendReconciliation, EpochLedgerConfig, EpochLedgerError,
    IncompleteTailPolicy, MerkleEpochLedger, epoch_file_path, inspect_epochs_readonly,
};

type TestResult = Result<(), Box<dyn Error>>;
const SITE: &str = "site:merkle-writer-recovery";

fn config() -> EpochLedgerConfig {
    EpochLedgerConfig {
        checkpoint_stride: 0,
        ..EpochLedgerConfig::default()
    }
}

fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fss-merkle-writer-recovery-{}", std::process::id()))
        .join(label);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn open(dir: &Path) -> Result<MerkleEpochLedger, EpochLedgerError> {
    MerkleEpochLedger::open(dir, SITE, config(), IncompleteTailPolicy::Reject)
}

fn prepare(
    ledger: &MerkleEpochLedger,
    sequence: u64,
) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    Ok(ledger.prepare_batch(
        BatchId::parse(format!("batch:{sequence}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:{sequence}"),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(format!("object:{sequence}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(format!("payload:{sequence}").as_bytes()),
            witness_digest: None,
            operation_id: None,
        }],
        [],
    )?)
}

fn epoch_path(dir: &Path, ledger: &MerkleEpochLedger) -> PathBuf {
    epoch_file_path(&dir.join("epochs"), ledger.active_epoch_id())
}

fn authority() -> StorageAuthorityScope {
    StorageAuthorityScope::active(
        ContentDigest::sha256(b"contract-basis:epoch-recovery"),
        1,
        1,
        [Plane::Authority],
    )
}

fn block_checkpoint(dir: &Path, sequence: u64) -> Result<PathBuf, Box<dyn Error>> {
    let path = dir
        .join("checkpoints")
        .join(format!(".seq-{sequence:020}.fssc.tmp"));
    fs::create_dir(&path)?;
    Ok(path)
}

#[test]
fn exclusive_writer_rejects_competing_recovery_without_mutating_tail() -> TestResult {
    let dir = fresh_dir("writer-before-recovery")?;
    let mut owner = open(&dir)?;
    let committed = owner.append_batch(prepare(&owner, 1)?)?;
    assert!(inspect_epochs_readonly(&dir, SITE).is_ok());
    let epoch = epoch_path(&dir, &owner);
    let mut raw = OpenOptions::new().append(true).open(&epoch)?;
    raw.write_all(b"FSSR")?;
    raw.sync_all()?;
    drop(raw);
    let before = fs::read(&epoch)?;

    assert!(matches!(
        MerkleEpochLedger::open(&dir, SITE, config(), IncompleteTailPolicy::Truncate),
        Err(EpochLedgerError::WriterLocked)
    ));
    assert_eq!(fs::read(&epoch)?, before);
    assert!(!dir.join("quarantine").exists());
    assert!(matches!(
        owner.append_batch(prepare(&owner, 2)?),
        Err(EpochLedgerError::LiveStateDivergence(_))
    ));
    assert_eq!(owner.head_anchor(), &committed.anchor);
    drop(owner);

    let mut recovered =
        MerkleEpochLedger::open(&dir, SITE, config(), IncompleteTailPolicy::Truncate)?;
    assert_eq!(recovered.head_anchor(), &committed.anchor);
    assert!(
        recovered
            .recovery_summary()
            .truncated_tail_quarantine
            .is_some()
    );
    assert_eq!(recovered.append_batch(prepare(&recovered, 2)?)?.sequence, 2);
    assert_eq!(recovered.verify_full_chain()?.batches_verified, 2);
    drop(recovered);
    assert!(
        dir.join("LOCK").is_file(),
        "the shared lock inode must remain stable"
    );
    assert_eq!(open(&dir)?.commit_sequence(), 2);
    Ok(())
}

#[test]
fn writer_lock_child() -> TestResult {
    let Some(dir) = std::env::var_os("FSS_MERKLE_LOCK_TEST_ROOT") else {
        return Ok(());
    };
    if std::env::var_os("FSS_MERKLE_LOCK_EXPECT_BLOCKED").is_some() {
        assert!(matches!(
            open(Path::new(&dir)),
            Err(EpochLedgerError::WriterLocked)
        ));
    } else {
        let mut ledger = open(Path::new(&dir))?;
        assert_eq!(ledger.append_batch(prepare(&ledger, 2)?)?.sequence, 2);
    }
    Ok(())
}

#[test]
fn writer_lock_is_cross_process_and_released_on_drop() -> TestResult {
    let dir = fresh_dir("cross-process-lock")?;
    let mut owner = open(&dir)?;
    owner.append_batch(prepare(&owner, 1)?)?;
    let child = std::env::current_exe()?;
    let blocked = Command::new(&child)
        .args(["--exact", "writer_lock_child", "--nocapture"])
        .env("FSS_MERKLE_LOCK_TEST_ROOT", &dir)
        .env("FSS_MERKLE_LOCK_EXPECT_BLOCKED", "1")
        .output()?;
    assert!(
        blocked.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert_eq!(owner.verify_full_chain()?.batches_verified, 1);
    drop(owner);
    let admitted = Command::new(child)
        .args(["--exact", "writer_lock_child", "--nocapture"])
        .env("FSS_MERKLE_LOCK_TEST_ROOT", &dir)
        .env_remove("FSS_MERKLE_LOCK_EXPECT_BLOCKED")
        .output()?;
    assert!(
        admitted.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&admitted.stdout),
        String::from_utf8_lossy(&admitted.stderr)
    );
    assert_eq!(open(&dir)?.verify_full_chain()?.batches_verified, 2);
    Ok(())
}

#[test]
fn every_append_phase_preserves_exact_candidate_and_blocks_blind_retry() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let dir = fresh_dir(&format!("phase-{phase:?}"))?;
        let mut ledger = open(&dir)?;
        let first = ledger.append_batch(prepare(&ledger, 1)?)?;
        let pending = prepare(&ledger, 2)?;
        ledger.fail_journal_after_phase(phase);
        assert!(matches!(
            ledger.append_batch(pending.clone()),
            Err(EpochLedgerError::AppendIndeterminate {
                sequence: 2, phase: observed, ..
            }) if observed == phase
        ));
        assert_eq!(ledger.pending_append_sequence(), Some(2));
        assert_eq!(ledger.head_anchor(), &first.anchor);
        assert!(ledger.get_object(&ObjectId::parse("object:2")?).is_none());
        let epoch = epoch_path(&dir, &ledger);
        let attempted_bytes = fs::read(&epoch)?;
        assert!(matches!(
            ledger.prepare_batch(BatchId::parse("batch:other")?, vec![], []),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
        assert!(matches!(
            ledger.append_batch(pending.clone()),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
        assert!(matches!(
            ledger.force_checkpoint(),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
        assert!(matches!(
            ledger.verify_full_chain(),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
        assert!(matches!(open(&dir), Err(EpochLedgerError::WriterLocked)));
        assert_eq!(fs::read(&epoch)?, attempted_bytes);

        if committed {
            let EpochAppendReconciliation::Committed(receipt) =
                ledger.reconcile_pending(IncompleteTailPolicy::Reject)?
            else {
                return Err("complete attempted record was not reconciled as committed".into());
            };
            assert_eq!(receipt.batch_id, pending.batch_id);
            assert_eq!(receipt.batch_digest, pending.batch_digest);
            assert_eq!(receipt.anchor, pending.new_anchor);
        } else {
            assert!(matches!(
                ledger.reconcile_pending(IncompleteTailPolicy::Reject),
                Err(EpochLedgerError::IncompleteTail { .. })
            ));
            assert_eq!(fs::read(&epoch)?, attempted_bytes);
            assert_eq!(ledger.pending_append_sequence(), Some(2));
            assert_eq!(
                ledger.reconcile_pending(IncompleteTailPolicy::Truncate)?,
                EpochAppendReconciliation::NotCommitted { sequence: 2 }
            );
            let entries: Vec<_> = fs::read_dir(dir.join("quarantine"))?.collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(ledger.head_anchor(), &first.anchor);
            assert_eq!(ledger.append_batch(pending.clone())?.sequence, 2);
        }
        assert_eq!(ledger.pending_append_sequence(), None);
        assert!(matches!(
            ledger.append_batch(pending),
            Err(EpochLedgerError::DuplicateBatch {
                committed_sequence: 2,
                ..
            })
        ));
        assert_eq!(ledger.verify_full_chain()?.batches_verified, 2);
        let root = ledger.history_root();
        drop(ledger);
        let reopened = open(&dir)?;
        assert_eq!(reopened.commit_sequence(), 2);
        assert_eq!(reopened.history_root(), root);
    }
    Ok(())
}

#[test]
fn torn_attempt_prefixes_preserve_history_and_quarantine_exact_bytes() -> TestResult {
    for cut_kind in 0..6 {
        let dir = fresh_dir(&format!("torn-prefix-{cut_kind}"))?;
        let mut ledger = open(&dir)?;
        let first = ledger.append_batch(prepare(&ledger, 1)?)?;
        let committed_len = ledger.active_epoch_bytes() as usize;
        let batch = prepare(&ledger, 2)?;
        ledger.fail_journal_after_phase(AppendPhase::CommitWrite);
        assert!(matches!(
            ledger.append_batch(batch.clone()),
            Err(EpochLedgerError::AppendIndeterminate { .. })
        ));
        let path = epoch_path(&dir, &ledger);
        let attempted = fs::read(&path)?;
        let framed_len = attempted.len() - committed_len;
        let suffix_len = match cut_kind {
            0 => 0,
            1 => 1,
            2 => fss_ledger::EPOCH_RECORD_HEADER_LEN - 1,
            3 => fss_ledger::EPOCH_RECORD_HEADER_LEN + 1,
            4 => framed_len - fss_ledger::EPOCH_RECORD_TRAILER_LEN,
            _ => framed_len - 1,
        };
        // The failed commit write has no successful durability acknowledgement. Model the
        // surviving prefix after a torn write while retaining the exact attempted identity.
        fs::write(&path, &attempted[..committed_len + suffix_len])?;
        assert_eq!(
            ledger.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            EpochAppendReconciliation::NotCommitted { sequence: 2 }
        );
        assert_eq!(ledger.head_anchor(), &first.anchor);
        assert_eq!(fs::read(&path)?, attempted[..committed_len]);
        if suffix_len == 0 {
            assert!(!dir.join("quarantine").exists());
        } else {
            let entries = fs::read_dir(dir.join("quarantine"))?.collect::<Result<Vec<_>, _>>()?;
            assert_eq!(entries.len(), 1);
            assert_eq!(
                fs::read(entries[0].path())?,
                attempted[committed_len..committed_len + suffix_len]
            );
        }
        ledger.append_batch(batch)?;
        assert_eq!(ledger.verify_full_chain()?.batches_verified, 2);
    }
    Ok(())
}

#[test]
fn every_reconciliation_phase_retains_fence_until_resolution() -> TestResult {
    for append_phase in [AppendPhase::BodySync, AppendPhase::CommitSync] {
        for reconcile_phase in [
            AppendPhase::ReconcileRead,
            AppendPhase::ReconcileTruncate,
            AppendPhase::ReconcileSync,
            AppendPhase::ReconcileSeek,
        ] {
            if append_phase == AppendPhase::CommitSync
                && reconcile_phase == AppendPhase::ReconcileTruncate
            {
                continue;
            }
            let dir = fresh_dir(&format!("reconcile-{append_phase:?}-{reconcile_phase:?}"))?;
            let mut ledger = open(&dir)?;
            let pending = prepare(&ledger, 1)?;
            ledger.fail_journal_after_phase(append_phase);
            assert!(matches!(
                ledger.append_batch(pending.clone()),
                Err(EpochLedgerError::AppendIndeterminate { .. })
            ));
            ledger.fail_journal_after_phase(reconcile_phase);
            assert!(matches!(
                ledger.reconcile_pending(IncompleteTailPolicy::Truncate),
                Err(EpochLedgerError::AppendIndeterminate {
                    sequence: 1, phase, ..
                }) if phase == reconcile_phase
            ));
            assert_eq!(ledger.commit_sequence(), 0);
            assert_eq!(ledger.pending_append_sequence(), Some(1));
            assert!(matches!(
                ledger.force_checkpoint(),
                Err(EpochLedgerError::ReconciliationRequired { sequence: 1 })
            ));
            let outcome = ledger.reconcile_pending(IncompleteTailPolicy::Truncate)?;
            if append_phase == AppendPhase::CommitSync {
                assert!(matches!(outcome, EpochAppendReconciliation::Committed(_)));
            } else {
                assert_eq!(
                    outcome,
                    EpochAppendReconciliation::NotCommitted { sequence: 1 }
                );
                assert_eq!(fs::read_dir(dir.join("quarantine"))?.count(), 1);
                ledger.append_batch(pending)?;
            }
            assert_eq!(ledger.verify_full_chain()?.batches_verified, 1);
        }
    }
    Ok(())
}

#[test]
fn divergent_pending_bytes_are_never_truncated_or_published() -> TestResult {
    let dir = fresh_dir("pending-content-drift")?;
    let mut ledger = open(&dir)?;
    let batch = prepare(&ledger, 1)?;
    ledger.fail_journal_after_phase(AppendPhase::BodySync);
    assert!(matches!(
        ledger.append_batch(batch),
        Err(EpochLedgerError::AppendIndeterminate { .. })
    ));
    let epoch = epoch_path(&dir, &ledger);
    let exact = fs::read(&epoch)?;
    let mut corrupt = exact.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x01;
    fs::write(&epoch, &corrupt)?;
    assert!(matches!(
        ledger.reconcile_pending(IncompleteTailPolicy::Truncate),
        Err(EpochLedgerError::LiveStateDivergence(_))
    ));
    assert_eq!(ledger.commit_sequence(), 0);
    assert_eq!(ledger.pending_append_sequence(), Some(1));
    assert_eq!(fs::read(&epoch)?, corrupt);
    assert!(!dir.join("quarantine").exists());
    fs::write(&epoch, &exact)?;
    assert_eq!(
        ledger.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        EpochAppendReconciliation::NotCommitted { sequence: 1 }
    );
    Ok(())
}

#[test]
fn handle_loss_recovers_acknowledged_records_and_explicit_incomplete_tails() -> TestResult {
    for (phase, expected_sequence) in [(AppendPhase::BodyWrite, 1), (AppendPhase::CommitSync, 2)] {
        let dir = fresh_dir(&format!("lost-handle-{phase:?}"))?;
        let mut ledger = open(&dir)?;
        ledger.append_batch(prepare(&ledger, 1)?)?;
        let attempted = prepare(&ledger, 2)?;
        ledger.fail_journal_after_phase(phase);
        assert!(matches!(
            ledger.append_batch(attempted.clone()),
            Err(EpochLedgerError::AppendIndeterminate { .. })
        ));
        drop(ledger);
        if phase == AppendPhase::BodyWrite {
            assert!(matches!(
                open(&dir),
                Err(EpochLedgerError::IncompleteTail { .. })
            ));
        }
        let mut recovered =
            MerkleEpochLedger::open(&dir, SITE, config(), IncompleteTailPolicy::Truncate)?;
        assert_eq!(recovered.commit_sequence(), expected_sequence);
        if phase == AppendPhase::BodyWrite {
            recovered.append_batch(attempted)?;
        } else {
            assert!(matches!(
                recovered.append_batch(attempted),
                Err(EpochLedgerError::DuplicateBatch {
                    committed_sequence: 2,
                    ..
                })
            ));
        }
        assert_eq!(recovered.verify_full_chain()?.batches_verified, 2);
    }
    Ok(())
}

#[test]
fn storage_adapter_reconciles_exact_epoch_append_and_preserves_duplicate_identity() -> TestResult {
    let authority = authority();
    for phase in [AppendPhase::BodySync, AppendPhase::CommitSync] {
        let dir = fresh_dir(&format!("adapter-{phase:?}"))?;
        let mut ledger = open(&dir)?;
        let batch = prepare(&ledger, 1)?;
        ledger.fail_journal_after_phase(phase);
        let mut storage = MerkleEpochStorage::new(ledger);
        assert!(matches!(
            storage.commit_witnessed_batch(&authority, batch.clone(), &[], TimestampNs(1), false),
            Err(StorageError::IndeterminateAppend { sequence: 1, .. })
        ));
        assert!(matches!(
            storage.commit_witnessed_batch(&authority, batch.clone(), &[], TimestampNs(2), false),
            Err(StorageError::IndeterminateAppend { sequence: 1, .. })
        ));
        let mut migration_authority = authority.clone();
        migration_authority.allows_migration = true;
        let migration = StorageMigrationPlan {
            migration_id: "migration:pending-epoch".to_owned(),
            from_version: StorageSchemaVersion::V2_0,
            to_version: StorageSchemaVersion::V2_1,
            description: "Must not cross an unresolved append".to_owned(),
        };
        assert!(matches!(
            storage.migrate_schema(&migration_authority, &migration, TimestampNs(3), false),
            Err(StorageError::IndeterminateAppend { sequence: 1, .. })
        ));
        assert_eq!(storage.schema_version(), StorageSchemaVersion::V2_0);
        assert!(matches!(
            storage.force_checkpoint(&authority, false),
            Err(StorageError::IndeterminateAppend { sequence: 1, .. })
        ));
        assert!(matches!(
            storage.reconcile_after_crash(&authority, TimestampNs(3), true),
            Err(StorageError::Cancelled)
        ));
        let mut revoked = authority.clone();
        revoked.capability_active = false;
        assert!(matches!(
            storage.reconcile_after_crash(&revoked, TimestampNs(3), false),
            Err(StorageError::AuthorityRefused(_))
        ));
        assert_eq!(storage.ledger().pending_append_sequence(), Some(1));
        let outcome = storage.reconcile_after_crash(&authority, TimestampNs(4), false)?;
        assert_eq!(
            outcome.outcome,
            if phase == AppendPhase::CommitSync {
                StorageRecoveryOutcome::PendingCommitted
            } else {
                StorageRecoveryOutcome::PendingNotCommitted
            }
        );
        let receipt =
            storage.commit_witnessed_batch(&authority, batch, &[], TimestampNs(5), false)?;
        assert_eq!(
            receipt.commit_state,
            if phase == AppendPhase::CommitSync {
                StorageCommitState::ReconciledDuplicate
            } else {
                StorageCommitState::Durable
            }
        );
        assert_eq!(storage.ledger().verify_full_chain()?.batches_verified, 1);
    }
    Ok(())
}

#[test]
fn append_failure_after_epoch_rollover_preserves_both_epoch_boundaries() -> TestResult {
    let dir = fresh_dir("rollover-uncertain")?;
    let cfg = EpochLedgerConfig {
        max_batches_per_epoch: 1,
        ..config()
    };
    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    ledger.append_batch(prepare(&ledger, 1)?)?;
    let sealed_epoch = epoch_file_path(&dir.join("epochs"), 0);
    let sealed_bytes = fs::read(&sealed_epoch)?;
    let second = prepare(&ledger, 2)?;
    ledger.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        ledger.append_batch(second),
        Err(EpochLedgerError::AppendIndeterminate {
            epoch_id: 1,
            sequence: 2,
            ..
        })
    ));
    assert_eq!(ledger.commit_sequence(), 1);
    assert_eq!(fs::read(&sealed_epoch)?, sealed_bytes);
    assert!(matches!(
        ledger.reconcile_pending(IncompleteTailPolicy::Reject)?,
        EpochAppendReconciliation::Committed(_)
    ));
    assert_eq!(ledger.verify_full_chain()?.batches_verified, 2);
    drop(ledger);
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.active_epoch_id(), 1);
    assert_eq!(reopened.commit_sequence(), 2);
    Ok(())
}

#[test]
fn periodic_checkpoint_failure_returns_durable_receipt_and_can_be_repaired() -> TestResult {
    let dir = fresh_dir("checkpoint-after-commit")?;
    let cfg = EpochLedgerConfig {
        checkpoint_stride: 1,
        ..config()
    };
    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    let blocked = block_checkpoint(&dir, 1)?;
    let batch = prepare(&ledger, 1)?;
    let EpochLedgerError::CommittedCheckpointFailed { receipt, source } = ledger
        .append_batch(batch.clone())
        .expect_err("checkpoint path is blocked")
    else {
        return Err("durable append must not become a generic checkpoint error".into());
    };
    assert!(matches!(*source, EpochLedgerError::Io(_)));
    assert_eq!(receipt.batch_digest, batch.batch_digest);
    assert_eq!(ledger.head_anchor(), &receipt.anchor);
    assert_eq!(ledger.pending_append_sequence(), None);
    assert_eq!(ledger.verify_full_chain()?.batches_verified, 1);
    assert!(matches!(
        ledger.append_batch(batch),
        Err(EpochLedgerError::DuplicateBatch {
            committed_sequence: 1,
            ..
        })
    ));
    fs::remove_dir(&blocked)?;
    assert_eq!(ledger.force_checkpoint()?.commit_sequence, 1);
    drop(ledger);
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), 1);
    assert_eq!(reopened.history_root(), receipt.history_root);
    Ok(())
}

#[test]
fn rollover_checkpoint_failure_does_not_claim_the_next_batch_committed() -> TestResult {
    let dir = fresh_dir("checkpoint-before-rollover")?;
    let cfg = EpochLedgerConfig {
        max_batches_per_epoch: 1,
        ..config()
    };
    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    ledger.append_batch(prepare(&ledger, 1)?)?;
    let second = prepare(&ledger, 2)?;
    let blocked = block_checkpoint(&dir, 1)?;
    assert!(matches!(
        ledger.append_batch(second.clone()),
        Err(EpochLedgerError::Io(_))
    ));
    assert_eq!(ledger.commit_sequence(), 1);
    assert_eq!(ledger.pending_append_sequence(), None);
    fs::remove_dir(&blocked)?;
    assert_eq!(ledger.append_batch(second)?.sequence, 2);
    assert_eq!(ledger.verify_full_chain()?.batches_verified, 2);
    Ok(())
}

#[test]
fn storage_checkpoint_failure_preserves_receipt_and_idempotent_retry() -> TestResult {
    let dir = fresh_dir("adapter-checkpoint")?;
    let cfg = EpochLedgerConfig {
        checkpoint_stride: 1,
        ..config()
    };
    let ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    let batch = prepare(&ledger, 1)?;
    let blocked = block_checkpoint(&dir, 1)?;
    let authority = authority();
    let mut storage = MerkleEpochStorage::new(ledger);
    let error = storage
        .commit_witnessed_batch(&authority, batch.clone(), &[], TimestampNs(1), false)
        .expect_err("checkpoint path is blocked");
    assert_eq!(error.guidance(), StorageGuidance::RetryCheckpoint);
    let StorageError::CommittedCheckpointFailed { receipt, .. } = error else {
        return Err("adapter lost the committed checkpoint-failure receipt".into());
    };
    assert_eq!(receipt.batch_digest, batch.batch_digest);
    assert_eq!(receipt.sequence, 1);
    fs::remove_dir(&blocked)?;
    assert!(matches!(
        storage.force_checkpoint(&authority, true),
        Err(StorageError::Cancelled)
    ));
    assert_eq!(
        storage.force_checkpoint(&authority, false)?.commit_sequence,
        1
    );
    let duplicate =
        storage.commit_witnessed_batch(&authority, batch, &[], TimestampNs(2), false)?;
    assert_eq!(
        duplicate.commit_state,
        StorageCommitState::ReconciledDuplicate
    );
    assert_eq!(duplicate.committed_anchor, receipt.anchor);
    assert_eq!(duplicate.history_root, receipt.history_root);
    assert_eq!(storage.ledger().verify_full_chain()?.batches_verified, 1);
    drop(storage);
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        reopened
            .recovery_summary()
            .loaded_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.commit_sequence),
        Some(1)
    );
    Ok(())
}
