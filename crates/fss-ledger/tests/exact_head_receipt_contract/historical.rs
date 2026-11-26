#![forbid(unsafe_code)]
//! Exact historical receipts authenticate retained epoch suffixes against the live owner.

use super::*;

use std::fs::OpenOptions;

use fss_ledger::{
    EPOCH_HEADER_LEN, EPOCH_RECORD_HEADER_LEN, EpochCorruptionKind, ReceiptProofBudget,
    ReceiptProofResource, ReceiptProofUsage, epoch_file_path,
};

fn open_with_epoch_size(
    dir: &TempDir,
    max_batches_per_epoch: u64,
) -> Result<MerkleEpochLedger, EpochLedgerError> {
    MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:exact-batch",
        EpochLedgerConfig {
            max_batches_per_epoch,
            checkpoint_stride: 1,
            ..EpochLedgerConfig::default()
        },
        IncompleteTailPolicy::Reject,
    )
}

fn epoch_path(dir: &TempDir, epoch_id: u64) -> PathBuf {
    epoch_file_path(&dir.0.join("ledger/epochs"), epoch_id)
}

fn append_named(
    ledger: &mut MerkleEpochLedger,
    label: &str,
) -> Result<(EvidenceDeltaBatch, fss_ledger::CommitReceipt), Box<dyn std::error::Error>> {
    let batch = prepare(ledger, label)?;
    let receipt = ledger.append_batch(batch.clone())?;
    Ok((batch, receipt))
}

fn no_history_budget() -> ReceiptProofBudget {
    ReceiptProofBudget {
        max_epochs: 0,
        max_records: 0,
        max_bytes: 0,
    }
}

#[test]
fn historical_receipt_crosses_rollover_and_reopen_without_archived_prefix() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 1)?;
    let _ = append_named(&mut ledger, "irrelevant-prefix")?;
    let (target, original) = append_named(&mut ledger, "historical-target")?;

    // Supersede the target's current object state. A receipt must describe its original
    // publication, even when neither its old generation nor original state root is current.
    let mut replacement = target.deltas[0].clone();
    replacement.delta_id = "delta:exact:replacement".to_owned();
    replacement.prior_generation = Some(1);
    replacement.new_generation = 2;
    replacement.payload_digest = ContentDigest::sha256(b"superseding historical source");
    let next = ledger.prepare_batch(
        BatchId::parse("batch:exact:replacement")?,
        vec![replacement.clone()],
        [replacement.payload_digest],
    )?;
    let head_receipt = ledger.append_batch(next.clone())?;
    drop(ledger);

    // Verified checkpoints permit an archived prefix that does not intersect this proof.
    fs::remove_file(epoch_path(&dir, 0))?;
    let reopened = open_with_epoch_size(&dir, 1)?;
    assert_eq!(
        reopened
            .get_object(&target.deltas[0].object_id)
            .map(|revision| revision.generation),
        Some(2)
    );
    let before: Vec<_> = [1, 2]
        .into_iter()
        .map(|epoch| fs::read(epoch_path(&dir, epoch)))
        .collect::<Result<_, _>>()?;
    let proof = reopened
        .receipt_for_exact_batch(&target, ReceiptProofBudget::default())?
        .ok_or("retained historical batch did not produce a proof")?;
    assert_eq!(proof.receipt, original);
    assert_eq!(proof.head_anchor, head_receipt.anchor);
    assert_eq!(proof.head_history_root, head_receipt.history_root);
    assert_eq!(proof.head_batch_digest, next.batch_digest);
    assert_eq!(proof.usage.epochs_scanned, 2);
    assert_eq!(proof.usage.records_verified, 2);
    assert!(proof.usage.bytes_read > 0);
    assert!(!epoch_path(&dir, 0).exists());
    for (epoch, bytes) in [1, 2].into_iter().zip(before) {
        assert_eq!(fs::read(epoch_path(&dir, epoch))?, bytes);
    }
    assert_eq!(reopened.commit_sequence(), 3);
    Ok(())
}

#[test]
fn identical_state_and_batch_on_another_history_has_a_distinct_original_receipt() -> TestResult {
    let left_dir = TempDir::new()?;
    let right_dir = TempDir::new()?;
    let mut left = open_with_epoch_size(&left_dir, 1)?;
    let mut right = open_with_epoch_size(&right_dir, 1)?;
    let prefix = prepare(&left, "same-state-prefix")?;
    let mut fork = prefix.clone();
    fork.batch_id = BatchId::parse("batch:exact:alternate-prefix")?;
    fork.batch_digest = fork.computed_digest();
    left.append_batch(prefix)?;
    right.append_batch(fork)?;
    assert_eq!(left.head_anchor(), right.head_anchor());
    assert_ne!(left.history_root(), right.history_root());

    // The exact target body, batch identity, state anchor, and sequence exist in both
    // histories. Only the authenticated history path distinguishes their receipts.
    let target = prepare(&left, "shared-historical-body")?;
    let original_left = left.append_batch(target.clone())?;
    let original_right = right.append_batch(target.clone())?;
    let next = prepare(&left, "shared-current-head")?;
    left.append_batch(next.clone())?;
    right.append_batch(next)?;
    let proof_left = left
        .receipt_for_exact_batch(&target, ReceiptProofBudget::default())?
        .ok_or("missing left proof")?;
    let proof_right = right
        .receipt_for_exact_batch(&target, ReceiptProofBudget::default())?
        .ok_or("missing right proof")?;
    assert_eq!(proof_left.receipt, original_left);
    assert_eq!(proof_right.receipt, original_right);
    assert_eq!(proof_left.receipt.anchor, proof_right.receipt.anchor);
    assert_eq!(
        proof_left.receipt.batch_digest,
        proof_right.receipt.batch_digest
    );
    assert_ne!(
        proof_left.receipt.history_root,
        proof_right.receipt.history_root
    );

    // Substitute a fully well-formed alternate suffix, including correct epoch headers,
    // payload checksums, and recomputed history trailers. Only the final trusted-head
    // comparison can reject this; simple framing checks and exact target bytes all pass.
    for epoch in [1, 2] {
        fs::write(
            epoch_path(&left_dir, epoch),
            fs::read(epoch_path(&right_dir, epoch))?,
        )?;
    }
    let before = left.history_root();
    assert!(matches!(
        left.receipt_for_exact_batch(&target, ReceiptProofBudget::default()),
        Err(EpochLedgerError::LiveStateDivergence(_))
    ));
    assert_eq!(left.history_root(), before);
    assert_eq!(left.commit_sequence(), 3);
    for epoch in [1, 2] {
        assert_eq!(
            fs::read(epoch_path(&left_dir, epoch))?,
            fs::read(epoch_path(&right_dir, epoch))?
        );
    }
    Ok(())
}

#[test]
fn cumulative_receipt_budgets_include_locator_headers_and_pre_target_records() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 4)?;
    let mut target = None;
    for index in 1..=5 {
        let (batch, _) = append_named(&mut ledger, &format!("budget-{index}"))?;
        if index == 3 {
            target = Some(batch);
        }
    }
    let target = target.ok_or("missing fixture target")?;
    let proof = ledger
        .receipt_for_exact_batch(&target, ReceiptProofBudget::default())?
        .ok_or("missing budget proof")?;
    assert_eq!(proof.usage.epochs_scanned, 2);
    assert_eq!(proof.usage.records_verified, 5);
    let file_bytes =
        fs::metadata(epoch_path(&dir, 0))?.len() + fs::metadata(epoch_path(&dir, 1))?.len();
    assert_eq!(
        proof.usage.bytes_read,
        file_bytes + 2 * EPOCH_HEADER_LEN as u64
    );
    let exact = ReceiptProofBudget {
        max_epochs: proof.usage.epochs_scanned,
        max_records: proof.usage.records_verified,
        max_bytes: proof.usage.bytes_read,
    };
    assert_eq!(
        ledger.receipt_for_exact_batch(&target, exact)?,
        Some(proof.clone())
    );
    for (budget, resource) in [
        (
            ReceiptProofBudget {
                max_epochs: 1,
                ..exact
            },
            ReceiptProofResource::Epochs,
        ),
        (
            ReceiptProofBudget {
                max_records: 4,
                ..exact
            },
            ReceiptProofResource::Records,
        ),
        (
            ReceiptProofBudget {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            ReceiptProofResource::Bytes,
        ),
        (
            ReceiptProofBudget {
                max_bytes: EPOCH_HEADER_LEN as u64 - 1,
                ..exact
            },
            ReceiptProofResource::Bytes,
        ),
    ] {
        let error = ledger
            .receipt_for_exact_batch(&target, budget)
            .expect_err("incomplete proof must not fit a smaller budget");
        match error {
            EpochLedgerError::ReceiptProofLimitExceeded {
                resource: observed,
                used,
                requested,
                maximum,
            } => {
                assert_eq!(observed, resource);
                assert!(
                    used.checked_add(requested)
                        .is_none_or(|total| total > maximum)
                );
            }
            other => return Err(format!("expected explicit budget refusal, got {other}").into()),
        }
        assert_eq!(ledger.commit_sequence(), 5);
        assert_eq!(ledger.history_root(), proof.head_history_root);
    }
    Ok(())
}

#[test]
fn current_head_proof_uses_zero_budget_and_no_epoch_reads() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 8)?;
    let (historical, _) = append_named(&mut ledger, "before-head")?;
    let (head, original) = append_named(&mut ledger, "cached-head")?;
    let epochs = dir.0.join("ledger/epochs");
    let unavailable = dir.0.join("unavailable-epochs");
    fs::rename(&epochs, &unavailable)?;
    let proof = ledger
        .receipt_for_exact_batch(&head, no_history_budget())?
        .ok_or("cached head receipt was not recovered")?;
    assert_eq!(proof.receipt, original);
    assert_eq!(proof.head_anchor, head.new_anchor);
    assert_eq!(proof.head_history_root, original.history_root);
    assert_eq!(proof.head_batch_digest, head.batch_digest);
    assert_eq!(proof.usage, ReceiptProofUsage::default());
    assert!(matches!(
        ledger.receipt_for_exact_batch(&historical, no_history_budget()),
        Err(EpochLedgerError::ReceiptProofLimitExceeded {
            resource: ReceiptProofResource::Epochs,
            ..
        })
    ));
    fs::rename(&unavailable, &epochs)?;
    assert_eq!(ledger.commit_sequence(), 2);
    Ok(())
}

#[test]
fn historical_batch_body_identity_and_anchor_must_match_the_native_index() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 8)?;
    let (target, _) = append_named(&mut ledger, "indexed-history")?;
    let _ = append_named(&mut ledger, "after-indexed-history")?;
    let mut stale_digest = target.clone();
    stale_digest.deltas[0].delta_id.push_str(":changed");
    assert!(matches!(
        ledger.receipt_for_exact_batch(&stale_digest, no_history_budget()),
        Err(EpochLedgerError::BatchDigestMismatch { .. })
    ));
    let mut changed_id = target.clone();
    changed_id.batch_id = BatchId::parse("batch:exact:other-historical-identity")?;
    let mut changed_basis = target.clone();
    changed_basis.basis_anchor.policy_epoch += 1;
    let mut changed_state = target.clone();
    changed_state.new_anchor.state_root = ContentDigest::sha256(b"uncommitted historical state");
    for mut changed in [stale_digest, changed_id, changed_basis, changed_state] {
        changed.batch_digest = changed.computed_digest();
        assert!(
            ledger
                .receipt_for_exact_batch(&changed, no_history_budget())?
                .is_none()
        );
    }
    assert_eq!(ledger.commit_sequence(), 2);
    Ok(())
}

#[test]
fn missing_historical_epoch_remains_unresolved_without_repair() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 1)?;
    let (target, _) = append_named(&mut ledger, "before-missing-epoch")?;
    let _ = append_named(&mut ledger, "missing-epoch")?;
    let _ = append_named(&mut ledger, "after-missing-epoch")?;
    let missing = epoch_path(&dir, 1);
    fs::remove_file(&missing)?;
    let before = ledger.history_root();
    assert!(matches!(
        ledger.receipt_for_exact_batch(&target, ReceiptProofBudget::default()),
        Err(EpochLedgerError::MissingEpoch {
            expected_epoch_id: 1
        })
    ));
    assert!(!missing.exists());
    assert_eq!(ledger.history_root(), before);
    assert_eq!(ledger.commit_sequence(), 3);
    Ok(())
}

#[test]
fn historical_header_and_continuation_payload_tampering_are_preserved_and_refused() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 1)?;
    let (target, _) = append_named(&mut ledger, "before-corruption")?;
    let _ = append_named(&mut ledger, "corrupt-continuation")?;
    let _ = append_named(&mut ledger, "after-corruption")?;
    for (epoch, offset, kind) in [
        (0, 54, EpochCorruptionKind::HeaderChecksumMismatch),
        (
            1,
            EPOCH_HEADER_LEN + EPOCH_RECORD_HEADER_LEN + 5,
            EpochCorruptionKind::PayloadChecksum,
        ),
    ] {
        let path = epoch_path(&dir, epoch);
        let original = fs::read(&path)?;
        let mut corrupt = original.clone();
        corrupt[offset] ^= 0x80;
        fs::write(&path, &corrupt)?;
        let error = ledger
            .receipt_for_exact_batch(&target, ReceiptProofBudget::default())
            .expect_err("corrupt receipt proof must be refused");
        match error {
            EpochLedgerError::CorruptEpoch { kind: observed, .. } => assert_eq!(observed, kind),
            other => return Err(format!("expected corruption refusal, got {other}").into()),
        }
        assert_eq!(fs::read(&path)?, corrupt);
        assert_eq!(ledger.commit_sequence(), 3);
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn extra_complete_or_partial_tail_cannot_extend_the_verified_receipt_endpoint() -> TestResult {
    let dir = TempDir::new()?;
    let future_dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 16)?;
    let mut future = open_with_epoch_size(&future_dir, 16)?;
    let (target, _) = append_named(&mut ledger, "tail-target")?;
    future.append_batch(target.clone())?;
    let (head, _) = append_named(&mut ledger, "tail-current-head")?;
    future.append_batch(head)?;
    let _ = append_named(&mut future, "tail-unpublished-future")?;
    let path = epoch_path(&dir, 0);
    let original = fs::read(&path)?;
    let future_bytes = fs::read(epoch_path(&future_dir, 0))?;
    fs::write(&path, &future_bytes)?;
    assert!(matches!(
        ledger.receipt_for_exact_batch(&target, ReceiptProofBudget::default()),
        Err(EpochLedgerError::LiveStateDivergence(_))
    ));
    assert_eq!(fs::read(&path)?, future_bytes);
    let mut partial = original;
    partial.extend_from_slice(b"FSS");
    fs::write(&path, &partial)?;
    assert!(matches!(
        ledger.receipt_for_exact_batch(&target, ReceiptProofBudget::default()),
        Err(EpochLedgerError::IncompleteTail { epoch_id: 0, .. })
    ));
    assert_eq!(fs::read(&path)?, partial);
    assert_eq!(ledger.commit_sequence(), 2);
    Ok(())
}

#[test]
fn oversized_epoch_is_refused_by_byte_budget_before_tail_allocation() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 8)?;
    let (target, _) = append_named(&mut ledger, "oversized-target")?;
    let _ = append_named(&mut ledger, "oversized-head")?;
    let path = epoch_path(&dir, 0);
    let oversized = 256 * 1024 * 1024;
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(oversized)?;
    assert!(matches!(
        ledger.receipt_for_exact_batch(
            &target,
            ReceiptProofBudget {
                max_bytes: 1024,
                ..ReceiptProofBudget::default()
            },
        ),
        Err(EpochLedgerError::ReceiptProofLimitExceeded {
            resource: ReceiptProofResource::Bytes,
            ..
        })
    ));
    assert_eq!(fs::metadata(path)?.len(), oversized);
    assert_eq!(ledger.commit_sequence(), 2);
    Ok(())
}

#[test]
fn unresolved_append_fences_historical_and_cached_receipts_before_budget_or_io() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_with_epoch_size(&dir, 8)?;
    let (first, original) = append_named(&mut ledger, "history-before-fence")?;
    let pending = prepare(&ledger, "fenced-future")?;
    ledger.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        ledger.append_batch(pending.clone()),
        Err(EpochLedgerError::AppendIndeterminate { sequence: 2, .. })
    ));
    for offered in [&first, &pending] {
        assert!(matches!(
            ledger.receipt_for_exact_batch(offered, no_history_budget()),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
    }
    let EpochAppendReconciliation::Committed(receipt) =
        ledger.reconcile_pending(IncompleteTailPolicy::Reject)?
    else {
        return Err("native append did not reconcile to a committed receipt".into());
    };
    let historical = ledger
        .receipt_for_exact_batch(&first, ReceiptProofBudget::default())?
        .ok_or("reconciled owner did not prove the historical receipt")?;
    assert_eq!(historical.receipt, original);
    assert_eq!(historical.head_history_root, receipt.history_root);
    let current = ledger
        .receipt_for_exact_batch(&pending, no_history_budget())?
        .ok_or("reconciled exact head did not use its cached receipt")?;
    assert_eq!(current.receipt, *receipt);
    assert_eq!(current.usage, ReceiptProofUsage::default());
    Ok(())
}
