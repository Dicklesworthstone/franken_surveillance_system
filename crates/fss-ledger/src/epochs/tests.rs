#![forbid(unsafe_code)]
//! Unit tests for segmented epoch journals, checkpoint snapshots, crash tails, and recovery.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};

use crate::journal::IncompleteTailPolicy;
use crate::merkle::verify_proof;

use super::{
    CheckpointCorruptionKind, EPOCH_HEADER_LEN, EPOCH_RECORD_HEADER_LEN, EpochCorruptionKind,
    EpochLedgerConfig, EpochLedgerError, MerkleEpochLedger, checkpoint_file_path, crc32_ieee,
    epoch_file_path, read_and_verify_checkpoint,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:epoch-unit";

fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::env::temp_dir()
        .join(format!("fss-ledger-epochs-unit-{}", std::process::id()))
        .join(label);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn delta(
    tag: &str,
    obj_name: &str,
    prior: Option<u64>,
    new_gen: u64,
    family: &str,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    let start = i128::from(new_gen) * 100;
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: family.to_owned(),
        object_id: ObjectId::parse(format!("object:{obj_name}"))?,
        prior_generation: prior,
        new_generation: new_gen,
        validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 10))?,
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn append_create(
    ledger: &mut MerkleEpochLedger,
    idx: u64,
) -> Result<crate::CommitReceipt, Box<dyn Error>> {
    let batch = ledger.prepare_batch(
        BatchId::parse(format!("batch:{idx}"))?,
        vec![delta(
            &format!("d-{idx}"),
            &format!("obj-{idx}"),
            None,
            1,
            "sensor_capsule",
            Plane::Authority,
        )?],
        [],
    )?;
    Ok(ledger.append_batch(batch)?)
}

#[test]
fn crc32_matches_ieee_standard_vector() {
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32_ieee(b""), 0x0000_0000);
}

#[test]
fn epoch_rollover_by_batch_count_and_bytes_with_full_chain_verification() -> TestResult {
    let dir = fresh_dir("rollover-batches-and-bytes")?;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 3,
        checkpoint_stride: 100, // Only rollover checkpoints should fire
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    for i in 1..=10_u64 {
        let receipt = append_create(&mut ledger, i)?;
        assert_eq!(receipt.sequence, i);
    }

    // 10 batches with max 3/epoch => epochs 0 (1..=3), 1 (4..=6), 2 (7..=9), 3 (10)
    assert_eq!(ledger.active_epoch_id(), 3);
    assert_eq!(ledger.commit_sequence(), 10);
    assert_eq!(ledger.live_object_count(), 10);
    for epoch in 0..=3_u64 {
        assert!(epoch_file_path(&dir.join("epochs"), epoch).exists());
    }
    // Checkpoints emitted on rollover boundaries at seq 3, 6, 9
    for seq in [3_u64, 6, 9] {
        assert!(checkpoint_file_path(&dir.join("checkpoints"), seq).exists());
    }

    let report = ledger.verify_full_chain()?;
    assert_eq!(report.epochs_verified, 4);
    assert_eq!(report.batches_verified, 10);
    assert_eq!(report.live_objects, 10);
    assert_eq!(report.state_root, ledger.state_root());
    assert_eq!(report.history_root, ledger.history_root());

    // Reopen must load checkpoint seq 9 in O(1) and replay ONLY batch 10
    let expected_root = ledger.state_root();
    let expected_hist = ledger.history_root();
    drop(ledger);

    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), 10);
    assert_eq!(reopened.state_root(), expected_root);
    assert_eq!(reopened.history_root(), expected_hist);
    assert_eq!(reopened.recovery_summary().replayed_tail_batches, 1);
    assert_eq!(
        reopened
            .recovery_summary()
            .loaded_checkpoint
            .as_ref()
            .map(|cp| cp.commit_sequence),
        Some(9)
    );
    let _ = reopened.verify_full_chain()?;

    // Also verify byte-triggered rollover
    let dir_bytes = fresh_dir("rollover-bytes")?;
    let small_byte_cfg = EpochLedgerConfig {
        max_epoch_bytes: 512,
        max_batches_per_epoch: 100,
        checkpoint_stride: 0,
        max_objects: None,
    };
    let mut byte_ledger = MerkleEpochLedger::open(
        &dir_bytes,
        SITE,
        small_byte_cfg,
        IncompleteTailPolicy::Reject,
    )?;
    for i in 1..=5_u64 {
        append_create(&mut byte_ledger, i)?;
    }
    assert!(
        byte_ledger.active_epoch_id() >= 1,
        "byte limit should trigger rollover"
    );
    let byte_report = byte_ledger.verify_full_chain()?;
    assert_eq!(byte_report.batches_verified, 5);
    Ok(())
}

#[test]
fn malformed_checkpoint_refused_and_fallback_to_prior_checkpoint_or_genesis() -> TestResult {
    let dir = fresh_dir("checkpoint-fallback")?;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 100,
        checkpoint_stride: 3,
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    for i in 1..=8_u64 {
        append_create(&mut ledger, i)?;
    }
    let expected_root = ledger.state_root();
    let expected_hist = ledger.history_root();
    drop(ledger);

    // Checkpoints exist at seq 3 and seq 6.
    let cp_dir = dir.join("checkpoints");
    let cp3 = checkpoint_file_path(&cp_dir, 3);
    let cp6 = checkpoint_file_path(&cp_dir, 6);
    assert!(cp3.exists());
    assert!(cp6.exists());

    // Direct malformed checkpoint refusal checks
    assert_eq!(
        read_and_verify_checkpoint(&cp6, Some(99), SITE, true).err(),
        Some(CheckpointCorruptionKind::FilenameSequenceMismatch)
    );
    assert_eq!(
        read_and_verify_checkpoint(&cp6, Some(6), "site:wrong", true).err(),
        Some(CheckpointCorruptionKind::SiteLineageMismatch)
    );

    // Corrupt latest checkpoint (seq 6) by flipping a byte inside the body
    let mut cp6_bytes = fs::read(&cp6)?;
    let mid = cp6_bytes.len() / 2;
    cp6_bytes[mid] ^= 0x5A;
    fs::write(&cp6, &cp6_bytes)?;
    assert_eq!(
        read_and_verify_checkpoint(&cp6, Some(6), SITE, true).err(),
        Some(CheckpointCorruptionKind::IntegrityDigestMismatch)
    );

    // Also plant a truncated/partial future checkpoint at seq 7
    let cp7 = checkpoint_file_path(&cp_dir, 7);
    fs::write(&cp7, b"FSSC\x00\x02partial")?;

    // Open must quarantine seq 7 and seq 6, fall back cleanly to seq 3, and replay 4..=8 (5 batches)
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), 8);
    assert_eq!(reopened.state_root(), expected_root);
    assert_eq!(reopened.history_root(), expected_hist);
    assert_eq!(
        reopened
            .recovery_summary()
            .loaded_checkpoint
            .as_ref()
            .map(|cp| cp.commit_sequence),
        Some(3)
    );
    assert_eq!(reopened.recovery_summary().replayed_tail_batches, 5);
    assert_eq!(reopened.recovery_summary().quarantined_checkpoints.len(), 2);
    assert!(!cp6.exists());
    assert!(!cp7.exists());
    for (qpath, _) in &reopened.recovery_summary().quarantined_checkpoints {
        assert!(qpath.exists());
    }
    drop(reopened);

    // Now corrupt seq 3 with bad magic -> must quarantine and fall back cleanly to genesis!
    fs::write(
        &cp3,
        b"BADM\x00\x02truncated_bad_magic_checkpoint_payload_padding",
    )?;
    let from_genesis = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(from_genesis.commit_sequence(), 8);
    assert_eq!(from_genesis.state_root(), expected_root);
    assert_eq!(from_genesis.history_root(), expected_hist);
    assert!(from_genesis.recovery_summary().loaded_checkpoint.is_none());
    assert_eq!(from_genesis.recovery_summary().replayed_tail_batches, 8);
    assert_eq!(
        from_genesis
            .recovery_summary()
            .quarantined_checkpoints
            .len(),
        1
    );
    Ok(())
}

#[test]
fn truncated_epoch_tail_honors_reject_and_truncate_and_rejects_junk() -> TestResult {
    let dir = fresh_dir("truncated-tail")?;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 100,
        checkpoint_stride: 10,
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    append_create(&mut ledger, 1)?;
    append_create(&mut ledger, 2)?;
    let committed_len_at_2 = ledger.active_epoch_bytes();
    let root_at_2 = ledger.state_root();
    let hist_at_2 = ledger.history_root();
    append_create(&mut ledger, 3)?;
    let full_len_at_3 = ledger.active_epoch_bytes();
    drop(ledger);

    let epoch0 = epoch_file_path(&dir.join("epochs"), 0);
    let full_bytes = fs::read(&epoch0)?;
    let rec3_len = (full_len_at_3 - committed_len_at_2) as usize;

    // Test truncation in header, in payload, and in commit trailer
    for cut in [
        2_usize,
        EPOCH_RECORD_HEADER_LEN - 1,
        EPOCH_RECORD_HEADER_LEN + 12,
        rec3_len - 5,
    ] {
        let cut_dir = fresh_dir(&format!("truncated-tail-cut-{cut}"))?;
        let cut_epochs = cut_dir.join("epochs");
        fs::create_dir_all(&cut_epochs)?;
        let cut_epoch0 = epoch_file_path(&cut_epochs, 0);
        fs::write(
            &cut_epoch0,
            &full_bytes[..committed_len_at_2 as usize + cut],
        )?;

        // Under Reject: refused with IncompleteTail at committed_len_at_2
        let rejected = MerkleEpochLedger::open(&cut_dir, SITE, cfg, IncompleteTailPolicy::Reject);
        assert!(
            matches!(
                rejected,
                Err(EpochLedgerError::IncompleteTail {
                    epoch_id: 0,
                    offset
                }) if offset == committed_len_at_2
            ),
            "expected IncompleteTail for cut={cut}, got {rejected:?}"
        );

        // Under Truncate: quarantines torn tail, truncates to committed_len_at_2, allows new commits
        let mut recovered =
            MerkleEpochLedger::open(&cut_dir, SITE, cfg, IncompleteTailPolicy::Truncate)?;
        assert_eq!(recovered.commit_sequence(), 2);
        assert_eq!(recovered.state_root(), root_at_2);
        assert_eq!(recovered.history_root(), hist_at_2);
        assert_eq!(fs::metadata(&cut_epoch0)?.len(), committed_len_at_2);
        let qpath = recovered
            .recovery_summary()
            .truncated_tail_quarantine
            .as_ref()
            .ok_or("missing quarantined tail path")?;
        assert!(qpath.exists());
        assert_eq!(fs::read(qpath)?.len(), cut);

        // Appending commit 3 after truncation succeeds and preserves full chain verification
        let r3 = append_create(&mut recovered, 3)?;
        assert_eq!(r3.sequence, 3);
        let proof = recovered.prove_object(&ObjectId::parse("object:obj-3")?)?;
        verify_proof(
            recovered.state_root(),
            &ObjectId::parse("object:obj-3")?,
            &proof,
        )?;
        let report = recovered.verify_full_chain()?;
        assert_eq!(report.batches_verified, 3);
    }

    // LEDGER-CRASH-001: arbitrary non-magic junk is Corrupt(RecordMagic) under BOTH policies!
    let junk_dir = fresh_dir("trailing-junk")?;
    let junk_epochs = junk_dir.join("epochs");
    fs::create_dir_all(&junk_epochs)?;
    let junk_epoch0 = epoch_file_path(&junk_epochs, 0);
    fs::write(&junk_epoch0, &full_bytes[..committed_len_at_2 as usize])?;
    {
        let mut f = OpenOptions::new().append(true).open(&junk_epoch0)?;
        f.write_all(b"JUNK_NON_MAGIC_BYTES")?;
        f.sync_all()?;
    }

    for policy in [IncompleteTailPolicy::Reject, IncompleteTailPolicy::Truncate] {
        let res = MerkleEpochLedger::open(&junk_dir, SITE, cfg, policy);
        assert!(
            matches!(
                res,
                Err(EpochLedgerError::CorruptEpoch {
                    epoch_id: 0,
                    offset,
                    kind: EpochCorruptionKind::RecordMagic,
                }) if offset == committed_len_at_2
            ),
            "expected CorruptEpoch(RecordMagic) under {policy:?}, got {res:?}"
        );
    }
    Ok(())
}

#[test]
fn verify_full_chain_detects_historical_epoch_tampering_behind_checkpoint() -> TestResult {
    let dir = fresh_dir("historical-tamper")?;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 3,
        checkpoint_stride: 3,
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    for i in 1..=6_u64 {
        append_create(&mut ledger, i)?;
    }
    drop(ledger);

    // Flip a payload byte in historical epoch 0 (already superseded by checkpoint at seq 6 in epoch 1)
    let epoch0 = epoch_file_path(&dir.join("epochs"), 0);
    let mut e0 = fs::read(&epoch0)?;
    e0[EPOCH_HEADER_LEN + EPOCH_RECORD_HEADER_LEN + 5] ^= 0xFF;
    fs::write(&epoch0, &e0)?;

    // Fast O(1) open from checkpoint seq 6 succeeds (does not re-scan epoch 0)
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), 6);

    // On-demand verify_full_chain scans from genesis and catches historical corruption!
    let verify_err = reopened.verify_full_chain();
    assert!(
        matches!(
            verify_err,
            Err(EpochLedgerError::CorruptEpoch {
                epoch_id: 0,
                kind: EpochCorruptionKind::PayloadChecksum,
                ..
            })
        ),
        "expected PayloadChecksum corruption in epoch 0, got {verify_err:?}"
    );
    Ok(())
}
