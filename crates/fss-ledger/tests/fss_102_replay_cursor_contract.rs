#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-102` (`fss-x4a.9.9`):
//! Single-thread reference delta ledger and anchor-pinned bounded `LedgerReplayCursor`.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableAppendReconciliation, DurableReferenceLedger, IncompleteTailPolicy,
    LEDGER_REPLAY_CURSOR_VERSION, LedgerOracle, LedgerReplayCursor, MAX_REPLAY_CURSOR_BYTES,
    MAX_REPLAY_PAGE_BATCHES, MAX_REPLAY_PAGE_BYTES, OracleLimits, ReplayCursorError,
    ReplayCursorGuidance, ReplayPageBudget, encode_batch,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..32 {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("fss-102-cursor-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn make_delta(
    delta_id: &str,
    family: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
    payload: &str,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: family.to_owned(),
        object_id: ObjectId::parse(object_id)?,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        plane,
        payload_digest: d(payload),
        witness_digest: Some(d(&format!("wit:{delta_id}"))),
        operation_id: None,
    })
}

fn populate_reference_history(
    oracle: &mut LedgerOracle,
    durable: &mut DurableReferenceLedger,
    count: u64,
) -> TestResult {
    for seq in 1..=count {
        let deltas = vec![
            make_delta(
                &format!("d-auth-{seq}"),
                "source_evidence",
                &format!("obj:cam-{seq}"),
                None,
                1,
                Plane::Authority,
                &format!("payload-auth-{seq}"),
            )?,
            make_delta(
                &format!("d-cog-{seq}"),
                "world_fact",
                "obj:shared-counter",
                if seq == 1 { None } else { Some(seq - 1) },
                seq,
                Plane::Cognition,
                &format!("payload-cog-{seq}"),
            )?,
        ];
        let batch = oracle.prepare_batch(
            BatchId::parse(format!("batch:fss102-{seq:03}"))?,
            deltas,
            vec![d(&format!("child-{seq}-a")), d(&format!("child-{seq}-b"))],
        )?;
        oracle.append(batch.clone())?;
        durable.append(batch)?;
    }
    Ok(())
}

#[test]
fn paginated_cursor_replay_matches_oracle_and_durable_across_page_sizes_and_restart() -> TestResult
{
    let dir = TempDir::new()?;
    let journal_path = dir.0.join("fss102.journal");

    let mut oracle = LedgerOracle::new("site-fss-102", OracleLimits::CEILING)?;
    let mut durable =
        DurableReferenceLedger::open(&journal_path, "site-fss-102", IncompleteTailPolicy::Reject)?;
    populate_reference_history(&mut oracle, &mut durable, 9)?;

    // Cold reopen durable ledger from disk.
    drop(durable);
    let durable =
        DurableReferenceLedger::open(&journal_path, "site-fss-102", IncompleteTailPolicy::Reject)?;

    // Genesis cursors from both engines must be bit-identical.
    let oracle_genesis = oracle.replay_cursor_genesis()?;
    let durable_genesis = durable.replay_cursor_genesis()?;
    assert_eq!(oracle_genesis, durable_genesis);
    assert_eq!(
        oracle_genesis.to_canonical_bytes()?,
        durable_genesis.to_canonical_bytes()?
    );

    // Replay across multiple page sizes, round-tripping cursor wire bytes at every page boundary,
    // and alternating between LedgerOracle and DurableReferenceLedger on alternating pages!
    for page_size in [1usize, 2, 3, 7, 100] {
        let budget = ReplayPageBudget::new(page_size, MAX_REPLAY_PAGE_BYTES)?;
        let mut cursor_bytes = oracle_genesis.to_canonical_bytes()?;
        let mut collected = Vec::new();
        let mut page_index = 0usize;
        let mut total_bytes = 0u64;

        loop {
            let cursor = LedgerReplayCursor::from_canonical_bytes(&cursor_bytes)?;
            let page = if page_index % 2 == 0 {
                oracle.replay_page(&cursor, budget, false)?
            } else {
                durable.replay_page(&cursor, budget, false)?
            };
            assert_eq!(page.start_cursor, cursor);
            assert!(page.batches.len() <= page_size);
            total_bytes += page.bytes_accounted;
            collected.extend(page.batches.iter().cloned());
            cursor_bytes = page.next_cursor.to_canonical_bytes()?;
            page_index += 1;

            if page.complete {
                assert!(!page.has_more);
                assert_eq!(page.remaining_batches, 0);
                assert_eq!(page.next_cursor.last_anchor(), oracle.head_anchor());
                assert_eq!(page.next_cursor.history_root(), oracle.head_history_root());
                break;
            }
            assert!(page.has_more);
            assert!(page.remaining_batches > 0);
        }

        // Rebuild a fresh oracle purely from cursor-replayed batches and assert bit-identical state.
        let rebuilt = LedgerOracle::rebuild("site-fss-102", OracleLimits::CEILING, collected)?;
        assert_eq!(rebuilt.fingerprint(), oracle.fingerprint());
        assert!(total_bytes > 0);

        // One more replay at head returns empty complete page with unchanged cursor.
        let head_cursor = LedgerReplayCursor::from_canonical_bytes(&cursor_bytes)?;
        let tail_page = durable.replay_page(&head_cursor, budget, false)?;
        assert!(tail_page.batches.is_empty());
        assert!(tail_page.complete);
        assert!(!tail_page.has_more);
        assert_eq!(tail_page.next_cursor, head_cursor);
    }

    // Tight byte-budget pacing: set byte budget just large enough for one batch at a time.
    let first_batch_len = encode_batch(&durable.batches()[0])?.len() as u64;
    let tight_budget = ReplayPageBudget::new(64, first_batch_len + 16)?;
    let page1 = oracle.replay_page(&oracle_genesis, tight_budget, false)?;
    assert_eq!(page1.batches.len(), 1);
    assert_eq!(page1.bytes_accounted, first_batch_len);
    assert!(page1.has_more);
    assert!(!page1.complete);

    emit_caplog(
        "fss102_paginated_cross_engine_cursor_replay",
        "bit_identical_across_page_sizes_engines_and_restart",
        "bit_identical_across_page_sizes_engines_and_restart",
        "pass",
    );
    Ok(())
}

#[test]
fn cursor_faults_cancellation_indeterminate_isolation_and_wire_hostility_fail_closed() -> TestResult
{
    let dir = TempDir::new()?;
    let journal_path = dir.0.join("fss102-faults.journal");

    let mut oracle = LedgerOracle::new("site-fss-102-faults", OracleLimits::CEILING)?;
    let mut durable = DurableReferenceLedger::open(
        &journal_path,
        "site-fss-102-faults",
        IncompleteTailPolicy::Reject,
    )?;
    populate_reference_history(&mut oracle, &mut durable, 4)?;

    // 1. Invalid budget refusal.
    assert!(matches!(
        ReplayPageBudget::new(0, 1024),
        Err(ReplayCursorError::InvalidBudget { .. })
    ));
    assert!(matches!(
        ReplayPageBudget::new(MAX_REPLAY_PAGE_BATCHES + 1, 1024),
        Err(ReplayCursorError::InvalidBudget { .. })
    ));
    assert!(matches!(
        ReplayPageBudget::new(1, 0),
        Err(ReplayCursorError::InvalidBudget { .. })
    ));
    assert!(matches!(
        ReplayPageBudget::new(1, MAX_REPLAY_PAGE_BYTES + 1),
        Err(ReplayCursorError::InvalidBudget { .. })
    ));

    let valid_budget = ReplayPageBudget::new(2, MAX_REPLAY_PAGE_BYTES)?;
    let cur2 = oracle.replay_cursor_at(2)?;

    // 2. Cooperative cancellation returns Cancelled with RetryFromCursor and zero advance.
    let cancel_err = oracle
        .replay_page(&cur2, valid_budget, true)
        .expect_err("cancelled replay must fail closed");
    assert_eq!(
        cancel_err,
        ReplayCursorError::Cancelled { cursor_sequence: 2 }
    );
    assert_eq!(cancel_err.guidance(), ReplayCursorGuidance::RetryFromCursor);

    // 3. BatchExceedsByteBudget prevents 0-progress infinite loops.
    let tiny_budget = ReplayPageBudget::new(4, 16)?;
    let byte_err = oracle
        .replay_page(&cur2, tiny_budget, false)
        .expect_err("batch exceeding byte budget must fail loudly");
    assert!(matches!(
        byte_err,
        ReplayCursorError::BatchExceedsByteBudget { sequence: 3, .. }
    ));
    assert_eq!(
        byte_err.guidance(),
        ReplayCursorGuidance::IncreaseByteBudget
    );

    // 4. Lineage mismatch, epoch mismatch, cursor ahead of head, and forked/tampered anchor.
    let mut other_oracle = LedgerOracle::new("site-other", OracleLimits::CEILING)?;
    let other_cur = other_oracle.replay_cursor_genesis()?;
    let lin_err = oracle
        .replay_page(&other_cur, valid_budget, false)
        .expect_err("lineage mismatch must fail");
    assert!(matches!(lin_err, ReplayCursorError::LineageMismatch { .. }));
    assert_eq!(
        lin_err.guidance(),
        ReplayCursorGuidance::ResnapshotFromGenesis
    );

    let mut wrong_epoch_anchor = cur2.last_anchor().clone();
    wrong_epoch_anchor.ledger_epoch = 99;
    let wrong_epoch_cur = LedgerReplayCursor::new(wrong_epoch_anchor, cur2.history_root())?;
    let epoch_err = oracle
        .replay_page(&wrong_epoch_cur, valid_budget, false)
        .expect_err("epoch mismatch must fail");
    assert!(matches!(
        epoch_err,
        ReplayCursorError::EpochMismatch {
            expected: 0,
            supplied: 99
        }
    ));

    let mut ahead_anchor = cur2.last_anchor().clone();
    ahead_anchor.commit_sequence = 99;
    let ahead_cur = LedgerReplayCursor::new(ahead_anchor, cur2.history_root())?;
    let ahead_err = oracle
        .replay_page(&ahead_cur, valid_budget, false)
        .expect_err("cursor ahead of head must fail");
    assert!(matches!(
        ahead_err,
        ReplayCursorError::CursorAheadOfHead {
            cursor_sequence: 99,
            head_sequence: 4
        }
    ));
    assert_eq!(
        ahead_err.guidance(),
        ReplayCursorGuidance::ResnapshotOrWaitForReplication
    );

    // Forked state_root at sequence 2.
    let mut forked_anchor = cur2.last_anchor().clone();
    forked_anchor.state_root = d("forked-state-root");
    let forked_cur = LedgerReplayCursor::new(forked_anchor, cur2.history_root())?;
    assert!(matches!(
        oracle.replay_page(&forked_cur, valid_budget, false),
        Err(ReplayCursorError::DivergentAnchor { sequence: 2 })
    ));

    // Forked history_root at sequence 2 (even with matching anchor).
    let forked_hist_cur =
        LedgerReplayCursor::new(cur2.last_anchor().clone(), d("forked-history-root"))?;
    assert!(matches!(
        durable.replay_page(&forked_hist_cur, valid_budget, false),
        Err(ReplayCursorError::DivergentAnchor { sequence: 2 })
    ));

    // 5. Indeterminate durable append isolation: pending reconciliation blocks replay until resolved.
    let next_batch = durable.prepare_batch(
        BatchId::parse("batch:fss102-indet-5")?,
        vec![make_delta(
            "d-indet-5",
            "source_evidence",
            "obj:cam-5",
            None,
            1,
            Plane::Authority,
            "payload-indet-5",
        )?],
        vec![d("child-5")],
    )?;
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(durable.append(next_batch).is_err());
    assert_eq!(durable.pending_append_sequence(), Some(5));

    let pend_err = durable
        .replay_page(&cur2, valid_budget, false)
        .expect_err("pending indeterminate append must block replay");
    assert_eq!(
        pend_err,
        ReplayCursorError::PendingReconciliation { sequence: 5 }
    );
    assert_eq!(
        pend_err.guidance(),
        ReplayCursorGuidance::ReconcilePendingAppend
    );

    // Reconcile pending append -> replay immediately resumes cleanly and sees sequence 5!
    let rec = durable.reconcile_pending(IncompleteTailPolicy::Reject)?;
    assert!(matches!(
        rec,
        DurableAppendReconciliation::Committed { sequence: 5, .. }
    ));
    let resumed_page = durable.replay_page(
        &cur2,
        ReplayPageBudget::new(8, MAX_REPLAY_PAGE_BYTES)?,
        false,
    )?;
    assert_eq!(resumed_page.batches.len(), 3);
    assert_eq!(resumed_page.head_anchor.commit_sequence, 5);
    assert!(resumed_page.complete);

    // 6. Hostile cursor wire bytes: bad magic, unsupported version, truncation, checksum flip,
    //    trailing garbage, and oversize payload.
    let valid_wire = cur2.to_canonical_bytes()?;
    assert_eq!(LedgerReplayCursor::from_canonical_bytes(&valid_wire)?, cur2);

    let mut bad_magic = valid_wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        LedgerReplayCursor::from_canonical_bytes(&bad_magic),
        Err(ReplayCursorError::InvalidMagic)
    );

    let mut bad_ver = valid_wire.clone();
    bad_ver[8..12].copy_from_slice(&(LEDGER_REPLAY_CURSOR_VERSION + 1).to_be_bytes());
    assert_eq!(
        LedgerReplayCursor::from_canonical_bytes(&bad_ver),
        Err(ReplayCursorError::UnsupportedVersion {
            version: LEDGER_REPLAY_CURSOR_VERSION + 1
        })
    );

    assert!(matches!(
        LedgerReplayCursor::from_canonical_bytes(&valid_wire[..valid_wire.len() - 4]),
        Err(ReplayCursorError::TruncatedOrMalformed(_))
    ));

    let mut flipped = valid_wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        LedgerReplayCursor::from_canonical_bytes(&flipped),
        Err(ReplayCursorError::ChecksumMismatch)
    );

    let mut trailing = valid_wire;
    trailing.push(0x00);
    assert!(matches!(
        LedgerReplayCursor::from_canonical_bytes(&trailing),
        Err(ReplayCursorError::TruncatedOrMalformed(_))
    ));

    let oversize = vec![0u8; MAX_REPLAY_CURSOR_BYTES + 1];
    assert!(matches!(
        LedgerReplayCursor::from_canonical_bytes(&oversize),
        Err(ReplayCursorError::BoundsExceeded { .. })
    ));

    // Avoid unused mut warning on other_oracle by appending one batch and confirming still mismatched.
    let ob = other_oracle.prepare_batch(
        BatchId::parse("batch:other-1")?,
        vec![make_delta(
            "d-other-1",
            "source_evidence",
            "obj:other-1",
            None,
            1,
            Plane::Authority,
            "payload-other",
        )?],
        vec![],
    )?;
    other_oracle.append(ob)?;
    assert_eq!(other_oracle.head_sequence(), 1);

    emit_caplog(
        "fss102_cursor_faults_cancel_indeterminate_and_wire",
        "all_fault_classes_fail_closed_with_typed_guidance",
        "all_fault_classes_fail_closed_with_typed_guidance",
        "pass",
    );
    Ok(())
}
