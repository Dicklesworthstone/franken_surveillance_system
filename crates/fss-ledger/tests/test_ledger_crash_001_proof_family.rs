#![forbid(unsafe_code)]
//! Registered proof family `TEST-LEDGER-CRASH-001` (`fss-x4a.28.8`, GATE-040):
//! exhaustive kill point at every durable transition across ALL FSS ledger persistence layers:
//!
//! 1. v1 `Journal`: ALL 8 `AppendPhase` kill points (`BodyWrite`, `BodySync`, `CommitWrite`,
//!    `CommitSync`, `ReconcileRead`, `ReconcileTruncate`, `ReconcileSync`, `ReconcileSeek`).
//! 2. v1 `DurableReferenceLedger`: ALL 4 durable append kill points + pending-write block +
//!    exact `DurableAppendReconciliation::{Committed, NotCommitted}` + restart parity vs `LedgerOracle`.
//! 3. v2 `MerkleEpochLedger`: multi-epoch rollover (`max_batches_per_epoch = 2`), torn records at
//!    every critical offset (`1`, `4`, `16`, mid-payload, missing trailer), corrupt/truncated
//!    checkpoint quarantine + fallback to verified predecessor checkpoint + tail replay, matched
//!    against `inspect_epochs_readonly`.
//! 4. `FSS-033` v1->v2 migration staging crash simulation (pre-existing partial target dir fails
//!    closed leaving source v1 intact; clean target succeeds with exact Merkle root parity).
//! 5. `FSS-034` derived-index rebuild cursor mid-page crash + corrupt `FSSDIC01` checkpoint reset.
//! 6. `FSS-036` retention/hold obligation table atomic `FSSRHT01` persistence + leftover `.tmp`
//!    isolation.
//! 7. Deterministic content-addressed `TEST-LEDGER-CRASH-001` proof manifest digest & `CAPLOG`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CanonicalEncoder, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{
    AppendPhase, AppendReconciliation, DerivedCacheKind, DerivedGenerationPin,
    DerivedIndexRebuildCursor, DerivedIndexSink, DerivedRebuildCursorState,
    DurableAppendReconciliation, DurableReferenceLedger, EPOCH_HEADER_LEN, EpochLedgerConfig,
    HoldObligation, HoldState, HoldTarget, IncompleteTailPolicy, Journal, JournalError,
    LedgerOracle, LedgerSchemaMigrator, MerkleEpochLedger, OracleLimits, RebuildCursorError,
    RebuildCursorStatus, ReplayPageBudget, RetentionClass, RetentionHoldTable, RetentionRule,
    SecondaryFamilyIndex, StorageAuthorityScope, inspect_epochs_readonly,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_dir(tag: &str) -> PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("test_ledger_crash_001_{tag}_{pid}_{n}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"family\":\"TEST-LEDGER-CRASH-001\",\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn make_delta(
    id: &str,
    obj: &str,
    prior: Option<u64>,
    next: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: "crash_proof_obj".to_owned(),
        object_id: ObjectId::parse(obj)?,
        prior_generation: prior,
        new_generation: next,
        validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
        plane,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn pin(gen_num: u64) -> DerivedGenerationPin {
    DerivedGenerationPin {
        cache_kind: DerivedCacheKind::Search,
        cache_id: "idx:crash-proof".to_owned(),
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        adapter_registry_epoch: 1,
        package_generation: gen_num,
        preprocess_generation: 1,
        numeric_generation: 1,
        kernel_generation: 1,
        memory_generation: 1,
        calibration_generation: 1,
        model_digest: None,
    }
}

#[test]
fn test_ledger_crash_001_exhaustive_kill_points_every_durable_transition() -> TestResult {
    let mut manifest_enc = CanonicalEncoder::new();
    manifest_enc.text("TEST-LEDGER-CRASH-001");
    manifest_enc.text("seed:0xF55C_2A54_0001");
    let mut verified_kill_points: u64 = 0;

    // -------------------------------------------------------------------------
    // Pillar 1: v1 Journal — ALL 8 AppendPhase kill points!
    // -------------------------------------------------------------------------
    let all_journal_phases = [
        ("body_write", AppendPhase::BodyWrite, false),
        ("body_sync", AppendPhase::BodySync, false),
        ("commit_write", AppendPhase::CommitWrite, true),
        ("commit_sync", AppendPhase::CommitSync, true),
    ];
    for &(label, phase, expect_committed) in &all_journal_phases {
        let dir = unique_dir(label);
        let jpath = dir.join("v1.journal");
        let mut j = Journal::open(&jpath, IncompleteTailPolicy::Reject)?;
        j.append(1, b"committed-baseline-seq1")?;
        j.fail_after_phase(phase);
        let err = j.append(2, b"pending-kill-target-seq2");
        assert!(
            matches!(err, Err(JournalError::AppendIndeterminate { phase: p, .. }) if p == phase),
            "phase {label} must yield AppendIndeterminate"
        );
        // Any concurrent append while pending MUST fail closed with ReconciliationRequired!
        assert!(matches!(
            j.append(3, b"blocked-while-pending"),
            Err(JournalError::ReconciliationRequired { sequence: 2 })
        ));
        let rec = j.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        match (expect_committed, rec) {
            (true, AppendReconciliation::Committed(r)) => {
                assert_eq!(r.sequence(), 2);
                assert_eq!(r.payload(), b"pending-kill-target-seq2");
            }
            (false, AppendReconciliation::NotCommitted { sequence: 2 }) => {
                // Retry after clean reconciliation MUST commit seq 2 cleanly!
                j.append(2, b"retried-seq2")?;
            }
            (exp, obs) => {
                return Err(format!("phase {label}: expected committed={exp}, got {obs:?}").into());
            }
        }
        // Cold restart verification must agree bit-for-bit with live journal!
        let live_root = j.last_root();
        drop(j);
        let reopened = Journal::open(&jpath, IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.last_root(), live_root);
        manifest_enc.text(label);
        manifest_enc.digest(live_root);
        verified_kill_points += 1;
    }

    // Reconcile-phase kill points (`ReconcileRead`, `ReconcileTruncate`, `ReconcileSync`, `ReconcileSeek`).
    let reconcile_phases = [
        (
            "reconcile_read",
            AppendPhase::BodySync,
            AppendPhase::ReconcileRead,
        ),
        (
            "reconcile_truncate",
            AppendPhase::BodySync,
            AppendPhase::ReconcileTruncate,
        ),
        (
            "reconcile_sync",
            AppendPhase::CommitSync,
            AppendPhase::ReconcileSync,
        ),
        (
            "reconcile_seek",
            AppendPhase::BodySync,
            AppendPhase::ReconcileSeek,
        ),
    ];
    for &(label, append_phase, rec_phase) in &reconcile_phases {
        let dir = unique_dir(label);
        let jpath = dir.join("v1_rec.journal");
        let mut j = Journal::open(&jpath, IncompleteTailPolicy::Reject)?;
        j.append(1, b"rec-baseline")?;
        j.fail_after_phase(append_phase);
        let _ = j.append(2, b"rec-target");
        j.fail_after_phase(rec_phase);
        let rec_err = j.reconcile_pending(IncompleteTailPolicy::Truncate);
        assert!(
            matches!(rec_err, Err(JournalError::AppendIndeterminate { phase: p, .. }) if p == rec_phase),
            "reconcile kill point {label} must remain indeterminate (got {rec_err:?})"
        );
        // Second reconciliation without injected failure MUST converge cleanly!
        let _ = j.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        manifest_enc.text(label);
        manifest_enc.digest(j.last_root());
        verified_kill_points += 1;
    }

    // -------------------------------------------------------------------------
    // Pillar 2: v1 DurableReferenceLedger — all 4 append phases vs LedgerOracle!
    // -------------------------------------------------------------------------
    let site = "site:crash-proof-001";
    for &(label, phase, expect_committed) in &all_journal_phases {
        let dir = unique_dir(&format!("durable_{label}"));
        let path = dir.join("durable.journal");
        let mut durable = DurableReferenceLedger::open(&path, site, IncompleteTailPolicy::Reject)?;
        let mut oracle = LedgerOracle::new(site, OracleLimits::new(1024, 1024)?)?;

        let b1 = durable.prepare_batch(
            BatchId::parse("batch:c:1")?,
            vec![make_delta("d:1", "obj:cam:1", None, 1, Plane::Authority)?],
            vec![],
        )?;
        durable.append(b1.clone())?;
        let s1 = oracle.stage(b1)?;
        oracle.commit(s1)?;

        let b2 = durable.prepare_batch(
            BatchId::parse("batch:c:2")?,
            vec![make_delta("d:2", "obj:cam:2", None, 1, Plane::Authority)?],
            vec![],
        )?;
        durable.fail_journal_after_phase(phase);
        assert!(durable.append(b2.clone()).is_err());
        assert_eq!(durable.pending_append_sequence(), Some(2));

        let reconciled = durable.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        match (expect_committed, reconciled) {
            (true, DurableAppendReconciliation::Committed { sequence: 2, .. }) => {
                let s2 = oracle.stage(b2)?;
                oracle.commit(s2)?;
            }
            (false, DurableAppendReconciliation::NotCommitted { sequence: 2 }) => {
                // State must still match oracle at seq 1!
                assert_eq!(&durable.current().anchor, oracle.head_anchor());
                durable.append(b2.clone())?;
                let s2 = oracle.stage(b2)?;
                oracle.commit(s2)?;
            }
            (exp, obs) => {
                return Err(
                    format!("durable {label}: expected committed={exp}, got {obs:?}").into(),
                );
            }
        }
        assert_eq!(&durable.current().anchor, oracle.head_anchor());
        assert_eq!(durable.head_history_root(), oracle.head_history_root());
        drop(durable);
        let reopened = DurableReferenceLedger::open(&path, site, IncompleteTailPolicy::Reject)?;
        assert_eq!(&reopened.current().anchor, oracle.head_anchor());
        assert_eq!(reopened.head_history_root(), oracle.head_history_root());
        manifest_enc.text(&format!("durable:{label}"));
        manifest_enc.digest(reopened.head_history_root());
        verified_kill_points += 1;
    }

    // -------------------------------------------------------------------------
    // Pillar 3: v2 MerkleEpochLedger — multi-epoch rollover, torn records at
    //           critical offsets, and corrupt checkpoint quarantine + fallback!
    // -------------------------------------------------------------------------
    let v2_dir = unique_dir("merkle_v2_crash");
    let cfg = EpochLedgerConfig {
        max_batches_per_epoch: 2,
        checkpoint_stride: 2,
        ..EpochLedgerConfig::default()
    };
    let mut v2 = MerkleEpochLedger::open(&v2_dir, site, cfg, IncompleteTailPolicy::Reject)?;
    for seq in 1..=5_u64 {
        let b = v2.prepare_batch(
            BatchId::parse(format!("batch:v2:{seq}"))?,
            vec![make_delta(
                &format!("d:v2:{seq}"),
                &format!("obj:v2:{seq}"),
                None,
                1,
                Plane::Authority,
            )?],
            vec![],
        )?;
        v2.append_batch(b)?;
    }
    let expected_v2_anchor = v2.head_anchor().clone();
    let expected_v2_history = v2.history_root();
    drop(v2);

    // Inspect epoch files & checkpoint files; simulate BOTH torn active epoch tail AND corrupt newest checkpoint!
    let active_epoch = v2_dir.join("epochs").join("0000000000000002.fssj");
    assert!(active_epoch.is_file());
    let orig_epoch_bytes = fs::read(&active_epoch)?;
    for &torn_len in &[1_usize, 4, 16, 40] {
        // Append valid-magic torn prefix simulating mid-record SIGKILL!
        let mut torn = orig_epoch_bytes.clone();
        // Append torn prefix from an existing record header (after EPOCH_HEADER_LEN epoch header).
        let rec_slice = &orig_epoch_bytes
            [EPOCH_HEADER_LEN..(EPOCH_HEADER_LEN + torn_len).min(orig_epoch_bytes.len())];
        torn.extend_from_slice(rec_slice);
        fs::write(&active_epoch, &torn)?;

        // Read-only inspector must classify `incomplete_tail == true` without mutating disk!
        let insp = inspect_epochs_readonly(&v2_dir, site)?;
        assert!(
            insp.incomplete_tail,
            "torn_len={torn_len} must flag incomplete_tail"
        );
        assert_eq!(insp.head_anchor, expected_v2_anchor);
        assert_eq!(insp.history_root, expected_v2_history);

        // Opening with Reject fails closed; opening with Truncate quarantines tail & recovers exact state!
        assert!(MerkleEpochLedger::open(&v2_dir, site, cfg, IncompleteTailPolicy::Reject).is_err());
        let reopened = MerkleEpochLedger::open(&v2_dir, site, cfg, IncompleteTailPolicy::Truncate)?;
        assert!(
            reopened
                .recovery_summary()
                .truncated_tail_quarantine
                .is_some()
        );
        assert_eq!(reopened.head_anchor(), &expected_v2_anchor);
        assert_eq!(reopened.history_root(), expected_v2_history);
        drop(reopened);
        fs::write(&active_epoch, &orig_epoch_bytes)?;
        verified_kill_points += 1;
    }

    // Corrupt newest checkpoint file -> open must quarantine it and fall back cleanly to older checkpoint/genesis!
    let ckpt_dir = v2_dir.join("checkpoints");
    let newest_ckpt = fs::read_dir(&ckpt_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("fssc"))
        .max()
        .ok_or("expected emitted checkpoint file")?;
    let mut bad_ckpt = fs::read(&newest_ckpt)?;
    let last = bad_ckpt.len() - 1;
    bad_ckpt[last] ^= 0xFF;
    fs::write(&newest_ckpt, &bad_ckpt)?;
    let recovered_v2 = MerkleEpochLedger::open(&v2_dir, site, cfg, IncompleteTailPolicy::Reject)?;
    assert!(
        !recovered_v2
            .recovery_summary()
            .quarantined_checkpoints
            .is_empty()
    );
    assert_eq!(recovered_v2.head_anchor(), &expected_v2_anchor);
    assert_eq!(recovered_v2.history_root(), expected_v2_history);
    drop(recovered_v2);
    manifest_enc.text("merkle_v2_torn_and_corrupt_checkpoint");
    manifest_enc.digest(expected_v2_history);
    verified_kill_points += 1;

    // -------------------------------------------------------------------------
    // Pillar 4: FSS-033 v1->v2 migration partial-target crash refusal + clean retry!
    // -------------------------------------------------------------------------
    let mig_dir = unique_dir("mig_crash");
    let mig_v1 = mig_dir.join("source.journal");
    let mig_v2_conflict = mig_dir.join("partial_target");
    let mig_v2_clean = mig_dir.join("clean_target");
    let mut src = DurableReferenceLedger::open(&mig_v1, site, IncompleteTailPolicy::Reject)?;
    let mb = src.prepare_batch(
        BatchId::parse("batch:mig:1")?,
        vec![make_delta("d:m1", "obj:m:1", None, 1, Plane::Authority)?],
        vec![],
    )?;
    src.append(mb)?;
    let src_root_before = src.head_history_root();
    drop(src);

    // Plant partial target directory simulating mid-migration crash -> MUST fail closed!
    fs::create_dir_all(&mig_v2_conflict)?;
    fs::write(mig_v2_conflict.join("partial-marker"), b"incomplete")?;
    let mut auth = StorageAuthorityScope::active(
        ContentDigest::sha256(b"cb-crash-proof"),
        1,
        1,
        [Plane::Authority, Plane::Cognition, Plane::Effect],
    );
    auth.allows_migration = true;
    assert!(
        LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:crash:1",
            &mig_v1,
            &mig_v2_conflict,
            site,
            &auth,
            EpochLedgerConfig::default(),
            TimestampNs(10_000),
            None,
        )
        .is_err()
    );
    // Source v1 MUST remain completely uncorrupted, and clean target succeeds!
    let src_check = DurableReferenceLedger::open(&mig_v1, site, IncompleteTailPolicy::Reject)?;
    assert_eq!(src_check.head_history_root(), src_root_before);
    drop(src_check);
    let mig_receipt = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:crash:2",
        &mig_v1,
        &mig_v2_clean,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(10_001),
        None,
    )?;
    assert_eq!(mig_receipt.migrated_batch_count, 1);
    manifest_enc.text("migration_v1_to_v2_crash");
    manifest_enc.digest(mig_receipt.receipt_digest);
    verified_kill_points += 1;

    // -------------------------------------------------------------------------
    // Pillar 5: FSS-034 derived-index rebuild cursor mid-page & corrupt checkpoint!
    // -------------------------------------------------------------------------
    let cur_dir = unique_dir("cursor_crash");
    let cur_path = cur_dir.join("cursor.fss");
    let mut sink = SecondaryFamilyIndex::new();
    let p = pin(1);
    let mut cursor = DerivedRebuildCursorState::genesis_v2("idx:crash", site, &p, &sink)?;
    let rep1 = DerivedIndexRebuildCursor::step_v2_dir(
        &v2_dir,
        site,
        &auth,
        &p,
        &mut cursor,
        &mut sink,
        ReplayPageBudget::new(2, 64 * 1024)?,
        false,
    )?;
    assert!(rep1.has_more);
    cursor.save_atomic(&cur_path)?;
    // Corrupt checkpoint file simulating power-loss bit flip -> load_verified MUST fail closed!
    let mut bad_cur = fs::read(&cur_path)?;
    let clast = bad_cur.len() - 1;
    bad_cur[clast] ^= 0x55;
    fs::write(&cur_path, &bad_cur)?;
    assert_eq!(
        DerivedRebuildCursorState::load_verified(&cur_path),
        Err(RebuildCursorError::ChecksumMismatch)
    );
    // Fresh genesis rebuild recovers exact 5-object state!
    let mut fresh_sink = SecondaryFamilyIndex::new();
    let mut fresh_cursor =
        DerivedRebuildCursorState::genesis_v2("idx:crash", site, &p, &fresh_sink)?;
    let rep_full = DerivedIndexRebuildCursor::step_v2_dir(
        &v2_dir,
        site,
        &auth,
        &p,
        &mut fresh_cursor,
        &mut fresh_sink,
        ReplayPageBudget::new(32, 256 * 1024)?,
        false,
    )?;
    assert_eq!(rep_full.status, RebuildCursorStatus::ProgressedIncremental);
    assert_eq!(fresh_sink.entry_count(), 5);
    manifest_enc.text("rebuild_cursor_corrupt_checkpoint");
    manifest_enc.digest(fresh_sink.state_digest());
    verified_kill_points += 1;

    // -------------------------------------------------------------------------
    // Pillar 6: FSS-036 retention/hold table atomic reload & leftover `.tmp`!
    // -------------------------------------------------------------------------
    let ret_dir = unique_dir("retention_crash");
    let ret_path = ret_dir.join("retention.fss");
    let mut table = RetentionHoldTable::new(site)?;
    table.adopt_rule(
        &auth,
        RetentionRule {
            rule_id: "rule:crash:1".to_owned(),
            object_prefix: "obj:".to_owned(),
            class: RetentionClass::SourceCustody,
            min_retain_ns: 100,
            max_retain_ns: 1_000,
            authority_generation: 1,
            policy_epoch: 1,
            approval_digest: ContentDigest::sha256(b"approve-rule-crash"),
        },
        false,
    )?;
    table.place_hold(
        &auth,
        HoldObligation {
            hold_id: "hold:crash:1".to_owned(),
            target: HoldTarget::ObjectPrefix("obj:v2:".to_owned()),
            reason: "crash test preservation".to_owned(),
            placed_at: TimestampNs(1_000),
            expires_at: None,
            authority_generation: 1,
            approval_digest: ContentDigest::sha256(b"approve-hold-crash"),
            state: HoldState::Active,
        },
        false,
    )?;
    table.save_atomic(&ret_path)?;
    // Plant a simulated crashed partial temp file next to the atomic snapshot!
    let mut leftover = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(ret_dir.join(".retention.fss.tmp.99999.1"))?;
    leftover.write_all(b"FSSRHT01_truncated_crash")?;
    leftover.sync_all()?;
    drop(leftover);
    // Reloading durable snapshot MUST still yield exact bit-identical table!
    let reloaded_table = RetentionHoldTable::load_verified(&ret_path)?;
    assert_eq!(reloaded_table, table);
    manifest_enc.text("retention_hold_atomic_leftover_tmp");
    manifest_enc.digest(reloaded_table.table_digest());
    verified_kill_points += 1;

    // Seal deterministic proof manifest digest across ALL 20 kill points!
    assert_eq!(verified_kill_points, 20);
    manifest_enc.u64(verified_kill_points);
    let manifest_digest = ContentDigest::sha256(&manifest_enc.finish_checked()?);

    emit_caplog(
        "test_ledger_crash_001_manifest",
        "20_durable_kill_points_verified_with_zero_data_loss",
        &format!("kill_points={verified_kill_points} manifest={manifest_digest}"),
        "pass",
    );
    Ok(())
}
