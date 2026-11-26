#![forbid(unsafe_code)]
//! Contract, crash-resumable pagination, generation-drift reset, v1/v2 equivalence, fault, and
//! wire tests for `FSS-034` (`fss-x4a.9.4`: derived-index rebuild cursor).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DERIVED_REBUILD_CURSOR_MAGIC, DERIVED_REBUILD_CURSOR_VERSION, DerivedCacheKind,
    DerivedGenerationPin, DerivedIndexRebuildCursor, DerivedIndexSink, DerivedRebuildCursorState,
    DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy,
    LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN, LedgerSchemaMigrator, RebuildCursorError,
    RebuildCursorStatus, ReplayPageBudget, SecondaryFamilyIndex, StorageAuthorityScope,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fss_034_{tag}_{pid}_{n}"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn make_delta(
    id: &str,
    family: &str,
    obj: &str,
    prior: Option<u64>,
    next: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: family.to_owned(),
        object_id: ObjectId::parse(obj)?,
        prior_generation: prior,
        new_generation: next,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(500))?,
        plane,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn pin(pkg_gen: u64) -> DerivedGenerationPin {
    DerivedGenerationPin {
        cache_kind: DerivedCacheKind::Search,
        cache_id: "idx:secondary:family".to_owned(),
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        adapter_registry_epoch: 1,
        package_generation: pkg_gen,
        preprocess_generation: 1,
        numeric_generation: 1,
        kernel_generation: 1,
        memory_generation: 1,
        calibration_generation: 1,
        model_digest: None,
    }
}

#[test]
fn resumable_paged_rebuild_matches_full_genesis_on_v1_and_v2_and_resets_on_drift() -> TestResult {
    assert_eq!(
        LEDGER_DERIVED_REBUILD_CURSOR_DOMAIN,
        "fss.ledger_derived_rebuild_cursor.v1"
    );

    let base = unique_tmp_dir("v1_v2_rebuild");
    let v1_path = base.join("v1.journal");
    let v2_dir = base.join("v2-epochs");
    let ckpt_path = base.join("cursor.fss");
    let site = "site:fss-034-rebuild";

    // Populate 4 canonical batches in a live v1 DurableReferenceLedger.
    let mut v1 = DurableReferenceLedger::open(&v1_path, site, IncompleteTailPolicy::Reject)?;
    let b1 = v1.prepare_batch(
        BatchId::parse("batch:r:1")?,
        vec![
            make_delta(
                "d:1",
                "camera_config",
                "obj:cam:1",
                None,
                1,
                Plane::Authority,
            )?,
            make_delta(
                "d:2",
                "camera_config",
                "obj:cam:2",
                None,
                1,
                Plane::Authority,
            )?,
        ],
        vec![],
    )?;
    v1.append(b1)?;
    let b2 = v1.prepare_batch(
        BatchId::parse("batch:r:2")?,
        vec![make_delta(
            "d:3",
            "event_hypothesis",
            "obj:evt:1",
            None,
            1,
            Plane::Cognition,
        )?],
        vec![],
    )?;
    v1.append(b2)?;
    let b3 = v1.prepare_batch(
        BatchId::parse("batch:r:3")?,
        vec![make_delta(
            "d:4",
            "camera_config",
            "obj:cam:1",
            Some(1),
            2,
            Plane::Authority,
        )?],
        vec![],
    )?;
    v1.append(b3)?;
    let b4 = v1.prepare_batch(
        BatchId::parse("batch:r:4")?,
        vec![make_delta(
            "d:5",
            "alert_plan",
            "obj:eff:1",
            None,
            1,
            Plane::Effect,
        )?],
        vec![],
    )?;
    v1.append(b4)?;

    // Build independent fresh single-shot genesis oracle index!
    let mut oracle_sink = SecondaryFamilyIndex::new();
    for batch in v1.batches() {
        oracle_sink.apply_batch(batch);
    }
    let oracle_digest = oracle_sink.state_digest();
    assert_eq!(oracle_sink.entry_count(), 4);

    // 1. Step 1 batch at a time with durable checkpoint save & reload after EVERY step!
    let cb = ContentDigest::sha256(b"cb-fss-034");
    let mut auth = StorageAuthorityScope::active(
        cb,
        1,
        1,
        [Plane::Authority, Plane::Cognition, Plane::Effect],
    );
    let pin_v1 = pin(1);
    let mut sink = SecondaryFamilyIndex::new();
    let mut cursor = DerivedRebuildCursorState::genesis("idx:fam", site, &pin_v1, &sink)?;
    assert!(!cursor.grants_effect_authority());

    let page_1 = ReplayPageBudget::new(1, 64 * 1024)?;
    for expected_seq in 1..=4_u64 {
        let rep = DerivedIndexRebuildCursor::step_v1(
            &v1,
            &auth,
            &pin_v1,
            &mut cursor,
            &mut sink,
            page_1,
            false,
        )?;
        assert_eq!(rep.status, RebuildCursorStatus::ProgressedIncremental);
        assert_eq!(rep.batches_applied, 1);
        assert_eq!(cursor.applied_anchor.commit_sequence, expected_seq);
        assert_eq!(rep.has_more, expected_seq < 4);
        cursor.save_atomic(&ckpt_path)?;
        cursor = DerivedRebuildCursorState::load_verified(&ckpt_path)?;
    }

    // Next step reports UpToDate with 0 batches applied and bit-exact oracle index digest!
    let caught_up = DerivedIndexRebuildCursor::step_v1(
        &v1,
        &auth,
        &pin_v1,
        &mut cursor,
        &mut sink,
        page_1,
        false,
    )?;
    assert_eq!(caught_up.status, RebuildCursorStatus::UpToDate);
    assert_eq!(caught_up.batches_applied, 0);
    assert!(!caught_up.has_more);
    assert_eq!(sink.state_digest(), oracle_digest);
    assert_eq!(
        sink.lookup_family(Plane::Authority, "camera_config").len(),
        2
    );

    // 2. Generation drift (`package_generation: 1 -> 2`) triggers automatic genesis reset & rebuild!
    let pin_v2 = pin(2);
    let rebuilt = DerivedIndexRebuildCursor::step_v1(
        &v1,
        &auth,
        &pin_v2,
        &mut cursor,
        &mut sink,
        ReplayPageBudget::new(16, 256 * 1024)?,
        false,
    )?;
    assert_eq!(rebuilt.status, RebuildCursorStatus::RebuiltFromGenesis);
    assert_eq!(rebuilt.batches_applied, 4);
    assert_eq!(cursor.rebuild_epoch, 1);
    assert_eq!(sink.state_digest(), oracle_digest);

    // 3. Migrate v1 -> v2 MerkleEpochLedger (`FSS-033`) and prove v2 rebuild cursor yields IDENTICAL digest!
    drop(v1);
    auth.allows_migration = true;
    let _mig = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:fss-034:v2",
        &v1_path,
        &v2_dir,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(50_000),
        None,
    )?;
    let mut v2_sink = SecondaryFamilyIndex::new();
    let mut v2_cursor =
        DerivedRebuildCursorState::genesis_v2("idx:fam:v2", site, &pin_v2, &v2_sink)?;
    let v2_rep = DerivedIndexRebuildCursor::step_v2_dir(
        &v2_dir,
        site,
        &auth,
        &pin_v2,
        &mut v2_cursor,
        &mut v2_sink,
        ReplayPageBudget::new(16, 256 * 1024)?,
        false,
    )?;
    assert_eq!(v2_rep.status, RebuildCursorStatus::ProgressedIncremental);
    assert_eq!(v2_rep.batches_applied, 4);
    assert!(!v2_rep.has_more);
    assert_eq!(v2_sink.state_digest(), oracle_digest);

    emit_caplog(
        "fss_034_paged_rebuild_v1_v2_and_drift_reset",
        "v1_v2_crash_resumable_rebuild_and_drift_reset_matched_oracle_digest",
        "v1_v2_crash_resumable_rebuild_and_drift_reset_matched_oracle_digest",
        "pass",
    );
    Ok(())
}

#[test]
fn rebuild_cursor_pending_cancel_budget_auth_and_hostile_wire_fail_closed() -> TestResult {
    let base = unique_tmp_dir("faults");
    let v1_path = base.join("v1.journal");
    let site = "site:fss-034-faults";
    let mut v1 = DurableReferenceLedger::open(&v1_path, site, IncompleteTailPolicy::Reject)?;
    let b1 = v1.prepare_batch(
        BatchId::parse("batch:f:1")?,
        vec![make_delta(
            "d:f1",
            "cam",
            "obj:cam:f1",
            None,
            1,
            Plane::Authority,
        )?],
        vec![],
    )?;
    v1.append(b1)?;

    let cb = ContentDigest::sha256(b"cb-fss-034-faults");
    let auth = StorageAuthorityScope::active(cb, 1, 1, [Plane::Authority]);
    let p = pin(1);
    let mut sink = SecondaryFamilyIndex::new();
    let mut cursor = DerivedRebuildCursorState::genesis("idx:fault", site, &p, &sink)?;

    // 1. Revoked authority, wrong-plane authority, and cooperative cancellation fail closed!
    let mut revoked = auth.clone();
    revoked.capability_active = false;
    assert!(matches!(
        DerivedIndexRebuildCursor::step_v1(
            &v1,
            &revoked,
            &p,
            &mut cursor,
            &mut sink,
            ReplayPageBudget::new(4, 64 * 1024)?,
            false,
        ),
        Err(RebuildCursorError::AuthorityRefused(_))
    ));
    let wrong_plane = StorageAuthorityScope::active(cb, 1, 1, [Plane::Cognition]);
    assert!(matches!(
        DerivedIndexRebuildCursor::step_v1(
            &v1,
            &wrong_plane,
            &p,
            &mut cursor,
            &mut sink,
            ReplayPageBudget::new(4, 64 * 1024)?,
            false,
        ),
        Err(RebuildCursorError::AuthorityRefused(_))
    ));
    assert_eq!(
        DerivedIndexRebuildCursor::step_v1(
            &v1,
            &auth,
            &p,
            &mut cursor,
            &mut sink,
            ReplayPageBudget::new(4, 64 * 1024)?,
            true,
        ),
        Err(RebuildCursorError::Cancelled)
    );
    assert_eq!(cursor.applied_anchor.commit_sequence, 0);

    // 2. Undersized byte budget fails closed with BatchExceedsPageBudget AND leaves cursor/sink intact
    //    even when a generation-drift genesis reset would otherwise have been triggered!
    let cursor_before_err = cursor.clone();
    let sink_before_err = sink.clone();
    assert!(matches!(
        DerivedIndexRebuildCursor::step_v1(
            &v1,
            &auth,
            &pin(99),
            &mut cursor,
            &mut sink,
            ReplayPageBudget::new(1, 8)?,
            false,
        ),
        Err(RebuildCursorError::BatchExceedsPageBudget { .. })
    ));
    assert_eq!(cursor, cursor_before_err);
    assert_eq!(sink, sink_before_err);
    cursor.verify_self()?;

    // 3. Pending unresolved append on source ledger pauses cursor honestly (BlockedPendingReconciliation)!
    let b2 = v1.prepare_batch(
        BatchId::parse("batch:f:pending")?,
        vec![make_delta(
            "d:f2",
            "cam",
            "obj:cam:f2",
            None,
            1,
            Plane::Authority,
        )?],
        vec![],
    )?;
    v1.fail_journal_after_phase(AppendPhase::CommitSync);
    let _ = v1.append(b2);
    let blocked = DerivedIndexRebuildCursor::step_v1(
        &v1,
        &auth,
        &p,
        &mut cursor,
        &mut sink,
        ReplayPageBudget::new(4, 64 * 1024)?,
        false,
    )?;
    assert_eq!(
        blocked.status,
        RebuildCursorStatus::BlockedPendingReconciliation
    );
    assert_eq!(blocked.batches_applied, 0);

    // 4. Hostile wire decoding on `FSSDIC01`: bad magic, bad version, truncation, bit-flip, trailing byte!
    let wire = cursor.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &DERIVED_REBUILD_CURSOR_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        DERIVED_REBUILD_CURSOR_VERSION
    );
    assert_eq!(
        DerivedRebuildCursorState::from_canonical_bytes(&wire)?,
        cursor
    );

    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        DerivedRebuildCursorState::from_canonical_bytes(&bad_magic),
        Err(RebuildCursorError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&5_u32.to_be_bytes());
    assert_eq!(
        DerivedRebuildCursorState::from_canonical_bytes(&bad_ver),
        Err(RebuildCursorError::UnsupportedVersion { version: 5 })
    );
    assert!(matches!(
        DerivedRebuildCursorState::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(RebuildCursorError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        DerivedRebuildCursorState::from_canonical_bytes(&flipped),
        Err(RebuildCursorError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xDD);
    assert!(matches!(
        DerivedRebuildCursorState::from_canonical_bytes(&trailing),
        Err(RebuildCursorError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_034_faults_pending_cancel_budget_wire",
        "revoked_cancel_budget_pending_reconcile_and_wire_failed_closed",
        "revoked_cancel_budget_pending_reconcile_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
