#![forbid(unsafe_code)]
//! Contract, observational-equivalence, crash-reconciliation, migration, and hostile-wire tests
//! for `FSS-031` (`fss-x4a.9.1`): FrankenSQLite storage integration trait.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, Completeness, ContentDigest, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane, TimestampNs,
};
use fss_ledger::merkle::verify_proof;
use fss_ledger::storage_adapter::{
    DurableJournalStorage, FrankenSqliteStorageAdapter, LEDGER_STORAGE_ADAPTER_RECEIPT_DOMAIN,
    MerkleEpochStorage, ReferenceOracleStorage, STORAGE_RECEIPT_MAGIC, STORAGE_RECEIPT_VERSION,
    StorageAuthorityScope, StorageCommitReceipt, StorageCommitState, StorageError,
    StorageMigrationPlan, StorageRecoveryOutcome, StorageSchemaVersion,
};
use fss_ledger::{
    AppendPhase, DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy, LedgerOracle,
    MerkleEpochLedger, NegativeWitness, OracleLimits, PositiveWitness, SemanticWitness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_tmp_path(label: &str) -> PathBuf {
    let n = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fss_031_{label}_{pid}_{nanos}_{n}"))
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn delta(
    id: &str,
    obj: &str,
    prior_gen: Option<u64>,
    new_gen: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: "camera_frame_fact".to_owned(),
        object_id: ObjectId::parse(obj)?,
        prior_generation: prior_gen,
        new_generation: new_gen,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        plane,
        payload_digest: d(&format!("{id}-{obj}-{new_gen}")),
        witness_digest: None,
        operation_id: None,
    })
}

fn coverage_witness(anchor: &LedgerAnchor, certified: bool) -> CoverageWitness {
    let domain = BTreeSet::from(["zone:driveway".to_owned()]);
    CoverageWitness {
        anchor: anchor.clone(),
        authorized_domain: domain.clone(),
        observed_domain: if certified { domain } else { BTreeSet::new() },
        excluded_domain: if certified {
            BTreeSet::new()
        } else {
            BTreeSet::from(["zone:driveway".to_owned()])
        },
        continuity: if certified {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if certified {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        negative_predicate: "absent:obj:cam-absent".to_owned(),
        stop_reason: if certified {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn make_batch_on(
    oracle: &LedgerOracle,
    batch_id: &str,
    deltas: Vec<EvidenceDelta>,
) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
    Ok(oracle.prepare_batch(BatchId::parse(batch_id)?, deltas, vec![])?)
}

#[test]
fn storage_trait_proves_oracle_durable_and_merkle_equivalence_migrations_and_witnesses()
-> TestResult {
    let cb = d("contract-basis-031");
    let auth = StorageAuthorityScope::active(cb, 1, 1, [Plane::Authority, Plane::Cognition]);

    let mut ref_store =
        ReferenceOracleStorage::new(LedgerOracle::new("site:fss-031", OracleLimits::CEILING)?);
    let durable_path = unique_tmp_path("equiv_journal").with_extension("journal");
    let mut dur_store = DurableJournalStorage::new(DurableReferenceLedger::open(
        &durable_path,
        "site:fss-031",
        IncompleteTailPolicy::Reject,
    )?);
    let merkle_dir = unique_tmp_path("equiv_merkle");
    let mut merkle_store = MerkleEpochStorage::new(MerkleEpochLedger::open(
        &merkle_dir,
        "site:fss-031",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?);

    // 1. Commit batch 1 identically to ReferenceOracleStorage & DurableJournalStorage (and v2 MerkleEpochStorage).
    let d1 = delta("d-1", "obj:cam-1", None, 1, Plane::Authority)?;
    let b1 = make_batch_on(ref_store.oracle(), "batch:031-1", vec![d1.clone()])?;
    let b1_merkle =
        merkle_store
            .ledger()
            .prepare_batch(BatchId::parse("batch:031-1")?, vec![d1], vec![])?;

    let r_ref =
        ref_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(1_000), false)?;
    let r_dur =
        dur_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(1_000), false)?;
    let r_merkle =
        merkle_store.commit_witnessed_batch(&auth, b1_merkle, &[], TimestampNs(1_000), false)?;

    assert_eq!(r_ref.commit_state, StorageCommitState::Durable);
    assert_eq!(r_dur.commit_state, StorageCommitState::Durable);
    assert_eq!(r_merkle.commit_state, StorageCommitState::Durable);
    assert_eq!(r_ref.committed_anchor, r_dur.committed_anchor);
    assert_eq!(r_ref.history_root, r_dur.history_root);
    assert_eq!(ref_store.live_object_count(), dur_store.live_object_count());
    assert_eq!(
        ref_store.live_object_count(),
        merkle_store.live_object_count()
    );
    assert_eq!(
        LEDGER_STORAGE_ADAPTER_RECEIPT_DOMAIN,
        "fss.ledger_storage_adapter_receipt.v1"
    );

    // 2. Idempotent duplicate BatchId retry reconciles cleanly without advancing head!
    let dup_ref =
        ref_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(1_010), false)?;
    let dup_dur =
        dur_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(1_010), false)?;
    assert_eq!(
        dup_ref.commit_state,
        StorageCommitState::ReconciledDuplicate
    );
    assert_eq!(
        dup_dur.commit_state,
        StorageCommitState::ReconciledDuplicate
    );
    assert_eq!(dup_ref.history_root, dup_dur.history_root);
    assert_eq!(ref_store.head_anchor().commit_sequence, 1);
    assert_eq!(dur_store.head_anchor().commit_sequence, 1);

    // 3. BatchId reuse with DIFFERENT content fails closed with BatchIdConflict!
    let conflicting_b1 = make_batch_on(
        ref_store.oracle(),
        "batch:031-1",
        vec![delta("d-conflict", "obj:cam-2", None, 1, Plane::Authority)?],
    )?;
    assert!(matches!(
        ref_store.commit_witnessed_batch(
            &auth,
            conflicting_b1.clone(),
            &[],
            TimestampNs(1_020),
            false
        ),
        Err(StorageError::BatchIdConflict { .. })
    ));
    assert!(matches!(
        dur_store.commit_witnessed_batch(&auth, conflicting_b1, &[], TimestampNs(1_020), false),
        Err(StorageError::BatchIdConflict { .. })
    ));

    // 4. Witnessed batch 2 using positive witness for obj:cam-1 + certified negative witness for obj:cam-absent!
    let pos_w = SemanticWitness::Positive(PositiveWitness::from_oracle(
        ref_store.oracle(),
        1,
        &ObjectId::parse("obj:cam-1")?,
    )?);
    let certified_cov = coverage_witness(ref_store.head_anchor(), true);
    let neg_w = SemanticWitness::Negative(NegativeWitness::from_oracle(
        ref_store.oracle(),
        1,
        &ObjectId::parse("obj:cam-absent")?,
        certified_cov,
    )?);
    let b2 = make_batch_on(
        ref_store.oracle(),
        "batch:031-2",
        vec![delta("d-2", "obj:cam-1", Some(1), 2, Plane::Authority)?],
    )?;
    let r2_ref = ref_store.commit_witnessed_batch(
        &auth,
        b2.clone(),
        &[pos_w.clone(), neg_w.clone()],
        TimestampNs(1_100),
        false,
    )?;
    let r2_dur =
        dur_store.commit_witnessed_batch(&auth, b2, &[pos_w, neg_w], TimestampNs(1_100), false)?;
    assert_eq!(r2_ref.verified_witness_count, 2);
    assert_eq!(r2_dur.verified_witness_count, 2);
    assert_eq!(
        ref_store.read_object(&auth, &ObjectId::parse("obj:cam-1")?, false)?,
        dur_store.read_object(&auth, &ObjectId::parse("obj:cam-1")?, false)?
    );
    assert_eq!(
        ref_store.read_object_at(&auth, 1, &ObjectId::parse("obj:cam-1")?, false)?,
        dur_store.read_object_at(&auth, 1, &ObjectId::parse("obj:cam-1")?, false)?
    );

    // Historical duplicate retry of batch 1 AFTER batch 2 committed MUST return seq-1 history_root identically!
    let hist_dup_ref =
        ref_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(1_150), false)?;
    let hist_dup_dur =
        dur_store.commit_witnessed_batch(&auth, b1, &[], TimestampNs(1_150), false)?;
    assert_eq!(hist_dup_ref.history_root, hist_dup_dur.history_root);
    assert_eq!(hist_dup_ref.committed_anchor.commit_sequence, 1);

    // 5. MerkleEpochStorage emits standalone O(log N) inclusion + non-inclusion proofs!
    assert!(merkle_store.supports_merkle_proofs());
    let obj_cam1 = ObjectId::parse("obj:cam-1")?;
    let inc_proof = merkle_store
        .prove_object(&auth, &obj_cam1, false)?
        .ok_or("expected inclusion proof")?;
    verify_proof(merkle_store.head_anchor().state_root, &obj_cam1, &inc_proof)?;
    let obj_missing = ObjectId::parse("obj:missing")?;
    let non_inc_proof = merkle_store
        .prove_object(&auth, &obj_missing, false)?
        .ok_or("expected non-inclusion proof")?;
    verify_proof(
        merkle_store.head_anchor().state_root,
        &obj_missing,
        &non_inc_proof,
    )?;

    // 6. Forward schema migration requires allows_migration == true; downgrade is refused!
    let mig_plan = StorageMigrationPlan {
        migration_id: "mig:v1_0_to_v1_1".to_owned(),
        from_version: StorageSchemaVersion::V1_0,
        to_version: StorageSchemaVersion::V1_1,
        description: "add witness index".to_owned(),
    };
    assert!(matches!(
        ref_store.migrate_schema(&auth, &mig_plan, TimestampNs(1_200), false),
        Err(StorageError::AuthorityRefused(_))
    ));
    let mut mig_auth = auth.clone();
    mig_auth.allows_migration = true;
    let mig_receipt = ref_store.migrate_schema(&mig_auth, &mig_plan, TimestampNs(1_210), false)?;
    assert_eq!(ref_store.schema_version(), StorageSchemaVersion::V1_1);

    let downgrade = StorageMigrationPlan {
        migration_id: "mig:downgrade".to_owned(),
        from_version: StorageSchemaVersion::V1_1,
        to_version: StorageSchemaVersion::V1_0,
        description: "forbidden downgrade".to_owned(),
    };
    assert!(matches!(
        ref_store.migrate_schema(&mig_auth, &downgrade, TimestampNs(1_220), false),
        Err(StorageError::UnsupportedSchemaDowngrade { .. })
    ));

    // Binary wire codec round-trip (`FSSSQL01` v1).
    let wire = mig_receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &STORAGE_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        STORAGE_RECEIPT_VERSION
    );
    assert_eq!(
        StorageCommitReceipt::from_canonical_bytes(&wire)?,
        mig_receipt
    );
    let _ = dur_store.verify_integrity(&auth, false)?;
    let _ = merkle_store.verify_integrity(&auth, false)?;

    emit_caplog(
        "fss031_storage_trait_equivalence_migrations_merkle",
        "oracle_durable_merkle_equivalence_witnesses_migration_and_wire_verified",
        "oracle_durable_merkle_equivalence_witnesses_migration_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn storage_trait_handles_crash_reconciliation_uncertified_absence_auth_cancel_and_wire()
-> TestResult {
    let cb = d("contract-basis-031-faults");
    let auth = StorageAuthorityScope::active(cb, 2, 1, [Plane::Authority]);

    let durable_path = unique_tmp_path("crash_journal").with_extension("journal");
    let mut dur_store = DurableJournalStorage::new(DurableReferenceLedger::open(
        &durable_path,
        "site:fss-031-crash",
        IncompleteTailPolicy::Reject,
    )?);
    let mut oracle = LedgerOracle::new("site:fss-031-crash", OracleLimits::CEILING)?;

    // 1. Inject real journal sync crash after writing commit trailer -> IndeterminateAppend!
    let b1 = make_batch_on(
        &oracle,
        "batch:crash-1",
        vec![delta("d-c1", "obj:c1", None, 1, Plane::Authority)?],
    )?;
    dur_store
        .durable_mut()
        .fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        dur_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(2_000), false),
        Err(StorageError::IndeterminateAppend { sequence: 1, .. })
    ));

    // Further writes while indeterminate MUST be blocked until reconcile_after_crash!
    assert!(matches!(
        dur_store.commit_witnessed_batch(&auth, b1.clone(), &[], TimestampNs(2_010), false),
        Err(StorageError::IndeterminateAppend { sequence: 1, .. })
    ));

    // Reconcile resolves the exact durable state cleanly!
    let rec = dur_store.reconcile_after_crash(&auth, TimestampNs(2_020), false)?;
    assert_eq!(rec.outcome, StorageRecoveryOutcome::PendingCommitted);
    assert_eq!(dur_store.head_anchor().commit_sequence, 1);
    let _ = oracle.append(b1)?;

    // 2. Uncertified negative read witness (`CoverageContinuity::Gapped`) MUST fail closed!
    let gap_cov = coverage_witness(oracle.head_anchor(), false);
    let uncert_neg = SemanticWitness::Negative(NegativeWitness::from_oracle(
        &oracle,
        1,
        &ObjectId::parse("obj:missing")?,
        gap_cov,
    )?);
    let b2 = make_batch_on(
        &oracle,
        "batch:uncert",
        vec![delta("d-u1", "obj:c1", Some(1), 2, Plane::Authority)?],
    )?;
    assert_eq!(
        dur_store.commit_witnessed_batch(
            &auth,
            b2.clone(),
            &[uncert_neg],
            TimestampNs(2_100),
            false
        ),
        Err(StorageError::UncertifiedAbsenceWitness)
    );

    // 3. Cross-plane write (`Plane::Effect` outside `allowed_planes`) & cancellation fail closed!
    let effect_batch = make_batch_on(
        &oracle,
        "batch:eff",
        vec![delta("d-e1", "obj:eff-1", None, 1, Plane::Effect)?],
    )?;
    assert!(matches!(
        dur_store.commit_witnessed_batch(&auth, effect_batch, &[], TimestampNs(2_110), false),
        Err(StorageError::AuthorityRefused(_))
    ));
    assert_eq!(
        dur_store.commit_witnessed_batch(&auth, b2.clone(), &[], TimestampNs(2_120), true),
        Err(StorageError::Cancelled)
    );

    // 4. Commit cleanly and test hostile wire decoding on `FSSSQL01`.
    let receipt = dur_store.commit_witnessed_batch(&auth, b2, &[], TimestampNs(2_130), false)?;
    let wire = receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        StorageCommitReceipt::from_canonical_bytes(&bad_magic),
        Err(StorageError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        StorageCommitReceipt::from_canonical_bytes(&bad_ver),
        Err(StorageError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        StorageCommitReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(StorageError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        StorageCommitReceipt::from_canonical_bytes(&bit_flip),
        Err(StorageError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xCC);
    assert!(matches!(
        StorageCommitReceipt::from_canonical_bytes(&trailing),
        Err(StorageError::MalformedWire(_))
    ));

    emit_caplog(
        "fss031_storage_trait_crash_absence_auth_wire",
        "crash_reconciliation_uncertified_absence_plane_cancel_wire_failed_closed",
        "crash_reconciliation_uncertified_absence_plane_cancel_wire_failed_closed",
        "pass",
    );
    Ok(())
}
