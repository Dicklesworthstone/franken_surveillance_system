#![forbid(unsafe_code)]
//! Contract, differential, cancellation, crash/corruption, and wire tests for `FSS-033`
//! (`fss-x4a.9.3`: ledger schema catalog & root-last v1 -> v2 durable migrations).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    DurableReferenceLedger, EpochLedgerConfig, IncompleteTailPolicy,
    LEDGER_MIGRATION_RECEIPT_MAGIC, LEDGER_MIGRATION_RECEIPT_VERSION, LEDGER_SCHEMA_CATALOG,
    LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN, LedgerMigrationError, LedgerMigrationReceipt,
    LedgerSchemaCatalog, LedgerSchemaMigrator, MerkleEpochLedger, MigrationOutcomeState,
    MigrationStage, StorageAuthorityScope, StorageSchemaVersion, verify_proof,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fss_033_{tag}_{pid}_{n}"));
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
    obj: &str,
    prior: Option<u64>,
    next: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: "migration_test_family".to_owned(),
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

fn populate_v1_journal(
    path: &Path,
    site: &str,
) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    let mut ledger = DurableReferenceLedger::open(path, site, IncompleteTailPolicy::Reject)?;
    let b1 = ledger.prepare_batch(
        BatchId::parse("batch:mig:1")?,
        vec![
            make_delta("d:m1", "obj:cam:front", None, 1, Plane::Authority)?,
            make_delta("d:m2", "obj:cam:rear", None, 1, Plane::Authority)?,
        ],
        vec![],
    )?;
    ledger.append(b1)?;
    let b2 = ledger.prepare_batch(
        BatchId::parse("batch:mig:2")?,
        vec![
            make_delta("d:m3", "obj:cam:front", Some(1), 2, Plane::Authority)?,
            make_delta("d:m4", "obj:belief:1", None, 1, Plane::Cognition)?,
        ],
        vec![],
    )?;
    ledger.append(b2)?;
    let b3 = ledger.prepare_batch(
        BatchId::parse("batch:mig:3")?,
        vec![make_delta("d:m5", "obj:effect:1", None, 1, Plane::Effect)?],
        vec![],
    )?;
    ledger.append(b3)?;
    Ok(ledger.head_history_root())
}

#[test]
fn migrates_live_v1_journal_to_v2_epochs_with_merkle_proofs_and_idempotency() -> TestResult {
    assert_eq!(
        LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN,
        "fss.ledger_schema_migration_receipt.v1"
    );
    assert_eq!(LEDGER_SCHEMA_CATALOG.len(), 4);

    // 1. Schema catalog transition validation: forward passes, downgrade and unknown fail closed!
    assert_eq!(
        LedgerSchemaCatalog::validate_transition(
            StorageSchemaVersion::V1_0,
            StorageSchemaVersion::V2_0
        )?,
        MigrationOutcomeState::Verified
    );
    assert_eq!(
        LedgerSchemaCatalog::validate_transition(
            StorageSchemaVersion::V2_0,
            StorageSchemaVersion::V2_0
        )?,
        MigrationOutcomeState::AlreadyAtTarget
    );
    assert!(matches!(
        LedgerSchemaCatalog::validate_transition(
            StorageSchemaVersion::V2_0,
            StorageSchemaVersion::V1_0
        ),
        Err(LedgerMigrationError::DowngradeRefused { .. })
    ));
    assert!(matches!(
        LedgerSchemaCatalog::validate_transition(
            StorageSchemaVersion::V1_0,
            StorageSchemaVersion::new(9, 0)
        ),
        Err(LedgerMigrationError::UnsupportedSchemaVersion { .. })
    ));

    // 2. Real on-disk v1 journal -> staged v2 MerkleEpochLedger migration!
    let base = unique_tmp_dir("live_mig");
    let v1_path = base.join("v1.journal");
    let v2_dir = base.join("v2-epochs");
    let site = "site:fss-033-migration";
    let v1_root = populate_v1_journal(&v1_path, site)?;
    let v1_bytes_before = fs::read(&v1_path)?;

    let cb = ContentDigest::sha256(b"contract-basis-fss-033");
    let mut auth = StorageAuthorityScope::active(
        cb,
        1,
        1,
        [Plane::Authority, Plane::Cognition, Plane::Effect],
    );
    // Without allows_migration == true -> MUST fail closed!
    assert!(matches!(
        LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:v1_to_v2:001",
            &v1_path,
            &v2_dir,
            site,
            &auth,
            EpochLedgerConfig::default(),
            TimestampNs(10_000),
            None,
        ),
        Err(LedgerMigrationError::AuthorityRefused(_))
    ));
    assert!(!v2_dir.exists());

    // Migration authority lacking Plane::Effect present in source journal -> MUST fail closed!
    let mut partial_plane_auth = StorageAuthorityScope::active(cb, 1, 1, [Plane::Authority]);
    partial_plane_auth.allows_migration = true;
    assert!(matches!(
        LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:v1_to_v2:partial-plane",
            &v1_path,
            &v2_dir,
            site,
            &partial_plane_auth,
            EpochLedgerConfig::default(),
            TimestampNs(10_050),
            None,
        ),
        Err(LedgerMigrationError::AuthorityRefused(_))
    ));
    assert!(!v2_dir.exists());

    // Authorize migration and run!
    auth.allows_migration = true;
    let receipt = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:v1_to_v2:001",
        &v1_path,
        &v2_dir,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(10_100),
        None,
    )?;
    assert!(!receipt.grants_effect_authority());
    assert_eq!(receipt.outcome_state, MigrationOutcomeState::Committed);
    assert_eq!(receipt.source_history_root, v1_root);
    assert_eq!(receipt.migrated_batch_count, 3);
    assert_eq!(receipt.verified_object_count, 4);

    // Original v1 custody bytes MUST remain 100% untouched!
    assert_eq!(fs::read(&v1_path)?, v1_bytes_before);

    // Open migrated v2 ledger and verify every object + cryptographic Merkle inclusion proof!
    let v2 = MerkleEpochLedger::open(
        &v2_dir,
        site,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let verify_report = v2.verify_full_chain()?;
    assert_eq!(verify_report.history_root, receipt.target_history_root);
    assert_eq!(v2.head_anchor().commit_sequence, 3);
    assert_eq!(v2.live_object_count(), 4);
    for id in [
        "obj:cam:front",
        "obj:cam:rear",
        "obj:belief:1",
        "obj:effect:1",
    ] {
        let oid = ObjectId::parse(id)?;
        let proof = v2.prove_object(&oid)?;
        verify_proof(v2.head_anchor().state_root, &oid, &proof)?;
    }
    drop(v2);

    // 3. Re-running migration idempotently against the migrated target returns AlreadyAtTarget!
    let rerun = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:v1_to_v2:001",
        &v1_path,
        &v2_dir,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(10_200),
        None,
    )?;
    assert_eq!(rerun.outcome_state, MigrationOutcomeState::AlreadyAtTarget);
    assert_eq!(rerun.target_history_root, receipt.target_history_root);

    // 3b. Empty (genesis-only, 0-batch) v1 journal migrates cleanly and replays idempotently!
    let empty_v1 = base.join("empty_v1.journal");
    let empty_v2 = base.join("empty_v2_epochs");
    let _empty_ledger =
        DurableReferenceLedger::open(&empty_v1, site, IncompleteTailPolicy::Reject)?;
    drop(_empty_ledger);
    let empty_receipt = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:v1_to_v2:empty",
        &empty_v1,
        &empty_v2,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(10_250),
        None,
    )?;
    assert_eq!(empty_receipt.migrated_batch_count, 0);
    assert_eq!(empty_receipt.verified_object_count, 0);
    assert_eq!(
        empty_receipt.outcome_state,
        MigrationOutcomeState::Committed
    );
    let empty_rerun = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:v1_to_v2:empty",
        &empty_v1,
        &empty_v2,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(10_260),
        None,
    )?;
    assert_eq!(
        empty_rerun.outcome_state,
        MigrationOutcomeState::AlreadyAtTarget
    );

    // 4. Receipt wire determinism & round-trip (`FSSLMG01` v1).
    let w1 = receipt.to_canonical_bytes()?;
    let w2 = receipt.to_canonical_bytes()?;
    assert_eq!(w1, w2);
    assert_eq!(&w1[..8], &LEDGER_MIGRATION_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([w1[8], w1[9], w1[10], w1[11]]),
        LEDGER_MIGRATION_RECEIPT_VERSION
    );
    assert_eq!(LedgerMigrationReceipt::from_canonical_bytes(&w1)?, receipt);

    emit_caplog(
        "fss_033_v1_to_v2_migration_and_idempotency",
        "live_v1_to_v2_migration_merkle_proofs_idempotency_and_wire_verified",
        "live_v1_to_v2_migration_merkle_proofs_idempotency_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn cancellation_corrupt_source_target_conflict_and_hostile_wire_fail_closed() -> TestResult {
    let base = unique_tmp_dir("faults");
    let v1_path = base.join("v1.journal");
    let site = "site:fss-033-faults";
    let _ = populate_v1_journal(&v1_path, site)?;
    let cb = ContentDigest::sha256(b"contract-basis-fss-033-faults");
    let mut auth = StorageAuthorityScope::active(
        cb,
        1,
        1,
        [Plane::Authority, Plane::Cognition, Plane::Effect],
    );
    auth.allows_migration = true;

    // 1. Cancellation at EVERY stage boundary (Preflight, Stage, Verify, Commit) leaves target absent!
    for stage in [
        MigrationStage::Preflight,
        MigrationStage::Stage,
        MigrationStage::Verify,
        MigrationStage::Commit,
    ] {
        let target = base.join(format!("cancel-{stage:?}"));
        let res = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:cancel",
            &v1_path,
            &target,
            site,
            &auth,
            EpochLedgerConfig::default(),
            TimestampNs(20_000),
            Some(stage),
        );
        assert_eq!(res, Err(LedgerMigrationError::Cancelled { stage }));
        assert!(
            !target.exists(),
            "cancelled stage {stage:?} must not publish target"
        );
    }

    // 2. Corrupt v1 source journal (trailing garbage) MUST fail closed without publishing target!
    let corrupt_v1 = base.join("corrupt.journal");
    let mut bytes = fs::read(&v1_path)?;
    bytes.extend_from_slice(b"\xDE\xAD\xBE\xEF");
    fs::write(&corrupt_v1, bytes)?;
    let corrupt_target = base.join("corrupt-target");
    assert!(matches!(
        LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:corrupt",
            &corrupt_v1,
            &corrupt_target,
            site,
            &auth,
            EpochLedgerConfig::default(),
            TimestampNs(21_000),
            None,
        ),
        Err(LedgerMigrationError::SourceCorruptOrPending(_))
    ));
    assert!(!corrupt_target.exists());

    // 3. Target directory already existing without receipt MUST fail closed with TargetConflict!
    let conflict_target = base.join("preexisting");
    fs::create_dir_all(&conflict_target)?;
    assert!(matches!(
        LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
            "mig:conflict",
            &v1_path,
            &conflict_target,
            site,
            &auth,
            EpochLedgerConfig::default(),
            TimestampNs(22_000),
            None,
        ),
        Err(LedgerMigrationError::TargetConflict(_))
    ));

    // 4. Hostile wire decoding on `FSSLMG01`: bad magic, unsupported version, truncation, bit flip, trailing byte!
    let good_target = base.join("good-wire");
    let receipt = LedgerSchemaMigrator::migrate_v1_journal_to_v2_epochs(
        "mig:wire",
        &v1_path,
        &good_target,
        site,
        &auth,
        EpochLedgerConfig::default(),
        TimestampNs(23_000),
        None,
    )?;
    let wire = receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        LedgerMigrationReceipt::from_canonical_bytes(&bad_magic),
        Err(LedgerMigrationError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&7_u32.to_be_bytes());
    assert_eq!(
        LedgerMigrationReceipt::from_canonical_bytes(&bad_ver),
        Err(LedgerMigrationError::UnsupportedWireVersion { version: 7 })
    );
    assert!(matches!(
        LedgerMigrationReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(LedgerMigrationError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        LedgerMigrationReceipt::from_canonical_bytes(&flipped),
        Err(LedgerMigrationError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        LedgerMigrationReceipt::from_canonical_bytes(&trailing),
        Err(LedgerMigrationError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_033_cancellation_corruption_conflict_wire",
        "all_four_cancel_stages_corrupt_source_target_conflict_and_wire_failed_closed",
        "all_four_cancel_stages_corrupt_source_target_conflict_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
