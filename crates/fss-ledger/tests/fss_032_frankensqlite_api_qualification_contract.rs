#![forbid(unsafe_code)]
//! Qualification contract tests for `FSS-032` (`fss-x4a.9.2`, `INT-FSQL-001`):
//! exercises all three live `FrankenSqliteStorageAdapter` implementations (`ReferenceOracleStorage`,
//! `DurableJournalStorage`, `MerkleEpochStorage`) plus an adversarial broken adapter negative
//! control and hostile `FSSSQC01` wire decoding.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    ContentDigest, EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObjectRevision, TimestampNs,
};
use fss_ledger::{
    ApiCheckOutcome, AppendPhase, DurableJournalStorage, DurableReferenceLedger, EpochLedgerConfig,
    FrankenSqliteStorageAdapter, IncompleteTailPolicy, LEDGER_STORAGE_API_QUALIFICATION_DOMAIN,
    LedgerOracle, MerkleEpochLedger, MerkleEpochStorage, MerkleProof, OracleLimits,
    QualificationVerdict, ReferenceOracleStorage, STORAGE_QUALIFICATION_MAGIC,
    STORAGE_QUALIFICATION_VERSION, SemanticWitness, StorageApiCapability,
    StorageApiQualificationCertificate, StorageApiQualifier, StorageAuthorityScope,
    StorageCommitReceipt, StorageError, StorageMigrationPlan, StorageQualificationError,
    StorageRecoverySummary, StorageSchemaVersion,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_tmp_path(tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fss_032_{tag}_{pid}_{n}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

/// Adversarial wrapper that deliberately violates `FSQL-API-007` (allows unauthorized migration)
/// to prove [`StorageApiQualifier`] fails closed with [`QualificationVerdict::Refused`].
struct BrokenMigrationAdapter {
    inner: ReferenceOracleStorage,
    spoofed_version: StorageSchemaVersion,
}

impl FrankenSqliteStorageAdapter for BrokenMigrationAdapter {
    fn adapter_id(&self) -> &'static str {
        "fss-ledger:adversarial-broken-migration:v1"
    }

    fn schema_version(&self) -> StorageSchemaVersion {
        self.spoofed_version
    }

    fn head_anchor(&self) -> &LedgerAnchor {
        self.inner.head_anchor()
    }

    fn history_root(&self) -> ContentDigest {
        self.inner.history_root()
    }

    fn live_object_count(&self) -> u64 {
        self.inner.live_object_count()
    }

    fn read_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        self.inner.read_object(authority, object_id, cancelled)
    }

    fn read_object_at(
        &self,
        authority: &StorageAuthorityScope,
        sequence: u64,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        self.inner
            .read_object_at(authority, sequence, object_id, cancelled)
    }

    fn prove_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<MerkleProof>, StorageError> {
        self.inner.prove_object(authority, object_id, cancelled)
    }

    fn verify_witness(
        &self,
        authority: &StorageAuthorityScope,
        witness: &SemanticWitness,
        cancelled: bool,
    ) -> Result<(), StorageError> {
        self.inner.verify_witness(authority, witness, cancelled)
    }

    fn prepare_batch(
        &self,
        batch_id: fss_core::BatchId,
        deltas: Vec<fss_core::EvidenceDelta>,
    ) -> Result<EvidenceDeltaBatch, StorageError> {
        self.inner.prepare_batch(batch_id, deltas)
    }

    fn commit_witnessed_batch(
        &mut self,
        authority: &StorageAuthorityScope,
        batch: EvidenceDeltaBatch,
        witnesses: &[SemanticWitness],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        self.inner
            .commit_witnessed_batch(authority, batch, witnesses, now, cancelled)
    }

    fn migrate_schema(
        &mut self,
        authority: &StorageAuthorityScope,
        plan: &StorageMigrationPlan,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        // Deliberate bug: escalates allows_migration without authorization!
        let mut escalated = authority.clone();
        escalated.allows_migration = true;
        let receipt = self
            .inner
            .migrate_schema(&escalated, plan, now, cancelled)?;
        self.spoofed_version = self.inner.schema_version();
        Ok(receipt)
    }

    fn reconcile_after_crash(
        &mut self,
        authority: &StorageAuthorityScope,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageRecoverySummary, StorageError> {
        self.inner.reconcile_after_crash(authority, now, cancelled)
    }

    fn verify_integrity(
        &mut self,
        authority: &StorageAuthorityScope,
        cancelled: bool,
    ) -> Result<ContentDigest, StorageError> {
        self.inner.verify_integrity(authority, cancelled)
    }
}

#[test]
fn qualifies_oracle_durable_and_merkle_adapters_with_honest_scope() -> TestResult {
    let cb = ContentDigest::sha256(b"contract-basis-fss-032");
    assert_eq!(
        LEDGER_STORAGE_API_QUALIFICATION_DOMAIN,
        "fss.ledger_storage_api_qualification.v1"
    );

    // 1. ReferenceOracleStorage: 8 passed, 2 honestly excluded (crash injector & merkle proofs), 0 failed!
    let mut ref_adapter =
        ReferenceOracleStorage::new(LedgerOracle::new("site:qual:ref", OracleLimits::CEILING)?);
    let cert_ref = StorageApiQualifier::qualify(&mut ref_adapter, cb, TimestampNs(10_000), None)?;
    assert!(!cert_ref.grants_effect_authority());
    assert_eq!(
        cert_ref.verdict,
        QualificationVerdict::QualifiedWithExclusions
    );
    assert_eq!(cert_ref.passed_count(), 8);
    assert_eq!(cert_ref.excluded_count(), 2);
    assert_eq!(cert_ref.failed_count(), 0);

    // 2. DurableJournalStorage with REAL crash injection: 9 passed, 1 honestly excluded (merkle proofs), 0 failed!
    let dur_path = unique_tmp_path("dur").join("ledger.journal");
    let mut dur_adapter = DurableJournalStorage::new(DurableReferenceLedger::open(
        &dur_path,
        "site:qual:dur",
        IncompleteTailPolicy::Reject,
    )?);
    let mut dur_crash = |a: &mut DurableJournalStorage| {
        a.durable_mut()
            .fail_journal_after_phase(AppendPhase::CommitSync);
    };
    let cert_dur = StorageApiQualifier::qualify(
        &mut dur_adapter,
        cb,
        TimestampNs(20_000),
        Some(&mut dur_crash),
    )?;
    assert_eq!(
        cert_dur.verdict,
        QualificationVerdict::QualifiedWithExclusions,
        "durable checks: {:?}",
        cert_dur.checks
    );
    assert_eq!(cert_dur.passed_count(), 9);
    assert_eq!(cert_dur.excluded_count(), 1);
    assert_eq!(cert_dur.failed_count(), 0);

    // 3. MerkleEpochStorage with REAL crash injection + REAL Merkle proofs: 10/10 QualificationVerdict::Qualified!
    let merkle_dir = unique_tmp_path("merkle");
    let mut merkle_adapter = MerkleEpochStorage::new(MerkleEpochLedger::open(
        &merkle_dir,
        "site:qual:merkle",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?);
    let mut merkle_crash = |a: &mut MerkleEpochStorage| {
        a.ledger_mut()
            .fail_journal_after_phase(AppendPhase::CommitSync);
    };
    let cert_merkle = StorageApiQualifier::qualify(
        &mut merkle_adapter,
        cb,
        TimestampNs(30_000),
        Some(&mut merkle_crash),
    )?;
    assert_eq!(
        cert_merkle.verdict,
        QualificationVerdict::Qualified,
        "merkle checks: {:?}",
        cert_merkle.checks
    );
    assert_eq!(cert_merkle.passed_count(), 10);
    assert_eq!(cert_merkle.excluded_count(), 0);
    assert_eq!(cert_merkle.failed_count(), 0);
    assert!(cert_merkle.checks.iter().any(|c| {
        c.capability == StorageApiCapability::MerkleProofVerification
            && c.outcome == ApiCheckOutcome::Passed
    }));

    // Determinism & wire round-trip (`FSSSQC01` v1).
    let wire1 = cert_merkle.to_canonical_bytes()?;
    let wire2 = cert_merkle.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &STORAGE_QUALIFICATION_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        STORAGE_QUALIFICATION_VERSION
    );
    assert_eq!(
        StorageApiQualificationCertificate::from_canonical_bytes(&wire1)?,
        cert_merkle
    );

    emit_caplog(
        "fss_032_qualify_all_three_adapters",
        "oracle_durable_merkle_qualified_with_honest_exclusions_and_wire_determinism",
        "oracle_durable_merkle_qualified_with_honest_exclusions_and_wire_determinism",
        "pass",
    );
    Ok(())
}

#[test]
fn refuses_adversarial_broken_adapter_and_hostile_wire_certificates() -> TestResult {
    let cb = ContentDigest::sha256(b"contract-basis-fss-032-faults");

    // 1. Adversarial adapter escalating migration authority MUST receive QualificationVerdict::Refused!
    let mut broken = BrokenMigrationAdapter {
        inner: ReferenceOracleStorage::new(LedgerOracle::new(
            "site:qual:broken",
            OracleLimits::CEILING,
        )?),
        spoofed_version: StorageSchemaVersion::V1_0,
    };
    let cert_broken = StorageApiQualifier::qualify(&mut broken, cb, TimestampNs(40_000), None)?;
    assert_eq!(cert_broken.verdict, QualificationVerdict::Refused);
    assert!(cert_broken.failed_count() >= 1);
    assert!(cert_broken.checks.iter().any(|c| {
        c.capability == StorageApiCapability::ForwardOnlySchemaMigration
            && matches!(c.outcome, ApiCheckOutcome::Failed { .. })
    }));

    // 2. Non-genesis adapter refused before touching history!
    assert!(matches!(
        StorageApiQualifier::qualify(&mut broken, cb, TimestampNs(41_000), None),
        Err(StorageQualificationError::InvalidInput(_))
    ));

    // 3. Hostile binary wire decoding (`FSSSQC01`): bad magic, unsupported version, truncation, bit flip, trailing byte!
    let wire = cert_broken.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        StorageApiQualificationCertificate::from_canonical_bytes(&bad_magic),
        Err(StorageQualificationError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        StorageApiQualificationCertificate::from_canonical_bytes(&bad_ver),
        Err(StorageQualificationError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        StorageApiQualificationCertificate::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(StorageQualificationError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        StorageApiQualificationCertificate::from_canonical_bytes(&flipped),
        Err(StorageQualificationError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAA);
    assert!(matches!(
        StorageApiQualificationCertificate::from_canonical_bytes(&trailing),
        Err(StorageQualificationError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_032_refuses_broken_adapter_and_hostile_wire",
        "broken_adapter_refused_and_hostile_wire_failed_closed",
        "broken_adapter_refused_and_hostile_wire_failed_closed",
        "pass",
    );
    Ok(())
}
