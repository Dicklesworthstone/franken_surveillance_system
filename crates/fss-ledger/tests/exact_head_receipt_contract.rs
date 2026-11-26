#![forbid(unsafe_code)]
//! Canonical head receipt recovery is read-only, exact, and fenced by unresolved appends.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{
    AppendPhase, EpochAppendReconciliation, EpochLedgerConfig, EpochLedgerError,
    IncompleteTailPolicy, MerkleEpochLedger,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-head-receipt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_ledger(dir: &TempDir) -> Result<MerkleEpochLedger, EpochLedgerError> {
    MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:exact-batch",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )
}

fn prepare(
    ledger: &MerkleEpochLedger,
    label: &str,
) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
    let digest = ContentDigest::sha256(b"synthetic head-receipt metadata");
    Ok(ledger.prepare_batch(
        BatchId::parse(format!("batch:exact:{label}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:exact:{label}"),
            family: "synthetic_exact_metadata".to_owned(),
            object_id: ObjectId::parse(format!("obj:exact:{label}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        [digest],
    )?)
}

#[test]
fn exact_head_receipt_survives_reopen_but_excludes_historical_batches() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_ledger(&dir)?;
    let first = prepare(&ledger, "head-recovery")?;
    assert!(ledger.receipt_for_exact_head(&first)?.is_none());
    let committed = ledger.append_batch(first.clone())?;
    assert_eq!(
        ledger.receipt_for_exact_head(&first)?,
        Some(committed.clone())
    );
    drop(ledger);

    let mut reopened = open_ledger(&dir)?;
    assert_eq!(reopened.receipt_for_exact_head(&first)?, Some(committed));
    let next = prepare(&reopened, "next-head")?;
    let next_receipt = reopened.append_batch(next.clone())?;
    assert!(reopened.receipt_for_exact_head(&first)?.is_none());
    assert_eq!(reopened.receipt_for_exact_head(&next)?, Some(next_receipt));
    assert_eq!(reopened.commit_sequence(), 2);
    Ok(())
}

#[test]
fn exact_head_receipt_rejects_changed_body_identity_and_anchor() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_ledger(&dir)?;
    let batch = prepare(&ledger, "receipt-binding")?;
    let committed = ledger.append_batch(batch.clone())?;
    let mut changed_body = batch.clone();
    changed_body.deltas[0].delta_id.push_str(":changed");
    assert!(matches!(
        ledger.receipt_for_exact_head(&changed_body),
        Err(EpochLedgerError::BatchDigestMismatch { .. })
    ));

    let mut changed_id = batch.clone();
    changed_id.batch_id = BatchId::parse("batch:exact:other-identity")?;
    let mut changed_site = batch.clone();
    changed_site.new_anchor.site_lineage = "site:other".to_owned();
    let mut changed_basis = batch.clone();
    changed_basis.basis_anchor.policy_epoch += 1;
    for mut changed in [changed_body, changed_id, changed_site, changed_basis] {
        changed.batch_digest = changed.computed_digest();
        assert!(ledger.receipt_for_exact_head(&changed)?.is_none());
    }
    let mut noncanonical = batch.clone();
    noncanonical.children.push(batch.children[0]);
    noncanonical.batch_digest = noncanonical.computed_digest();
    assert!(matches!(
        ledger.receipt_for_exact_head(&noncanonical),
        Err(EpochLedgerError::NonCanonicalOrdering { .. })
    ));
    assert_eq!(ledger.receipt_for_exact_head(&batch)?, Some(committed));
    assert_eq!(ledger.commit_sequence(), 1);
    Ok(())
}

#[test]
fn unresolved_append_fences_receipt_recovery_until_native_reconciliation() -> TestResult {
    let dir = TempDir::new()?;
    let mut ledger = open_ledger(&dir)?;
    let first = prepare(&ledger, "known-prefix")?;
    let _ = ledger.append_batch(first.clone())?;
    let pending = prepare(&ledger, "unresolved")?;
    ledger.fail_journal_after_phase(AppendPhase::CommitSync);
    assert!(matches!(
        ledger.append_batch(pending.clone()),
        Err(EpochLedgerError::AppendIndeterminate { sequence: 2, .. })
    ));
    for offered in [&first, &pending] {
        assert!(matches!(
            ledger.receipt_for_exact_head(offered),
            Err(EpochLedgerError::ReconciliationRequired { sequence: 2 })
        ));
    }
    assert_eq!(ledger.commit_sequence(), 1);
    let EpochAppendReconciliation::Committed(receipt) =
        ledger.reconcile_pending(IncompleteTailPolicy::Reject)?
    else {
        return Err("complete append did not reconcile to its exact receipt".into());
    };
    assert_eq!(ledger.receipt_for_exact_head(&pending)?, Some(*receipt));
    assert!(ledger.receipt_for_exact_head(&first)?.is_none());
    assert_eq!(ledger.commit_sequence(), 2);
    Ok(())
}
