//! Contract tests: the durable reference ledger never reuses a committed stable batch identity.
//!
//! Ref: fss-ceszm (durable-ledger half).
//!
//! A successor that reuses a committed `BatchId` with different content must be refused with the
//! typed `DurableLedgerError::BatchIdConflict` before any journal byte is written. An identical
//! resubmission keeps its existing idempotent-duplicate semantics: it is refused without any state
//! or journal change and classified exactly as before (`ContractError::StaleAnchor`). The identity
//! index must survive close and reopen, cover every committed batch (not only the head), follow
//! the indeterminate-append reconciliation path, and be enforced during replay.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    ObjectId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger,
    ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001, IncompleteTailPolicy, Journal, JournalError,
    encode_batch,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:durable-batch-id-reuse";
const EVIDENCE_BATCH_RECORD_KIND: u16 = 1;

fn journal_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let directory =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fss-ledger-durable-batch-id-reuse");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{name}.journal"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

fn batch_id(name: &str) -> Result<BatchId, ContractError> {
    BatchId::parse(format!("batch:{name}"))
}

fn create(tag: &str, object: &str) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

fn open(path: &PathBuf) -> Result<DurableReferenceLedger, DurableLedgerError> {
    DurableReferenceLedger::open(path, SITE, IncompleteTailPolicy::Reject)
}

/// Appends one fresh batch creating `object` under `name` and returns the committed batch.
fn commit(
    durable: &mut DurableReferenceLedger,
    name: &str,
    object: &str,
) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    let batch = durable.prepare_batch(batch_id(name)?, vec![create(name, object)?], [])?;
    durable.append(batch.clone())?;
    Ok(batch)
}

/// Expected fields of a durable batch-identity conflict.
struct Conflict<'a> {
    committed: &'a EvidenceDeltaBatch,
    offered: &'a EvidenceDeltaBatch,
}

fn expect_conflict<T: Debug>(
    result: Result<T, DurableLedgerError>,
    expected: &Conflict<'_>,
) -> TestResult {
    let error = match result {
        Ok(value) => {
            return Err(format!("expected a batch-id conflict, durable accepted {value:?}").into());
        }
        Err(error) => error,
    };
    assert_eq!(
        error.stable_id(),
        Some(ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001)
    );
    match error {
        DurableLedgerError::BatchIdConflict {
            batch_id,
            committed_sequence,
            committed_digest,
            offered_digest,
        } => {
            assert_eq!(batch_id, expected.committed.batch_id);
            assert_eq!(batch_id, expected.offered.batch_id);
            assert_eq!(
                committed_sequence,
                expected.committed.new_anchor.commit_sequence
            );
            assert_eq!(committed_digest, expected.committed.batch_digest);
            assert_eq!(offered_digest, expected.offered.batch_digest);
            assert_ne!(committed_digest, offered_digest);
            Ok(())
        }
        other => Err(format!("expected a batch-id conflict, got {other}").into()),
    }
}

fn expect_stale_anchor<T: Debug>(result: Result<T, DurableLedgerError>) -> TestResult {
    match result {
        Err(DurableLedgerError::Contract(ContractError::StaleAnchor)) => Ok(()),
        Err(other) => {
            Err(format!("expected idempotent duplicate (StaleAnchor), got {other}").into())
        }
        Ok(value) => {
            Err(format!("expected idempotent duplicate, durable accepted {value:?}").into())
        }
    }
}

/// (a) Reuse with different content is refused with the typed error before any journal write.
#[test]
fn batch_id_reuse_with_different_content_is_rejected_and_journal_is_byte_identical() -> TestResult {
    let path = journal_path("reuse_rejected_byte_identical")?;
    let mut durable = open(&path)?;
    let first = commit(&mut durable, "1", "a")?;
    let _second = commit(&mut durable, "2", "b")?;

    let bytes_before = fs::read(&path)?;
    let root_before = durable.journal_root();
    let snapshot_before = durable.current().clone();
    let history_before = durable.batches().to_vec();

    // Well-formed successor of the head: only the reused identity makes it invalid.
    let reuse = durable.prepare_batch(first.batch_id.clone(), vec![create("r", "r")?], [])?;
    expect_conflict(
        durable.append(reuse.clone()),
        &Conflict {
            committed: &first,
            offered: &reuse,
        },
    )?;

    assert_eq!(fs::read(&path)?, bytes_before);
    assert_eq!(durable.journal_root(), root_before);
    assert_eq!(durable.current(), &snapshot_before);
    assert_eq!(durable.batches(), history_before.as_slice());
    assert_eq!(durable.pending_append_sequence(), None);
    assert_eq!(durable.verify_storage()?, root_before);

    // The refusal does not wedge the ledger: a fresh identity still commits.
    let third = commit(&mut durable, "3", "c")?;
    assert_eq!(durable.batches().len(), 3);
    assert_eq!(durable.current().anchor, third.new_anchor);
    Ok(())
}

/// (b) An identical resubmission keeps its idempotent-duplicate semantics.
#[test]
fn identical_resubmission_remains_an_idempotent_duplicate() -> TestResult {
    let path = journal_path("identical_resubmission_idempotent")?;
    let mut durable = open(&path)?;
    let first = commit(&mut durable, "1", "a")?;
    let second = commit(&mut durable, "2", "b")?;

    let bytes_before = fs::read(&path)?;
    let root_before = durable.journal_root();
    let history_before = durable.batches().to_vec();

    for resubmitted in [&second, &first] {
        expect_stale_anchor(durable.append(resubmitted.clone()))?;
        assert_eq!(fs::read(&path)?, bytes_before);
        assert_eq!(durable.journal_root(), root_before);
        assert_eq!(durable.batches(), history_before.as_slice());
        assert_eq!(durable.current().anchor, second.new_anchor);
    }

    // The same holds after restart.
    drop(durable);
    let mut reopened = open(&path)?;
    expect_stale_anchor(reopened.append(second.clone()))?;
    expect_stale_anchor(reopened.append(first))?;
    assert_eq!(fs::read(&path)?, bytes_before);
    assert_eq!(reopened.batches(), history_before.as_slice());
    Ok(())
}

/// (c) The identity index is rebuilt from the durable prefix on reopen.
#[test]
fn batch_id_reuse_is_rejected_after_close_and_reopen() -> TestResult {
    let path = journal_path("reuse_rejected_after_reopen")?;
    let mut durable = open(&path)?;
    let first = commit(&mut durable, "1", "a")?;
    drop(durable);

    let mut reopened = open(&path)?;
    let bytes_before = fs::read(&path)?;
    let root_before = reopened.journal_root();
    let reuse = reopened.prepare_batch(first.batch_id.clone(), vec![create("r", "r")?], [])?;
    expect_conflict(
        reopened.append(reuse.clone()),
        &Conflict {
            committed: &first,
            offered: &reuse,
        },
    )?;
    assert_eq!(fs::read(&path)?, bytes_before);
    assert_eq!(reopened.journal_root(), root_before);
    assert_eq!(reopened.batches(), [first.clone()].as_slice());
    drop(reopened);

    // A second restart still opens the untouched journal with exactly one batch.
    let again = open(&path)?;
    assert_eq!(again.batches(), [first].as_slice());
    assert_eq!(again.journal_root(), root_before);
    Ok(())
}

/// (d) Reuse of an older, non-head identity is refused, naming that batch's commit sequence.
#[test]
fn batch_id_reuse_of_older_non_head_batch_is_rejected() -> TestResult {
    let path = journal_path("reuse_of_non_head_rejected")?;
    let mut durable = open(&path)?;
    let first = commit(&mut durable, "1", "a")?;
    let second = commit(&mut durable, "2", "b")?;
    let third = commit(&mut durable, "3", "c")?;
    assert_eq!(durable.current().anchor, third.new_anchor);

    let bytes_before = fs::read(&path)?;
    let root_before = durable.journal_root();
    for (committed, tag) in [(&first, "r1"), (&second, "r2")] {
        let reuse =
            durable.prepare_batch(committed.batch_id.clone(), vec![create(tag, tag)?], [])?;
        expect_conflict(
            durable.append(reuse.clone()),
            &Conflict {
                committed,
                offered: &reuse,
            },
        )?;
        assert_eq!(fs::read(&path)?, bytes_before);
        assert_eq!(durable.journal_root(), root_before);
        assert_eq!(durable.batches().len(), 3);
    }
    Ok(())
}

/// A batch committed through indeterminate-append reconciliation enters the identity index.
#[test]
fn batch_id_reuse_is_rejected_after_reconciled_indeterminate_append() -> TestResult {
    let path = journal_path("reuse_rejected_after_reconcile")?;
    let mut durable = open(&path)?;
    let first = durable.prepare_batch(batch_id("1")?, vec![create("1", "a")?], [])?;
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    match durable.append(first.clone()) {
        Err(DurableLedgerError::Journal(JournalError::AppendIndeterminate { .. })) => {}
        other => return Err(format!("expected an indeterminate append, got {other:?}").into()),
    }
    assert_eq!(
        durable.reconcile_pending(IncompleteTailPolicy::Reject)?,
        DurableAppendReconciliation::Committed {
            sequence: 1,
            batch_id: first.batch_id.clone(),
        }
    );

    let bytes_before = fs::read(&path)?;
    let reuse = durable.prepare_batch(first.batch_id.clone(), vec![create("r", "r")?], [])?;
    expect_conflict(
        durable.append(reuse.clone()),
        &Conflict {
            committed: &first,
            offered: &reuse,
        },
    )?;
    assert_eq!(fs::read(&path)?, bytes_before);
    assert_eq!(durable.batches(), [first].as_slice());
    Ok(())
}

/// Replay applies the same identity check: a durable prefix that already reuses a batch ID (as a
/// pre-fix writer could produce) fails to open with the typed error, and the file is untouched.
///
/// Core `ReferenceLedger` rejects batch-ID reuse with `ContractError::IdempotencyConflict`, while
/// `DurableReferenceLedger` rejects it with `DurableLedgerError::BatchIdConflict`. Because core
/// now rejects batch-ID reuse on append, the fixture writes the pre-fix reusing prefix directly
/// at the raw journal layer.
#[test]
fn replay_rejects_durable_prefix_that_reuses_a_batch_id() -> TestResult {
    let path = journal_path("replay_rejects_reuse")?;
    let mut core = ReferenceLedger::new(SITE);
    let first = core.prepare_batch(batch_id("1")?, vec![create("1", "a")?], [])?;
    core.append(first.clone())?;
    let reuse = core.prepare_batch(first.batch_id.clone(), vec![create("r", "r")?], [])?;
    // Core correctly rejects appending the reused batch ID with IdempotencyConflict:
    assert_eq!(
        core.append(reuse.clone()),
        Err(ContractError::IdempotencyConflict)
    );

    // Simulate a pre-fix journal containing batch-ID reuse by appending directly at the journal layer:
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(EVIDENCE_BATCH_RECORD_KIND, &encode_batch(&first)?)?;
    journal.append(EVIDENCE_BATCH_RECORD_KIND, &encode_batch(&reuse)?)?;
    drop(journal);
    let bytes_before = fs::read(&path)?;

    for policy in [IncompleteTailPolicy::Reject, IncompleteTailPolicy::Truncate] {
        expect_conflict(
            DurableReferenceLedger::open(&path, SITE, policy),
            &Conflict {
                committed: &first,
                offered: &reuse,
            },
        )?;
        assert_eq!(fs::read(&path)?, bytes_before);
    }
    Ok(())
}
