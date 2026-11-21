#![forbid(unsafe_code)]
//! Durable current-state materialization preserves the complete canonical history and oracle.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    ObjectId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    JournalError, LedgerOracle, OracleError, OracleLimits, OracleReplayError,
    committed_batch_positions, encode_batch, inspect, inspect_durable,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:current-snapshot-replay";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-current-snapshot-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary-directory capacity".into())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("authority.fssj")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn input(index: u64) -> Test<(BatchId, Vec<EvidenceDelta>, Vec<ContentDigest>)> {
    let payload = ContentDigest::sha256(format!("capsule:{index}").as_bytes());
    let summary = ContentDigest::sha256(format!("summary:{index}").as_bytes());
    let validity = CaptureInterval::new(
        TimestampNs(i128::from(index) * 100),
        TimestampNs(i128::from(index) * 100 + 25),
    )?;
    Ok((
        BatchId::parse(format!("batch:{index}"))?,
        vec![
            EvidenceDelta {
                delta_id: format!("delta:capsule:{index}"),
                family: "sensor_capsule".into(),
                object_id: ObjectId::parse(format!("object:capsule:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity,
                plane: Plane::Authority,
                payload_digest: payload,
                witness_digest: Some(ContentDigest::sha256(format!("witness:{index}").as_bytes())),
                operation_id: None,
            },
            EvidenceDelta {
                delta_id: format!("delta:summary:{index}"),
                family: "source_summary".into(),
                object_id: ObjectId::parse("object:source-summary")?,
                prior_generation: (index != 0).then_some(index),
                new_generation: index + 1,
                validity,
                plane: Plane::Cognition,
                payload_digest: summary,
                witness_digest: None,
                operation_id: None,
            },
        ],
        vec![summary, payload],
    ))
}

fn batch(reference: &ReferenceLedger, index: u64) -> Test<EvidenceDeltaBatch> {
    let (id, deltas, children) = input(index)?;
    Ok(reference.prepare_batch(id, deltas, children)?)
}

fn assert_state(
    durable: &DurableReferenceLedger,
    reference: &ReferenceLedger,
    oracle: &LedgerOracle,
) -> Test {
    assert_eq!(durable.retained_snapshot_count(), 1);
    assert_eq!(durable.current(), reference.current());
    assert_eq!(durable.batches(), reference.batches());
    assert_eq!(oracle.head_anchor(), &reference.current().anchor);
    assert_eq!(oracle.view_at(oracle.head_sequence())?.snapshot(), *reference.current());
    assert!(oracle.batches().eq(reference.batches().iter()));
    Ok(())
}

fn assert_inspection(path: &Path, durable: &DurableReferenceLedger) -> Test {
    let bytes = fs::read(path)?;
    let inspection = inspect_durable(path, SITE, bytes.len())?;
    assert!(inspection.is_clean());
    assert_eq!(&inspection.snapshot, durable.current());
    assert_eq!(inspection.batches, durable.batches());
    assert_eq!(inspection.last_root, durable.journal_root());
    assert_eq!(inspection.committed_len, u64::try_from(bytes.len())?);
    let positions = committed_batch_positions(&inspection).ok_or("canonical journal positions")?;
    assert_eq!(positions.len(), durable.batches().len());
    for (position, batch) in positions.iter().zip(durable.batches()) {
        assert_eq!(position.commit_sequence, batch.new_anchor.commit_sequence);
    }
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}

#[test]
fn live_replay_and_inspection_keep_one_map_and_match_two_oracles_at_every_prefix() -> Test {
    const COMMITS: u64 = 256;
    let directory = Directory::new("prefixes")?;
    let path = directory.journal();
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut reference = ReferenceLedger::new(SITE);
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
    assert_state(&durable, &reference, &oracle)?;
    for index in 0..COMMITS {
        let (id, deltas, children) = input(index)?;
        let expected = oracle.prepare_batch(id.clone(), deltas.clone(), children.clone())?;
        let prepared = reference.prepare_batch(id, deltas, children)?;
        assert_eq!(prepared, expected, "independent preparation at prefix {index}");
        assert_eq!(encode_batch(&prepared)?, encode_batch(&expected)?);
        durable.append(prepared.clone())?;
        reference.append(prepared.clone())?;
        oracle.append(prepared)?;
        assert_state(&durable, &reference, &oracle)?;
        assert_eq!(reference.retained_snapshot_count(), usize::try_from(index + 2)?);

        if [1, 17, 64, 128, COMMITS].contains(&(index + 1)) {
            let root = durable.journal_root();
            let bytes = fs::read(&path)?;
            assert_eq!(durable.verify_storage()?, root);
            assert_inspection(&path, &durable)?;
            drop(durable);
            durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
            assert_state(&durable, &reference, &oracle)?;
            assert_eq!(durable.verify_storage()?, root);
            assert_eq!(fs::read(&path)?, bytes);
        }
    }

    // Historical core API behavior is unchanged, even though the durable owner no longer
    // retains these maps. All three implementations still agree at every canonical prefix.
    for sequence in 0..=COMMITS {
        let snapshot = reference.snapshot_at(sequence).ok_or("full-history snapshot")?;
        assert_eq!(&oracle.view_at(sequence)?.snapshot(), snapshot);
    }
    let before = fs::read(&path)?;
    let snapshot = durable.current().clone();
    for index in [0_usize, 127, 255] {
        let committed = reference.batches()[index].clone();
        let mut reused = batch(&reference, COMMITS)?;
        reused.batch_id = committed.batch_id.clone();
        reused.batch_digest = reused.computed_digest();
        assert_eq!(reference.append(reused.clone()).err(), Some(ContractError::IdempotencyConflict));
        assert!(matches!(oracle.stage(reused.clone()), Err(OracleError::BatchIdConflict { .. })));
        match durable.append(reused.clone()) {
            Err(DurableLedgerError::BatchIdConflict { committed_sequence, committed_digest, offered_digest, .. }) => {
                assert_eq!(committed_sequence, committed.new_anchor.commit_sequence);
                assert_eq!(committed_digest, committed.batch_digest);
                assert_eq!(offered_digest, reused.batch_digest);
            }
            other => return Err(format!("old batch identity escaped retention: {other:?}").into()),
        }
        assert_eq!(reference.append(committed.clone()).err(), Some(ContractError::StaleAnchor));
        assert!(matches!(oracle.stage(committed.clone()), Err(OracleError::DuplicateBatch { .. })));
        assert!(matches!(durable.append(committed), Err(DurableLedgerError::Contract(ContractError::StaleAnchor))));
        assert_state(&durable, &reference, &oracle)?;
        assert_eq!(durable.current(), &snapshot);
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}

#[test]
fn current_state_replay_still_checks_old_identities_before_any_tail_repair() -> Test {
    let directory = Directory::new("malformed-prefix")?;
    let path = directory.journal();
    let mut reference = ReferenceLedger::new(SITE);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    for index in 0..64 {
        let prepared = batch(&reference, index)?;
        journal.append(1, &encode_batch(&prepared)?)?;
        reference.append(prepared)?;
    }
    let mut counterfeit = batch(&reference, 64)?;
    counterfeit.batch_id = reference.batches()[0].batch_id.clone();
    counterfeit.batch_digest = counterfeit.computed_digest();
    journal.append(1, &encode_batch(&counterfeit)?)?;
    journal.fail_after_phase(AppendPhase::BodyWrite);
    assert!(matches!(journal.append(1, b"uncommitted tail"), Err(JournalError::AppendIndeterminate { .. })));
    drop(journal);
    let before = fs::read(&path)?;
    assert!(inspect(&path)?.incomplete_tail().is_some());

    let mut history = reference.batches().to_vec();
    history.push(counterfeit);
    assert!(matches!(ReferenceLedger::replay(SITE, history.clone()), Err(ContractError::IdempotencyConflict)));
    assert!(matches!(
        LedgerOracle::rebuild(SITE, OracleLimits::CEILING, history),
        Err(OracleReplayError::Batch { position: 64, error }) if matches!(*error, OracleError::BatchIdConflict { .. })
    ));
    for policy in [IncompleteTailPolicy::Reject, IncompleteTailPolicy::Truncate] {
        assert!(matches!(
            DurableReferenceLedger::open(&path, SITE, policy),
            Err(DurableLedgerError::BatchIdConflict { committed_sequence: 1, .. })
        ));
        assert_eq!(fs::read(&path)?, before);
    }
    assert!(matches!(
        inspect_durable(&path, SITE, before.len()),
        Err(DurableLedgerError::BatchIdConflict { committed_sequence: 1, .. })
    ));
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}
