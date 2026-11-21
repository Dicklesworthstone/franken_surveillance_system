#![forbid(unsafe_code)]
//! Object plane ownership agrees across reference, durable, and independent oracle histories.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    LedgerSnapshotRetention, ObjectId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    JournalError, LedgerOracle, OracleError, OracleLimits, OracleReplayError, encode_batch,
    inspect, inspect_durable,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:object-plane-ownership";
const OBJECT: &str = "object:plane-owner";
const PLANES: [Plane; 3] = [Plane::Authority, Plane::Cognition, Plane::Effect];
const MODES: [LedgerSnapshotRetention; 2] = [
    LedgerSnapshotRetention::FullHistory,
    LedgerSnapshotRetention::CurrentOnly,
];

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-plane-ownership-{label}-{}-{attempt}",
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

fn delta(generation: u64, plane: Plane) -> Test<EvidenceDelta> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:plane-owner:{generation}"),
        // Family changes are valid, including a tombstone, while plane ownership is stable.
        family: if generation == 1 { "owned_object" } else { "zzz_tombstone" }.into(),
        object_id: ObjectId::parse(OBJECT)?,
        prior_generation: (generation > 1).then_some(generation - 1),
        new_generation: generation,
        validity: CaptureInterval::new(
            TimestampNs(i128::from(generation) * 100),
            TimestampNs(i128::from(generation) * 100 + 10),
        )?,
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{generation}").as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn next_deltas(plane: Plane) -> Test<Vec<EvidenceDelta>> {
    let mut independent = delta(1, Plane::Authority)?;
    independent.delta_id = "delta:unrelated".into();
    independent.family = "aaa_independent".into();
    independent.object_id = ObjectId::parse("object:unrelated")?;
    // This legal creation sorts before the plane-changing revision. Its tentative insertion
    // must not escape when the later revision makes the complete batch invalid.
    Ok(vec![independent, delta(2, plane)?])
}

struct History {
    first: EvidenceDeltaBatch,
    counterfeit: EvidenceDeltaBatch,
    valid: EvidenceDeltaBatch,
}

fn history(from: Plane, to: Plane) -> Test<History> {
    let mut source = ReferenceLedger::new(SITE);
    let first = source.prepare_batch(
        BatchId::parse("batch:first")?,
        vec![delta(1, from)?],
        [],
    )?;
    source.append(first.clone())?;
    let valid = source.prepare_batch(BatchId::parse("batch:next")?, next_deltas(from)?, [])?;

    // Construct the counterfeit's root using an independently valid history in the target
    // plane. The resulting object map is exactly the map a silent plane mutation would create.
    // Rebinding only its basis and batch digest gives a well-ordered, correct-generation batch
    // with a genuine valid state root: rejection cannot be explained by a malformed hash.
    let mut target = ReferenceLedger::new(SITE);
    let target_first = target.prepare_batch(
        BatchId::parse("batch:first")?,
        vec![delta(1, to)?],
        [],
    )?;
    target.append(target_first)?;
    let mut counterfeit =
        target.prepare_batch(BatchId::parse("batch:next")?, next_deltas(to)?, [])?;
    counterfeit.basis_anchor = first.new_anchor.clone();
    counterfeit.batch_digest = counterfeit.computed_digest();
    assert!(counterfeit.is_canonically_ordered());
    assert_eq!(counterfeit.new_anchor.commit_sequence, 2);
    assert_ne!(counterfeit.new_anchor.state_root, valid.new_anchor.state_root);
    Ok(History { first, counterfeit, valid })
}

fn conflict(from: Plane, to: Plane) -> Test<ContractError> {
    Ok(ContractError::ObjectPlaneConflict {
        object_id: ObjectId::parse(OBJECT)?,
        committed_plane: from,
        delta_plane: to,
    })
}

fn assert_unchanged_refusal(
    ledger: &mut ReferenceLedger,
    batch: EvidenceDeltaBatch,
    expected: &ContractError,
) {
    let snapshot = ledger.current().clone();
    let batches = ledger.batches().to_vec();
    let retained = ledger.retained_snapshot_count();
    assert_eq!(ledger.stage_append(batch.clone()).err(), Some(expected.clone()));
    assert_eq!(ledger.append(batch).err(), Some(expected.clone()));
    assert_eq!(ledger.current(), &snapshot);
    assert_eq!(ledger.batches(), batches);
    assert_eq!(ledger.retained_snapshot_count(), retained);
}

fn assert_durable_conflict(error: DurableLedgerError, expected: &ContractError) -> Test {
    match error {
        DurableLedgerError::Contract(actual) => assert_eq!(&actual, expected),
        other => return Err(format!("wrong durable plane refusal: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn all_plane_changes_are_atomic_refusals_in_both_modes_and_the_independent_oracle() -> Test {
    for from in PLANES {
        for to in PLANES {
            if from == to {
                continue;
            }
            let History { first, counterfeit, valid } = history(from, to)?;
            let expected = conflict(from, to)?;
            assert_eq!(expected.code(), "object_plane_conflict");
            assert_eq!(
                ReferenceLedger::replay(SITE, [first.clone(), counterfeit.clone()]).err(),
                Some(expected.clone())
            );
            for mode in MODES {
                let mut reference = ReferenceLedger::replay_with_snapshot_retention(
                    SITE,
                    mode,
                    [first.clone()],
                )?;
                assert_eq!(
                    reference.prepare_batch(
                        counterfeit.batch_id.clone(),
                        counterfeit.deltas.clone(),
                        [],
                    ).err(),
                    Some(expected.clone())
                );
                assert_unchanged_refusal(&mut reference, counterfeit.clone(), &expected);
                assert_eq!(
                    ReferenceLedger::replay_with_snapshot_retention(
                        SITE,
                        mode,
                        [first.clone(), counterfeit.clone()],
                    ).err(),
                    Some(expected.clone())
                );

                let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
                oracle.append(first.clone())?;
                for error in [
                    oracle.prepare_batch(
                        counterfeit.batch_id.clone(),
                        counterfeit.deltas.clone(),
                        [],
                    ).err().ok_or("oracle prepared a plane mutation")?,
                    oracle.stage(counterfeit.clone()).err().ok_or("oracle staged a plane mutation")?,
                ] {
                    assert!(matches!(
                        error,
                        OracleError::PlaneConflict { object_id, committed_plane, delta_plane }
                            if object_id.as_str() == OBJECT
                                && committed_plane == from
                                && delta_plane == to
                    ));
                }
                assert_eq!(oracle.head_anchor(), &reference.current().anchor);
                assert_eq!(oracle.view_at(1)?.snapshot(), *reference.current());

                // A refused candidate reserves neither its batch identity nor the unrelated
                // object's identity. The valid same-plane batch can immediately use both.
                let oracle_valid = oracle.prepare_batch(
                    valid.batch_id.clone(),
                    valid.deltas.clone(),
                    [],
                )?;
                let reference_valid = reference.prepare_batch(
                    valid.batch_id.clone(),
                    valid.deltas.clone(),
                    [],
                )?;
                assert_eq!(reference_valid, valid);
                assert_eq!(oracle_valid, valid);
                assert_eq!(encode_batch(&reference_valid)?, encode_batch(&oracle_valid)?);
                reference.append(reference_valid)?;
                oracle.append(oracle_valid)?;
                assert_eq!(reference.current().objects.len(), 2);
                assert_eq!(oracle.view_at(2)?.snapshot(), *reference.current());
                assert_eq!(
                    reference.current().objects[&ObjectId::parse(OBJECT)?].plane,
                    from
                );
                assert_eq!(
                    reference.current().objects[&ObjectId::parse(OBJECT)?].family,
                    "zzz_tombstone"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn earlier_batch_and_generation_errors_keep_their_existing_precedence() -> Test {
    let History { first, counterfeit, valid } = history(Plane::Cognition, Plane::Authority)?;
    for mode in MODES {
        let mut ledger = ReferenceLedger::replay_with_snapshot_retention(
            SITE,
            mode,
            [first.clone()],
        )?;
        let mut reused = counterfeit.clone();
        reused.batch_id = first.batch_id.clone();
        reused.basis_anchor = ReferenceLedger::new(SITE).current().anchor.clone();
        reused.batch_digest = reused.computed_digest();
        assert_unchanged_refusal(&mut ledger, reused, &ContractError::IdempotencyConflict);

        let mut stale = counterfeit.clone();
        stale.basis_anchor = ReferenceLedger::new(SITE).current().anchor.clone();
        stale.batch_digest = stale.computed_digest();
        assert_unchanged_refusal(&mut ledger, stale, &ContractError::StaleAnchor);

        let mut successor = counterfeit.clone();
        successor.new_anchor.commit_sequence = 3;
        successor.batch_digest = successor.computed_digest();
        assert_unchanged_refusal(&mut ledger, successor, &ContractError::InvalidAnchorSuccessor);

        let mut order = counterfeit.clone();
        order.deltas.reverse();
        order.batch_digest = order.computed_digest();
        assert_unchanged_refusal(&mut ledger, order, &ContractError::NonCanonicalOrdering);

        let mut digest = counterfeit.clone();
        digest.batch_digest = ContentDigest::sha256(b"incorrect batch digest");
        assert_unchanged_refusal(&mut ledger, digest, &ContractError::DigestMismatch);

        let mut prior = counterfeit.clone();
        prior.deltas.last_mut().ok_or("owned revision")?.prior_generation = Some(0);
        prior.batch_digest = prior.computed_digest();
        assert_unchanged_refusal(&mut ledger, prior, &ContractError::GenerationConflict);

        let mut generation = counterfeit.clone();
        generation.deltas.last_mut().ok_or("owned revision")?.new_generation = 3;
        generation.batch_digest = generation.computed_digest();
        assert_unchanged_refusal(&mut ledger, generation, &ContractError::GenerationConflict);

        ledger.append(valid.clone())?;
        assert_eq!(ledger.batches(), [first.clone(), valid.clone()]);
    }
    Ok(())
}

#[test]
fn durable_preparation_and_append_refuse_before_journal_io_and_allow_same_plane_retry() -> Test {
    let directory = Directory::new("live")?;
    let path = directory.journal();
    let History { first, counterfeit, valid } = history(Plane::Cognition, Plane::Authority)?;
    let expected = conflict(Plane::Cognition, Plane::Authority)?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    durable.append(first.clone())?;
    let before = fs::read(&path)?;
    let snapshot = durable.current().clone();
    let root = durable.journal_root();
    let prepare_error = durable.prepare_batch(
        counterfeit.batch_id.clone(),
        counterfeit.deltas.clone(),
        [],
    ).err().ok_or("durable preparation admitted a plane mutation")?;
    assert_durable_conflict(prepare_error, &expected)?;
    let append_error = durable.append(counterfeit).err().ok_or("durable append admitted a plane mutation")?;
    assert_durable_conflict(append_error, &expected)?;
    assert_eq!(durable.current(), &snapshot);
    assert_eq!(durable.batches(), [first.clone()]);
    assert_eq!(durable.retained_snapshot_count(), 1);
    assert_eq!(durable.verify_storage()?, root);
    assert_eq!(fs::read(&path)?, before);

    let prepared = durable.prepare_batch(valid.batch_id.clone(), valid.deltas.clone(), [])?;
    assert_eq!(prepared, valid);
    durable.append(prepared)?;
    let reference = ReferenceLedger::replay(SITE, [first, valid])?;
    assert_eq!(durable.current(), reference.current());
    let committed = fs::read(&path)?;
    drop(durable);
    let mut reopened = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.current(), reference.current());
    assert_eq!(reopened.verify_storage()?, reopened.journal_root());
    assert_eq!(inspect_durable(&path, SITE, committed.len())?.snapshot, *reference.current());
    assert_eq!(fs::read(&path)?, committed);
    Ok(())
}

#[test]
fn an_old_plane_mutation_is_rejected_before_any_torn_tail_repair() -> Test {
    let directory = Directory::new("invalid-prefix")?;
    let path = directory.journal();
    let History { first, counterfeit, .. } = history(Plane::Cognition, Plane::Effect)?;
    let expected = conflict(Plane::Cognition, Plane::Effect)?;
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(1, &encode_batch(&first)?)?;
    journal.append(1, &encode_batch(&counterfeit)?)?;
    journal.fail_after_phase(AppendPhase::BodyWrite);
    assert!(matches!(
        journal.append(1, b"uncommitted tail"),
        Err(JournalError::AppendIndeterminate { .. })
    ));
    drop(journal);
    let before = fs::read(&path)?;
    assert!(inspect(&path)?.incomplete_tail().is_some());
    assert_eq!(
        ReferenceLedger::replay(SITE, [first.clone(), counterfeit.clone()]).err(),
        Some(expected.clone())
    );
    assert!(matches!(
        LedgerOracle::rebuild(SITE, OracleLimits::CEILING, [first, counterfeit]),
        Err(OracleReplayError::Batch { position: 1, error })
            if matches!(*error, OracleError::PlaneConflict {
                committed_plane: Plane::Cognition,
                delta_plane: Plane::Effect,
                ..
            })
    ));
    for policy in [IncompleteTailPolicy::Reject, IncompleteTailPolicy::Truncate] {
        let error = DurableReferenceLedger::open(&path, SITE, policy)
            .err()
            .ok_or("durable replay admitted an invalid committed prefix")?;
        assert_durable_conflict(error, &expected)?;
        assert_eq!(fs::read(&path)?, before, "a semantic refusal must preserve the torn tail");
    }
    let error = inspect_durable(&path, SITE, before.len())
        .err()
        .ok_or("durable inspection admitted a plane mutation")?;
    assert_durable_conflict(error, &expected)?;
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}
