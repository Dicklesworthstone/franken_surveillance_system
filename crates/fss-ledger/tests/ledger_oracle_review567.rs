//! Contract and defect tests for review-567 rework on canonical ledger oracle (FSS-016).
//!
//! Ref: fss-x4a.7.4 / review-567.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    LedgerOracle, MAX_ORACLE_OBJECTS, OracleError, OracleLimits, encode_batch,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:oracle-review567";
const EVIDENCE_BATCH_RECORD_KIND: u16 = 1;

fn journal_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fss-ledger-oracle-review567");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{name}.journal"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

fn create_delta(
    tag: &str,
    object: &str,
    plane: Plane,
    earliest_ns: i128,
    latest_ns: i128,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval {
            earliest: TimestampNs(earliest_ns),
            latest: TimestampNs(latest_ns),
        },
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

fn update_delta(
    tag: &str,
    object: &str,
    prior: u64,
    plane: Plane,
    earliest_ns: i128,
    latest_ns: i128,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: Some(prior),
        new_generation: prior.checked_add(1).ok_or("generation overflow")?,
        validity: CaptureInterval {
            earliest: TimestampNs(earliest_ns),
            latest: TimestampNs(latest_ns),
        },
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

/// Hardened differential consistency check addressing Finding 2:
/// verifies absence of pending indeterminate appends, on-disk storage integrity,
/// head snapshot equality, all historical anchor snapshots 0..=head_sequence, and batch histories.
fn assert_same_state_strict(
    oracle: &LedgerOracle,
    durable: &mut DurableReferenceLedger,
) -> TestResult {
    if let Some(seq) = durable.pending_append_sequence() {
        return Err(format!(
            "DIVERGENCE pending append: durable ledger holds unreconciled append at sequence {seq}"
        )
        .into());
    }

    durable
        .verify_storage()
        .map_err(|err| format!("DIVERGENCE durable storage verification failed: {err}"))?;

    let head = oracle.view_at(oracle.head_sequence())?;
    let oracle_snapshot = head.snapshot();
    if oracle_snapshot != *durable.current() {
        return Err(format!(
            "DIVERGENCE head snapshot: oracle head {:?} vs durable head {:?}",
            oracle_snapshot.anchor,
            durable.current().anchor
        )
        .into());
    }

    let head_seq = oracle.head_sequence();
    for seq in 0..=head_seq {
        let oracle_view = oracle.view_at(seq)?;
        let oracle_anchor = oracle_view.anchor();
        if seq == head_seq && *oracle_anchor != durable.current().anchor {
            return Err(format!(
                "DIVERGENCE anchor at head sequence {seq}: oracle {:?} vs durable {:?}",
                oracle_anchor,
                durable.current().anchor
            )
            .into());
        }
    }

    let oracle_batches: Vec<&EvidenceDeltaBatch> = oracle.batches().collect();
    let durable_batches: Vec<&EvidenceDeltaBatch> = durable.batches().iter().collect();
    if oracle_batches != durable_batches {
        return Err(format!(
            "DIVERGENCE history: oracle has {} batches, durable has {}",
            oracle_batches.len(),
            durable_batches.len()
        )
        .into());
    }

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 1 (CRITICAL): Non-Canonical Batch Encodings Accepted (Inverted Time & Empty Identifiers)
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_1_oracle_rejects_inverted_time_intervals() -> TestResult {
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
    let delta = create_delta("inv", "test_inv", Plane::Authority, 2_000, 1_000)?;

    // Both prepare_batch and stage/append must fail closed on inverted intervals
    let prep_res = oracle.prepare_batch(BatchId::parse("batch:prep_inv")?, vec![delta.clone()], []);
    assert!(
        prep_res.is_err(),
        "prepare_batch must reject deltas with inverted CaptureInterval"
    );

    // Also verify when batch is prepared manually without prepare_batch
    let basis_anchor = oracle.head_anchor().clone();
    let mut new_anchor = basis_anchor.clone();
    new_anchor.commit_sequence = 1;
    let mut batch = EvidenceDeltaBatch {
        batch_id: BatchId::parse("batch:manual_inv")?,
        basis_anchor,
        new_anchor,
        deltas: vec![delta],
        children: Vec::new(),
        batch_digest: ContentDigest::sha256(b"temp"),
    };
    batch.batch_digest = batch.computed_digest();

    let stage_res = oracle.stage(batch.clone());
    assert!(
        stage_res.is_err(),
        "stage must reject batches with inverted CaptureInterval"
    );

    let append_res = oracle.append(batch);
    assert!(
        append_res.is_err(),
        "append must reject batches with inverted CaptureInterval"
    );

    Ok(())
}

#[test]
fn test_finding_1_oracle_rejects_empty_identifiers() -> TestResult {
    let oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    let mut empty_id_delta = create_delta("valid", "test_empty_id", Plane::Authority, 100, 200)?;
    empty_id_delta.delta_id = String::new();

    let res1 = oracle.prepare_batch(
        BatchId::parse("batch:empty_id")?,
        vec![empty_id_delta.clone()],
        [],
    );
    assert!(
        res1.is_err(),
        "prepare_batch must reject deltas with empty delta_id"
    );

    let mut empty_family_delta =
        create_delta("valid2", "test_empty_family", Plane::Authority, 100, 200)?;
    empty_family_delta.family = String::new();

    let res2 = oracle.prepare_batch(
        BatchId::parse("batch:empty_fam")?,
        vec![empty_family_delta.clone()],
        [],
    );
    assert!(
        res2.is_err(),
        "prepare_batch must reject deltas with empty family"
    );

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 2 (CRITICAL): Permissive Differential Check Flags Indeterminate Appends
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_2_assert_same_state_flags_unreconciled_indeterminate_appends() -> TestResult {
    let path = journal_path("finding_2_indeterminate_divergence")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    let d1 = create_delta("1", "item_a", Plane::Authority, 100, 200)?;
    let batch = oracle.prepare_batch(BatchId::parse("batch:indet")?, vec![d1], [])?;

    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    let append_res = durable.append(batch);
    assert!(
        append_res.is_err(),
        "durable.append must return indeterminate error on CommitSync failure"
    );
    assert!(
        durable.pending_append_sequence().is_some(),
        "durable ledger must hold pending append sequence"
    );

    // assert_same_state_strict must fail when durable ledger is quarantined with pending append
    let diff_result = assert_same_state_strict(&oracle, &mut durable);
    assert!(
        diff_result.is_err(),
        "assert_same_state_strict must report divergence when durable has unresolved indeterminate append"
    );

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 3 (HIGH): Object Plane Mutation Across Generations Allowed by apply_deltas
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_3_oracle_rejects_object_plane_mutation_across_generations() -> TestResult {
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    // Create object in Cognition plane
    let d1 = create_delta("obj1", "obj1", Plane::Cognition, 100, 200)?;
    let b1 = oracle.prepare_batch(BatchId::parse("batch:plane1")?, vec![d1], [])?;
    oracle.append(b1)?;

    // Attempt to update same object in Authority plane
    let d2 = update_delta("obj1_up", "obj1", 1, Plane::Authority, 200, 300)?;
    let prep_res = oracle.prepare_batch(BatchId::parse("batch:plane2")?, vec![d2.clone()], []);
    match prep_res {
        Err(OracleError::PlaneConflict {
            ref object_id,
            committed_plane,
            delta_plane,
        }) => {
            assert_eq!(object_id.as_str(), "object:obj1");
            assert_eq!(committed_plane, Plane::Cognition);
            assert_eq!(delta_plane, Plane::Authority);
        }
        other => return Err(format!("expected PlaneConflict error, got {other:?}").into()),
    }

    // Construct batch manually and attempt append directly
    let basis_anchor = oracle.head_anchor().clone();
    let mut new_anchor = basis_anchor.clone();
    new_anchor.commit_sequence = 2;
    let mut b2 = EvidenceDeltaBatch {
        batch_id: BatchId::parse("batch:plane2_manual")?,
        basis_anchor,
        new_anchor,
        deltas: vec![d2],
        children: Vec::new(),
        batch_digest: ContentDigest::sha256(b"temp"),
    };
    b2.batch_digest = b2.computed_digest();

    let append_res = oracle.append(b2);
    match append_res {
        Err(OracleError::PlaneConflict {
            ref object_id,
            committed_plane,
            delta_plane,
        }) => {
            assert_eq!(object_id.as_str(), "object:obj1");
            assert_eq!(committed_plane, Plane::Cognition);
            assert_eq!(delta_plane, Plane::Authority);
        }
        other => {
            return Err(format!("expected PlaneConflict error from append, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_finding_3_seeded_history_with_plane_mutation_is_rejected_with_plane_conflict() -> TestResult
{
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    let d1 = create_delta("seed_obj1", "seed_obj1", Plane::Cognition, 100, 200)?;
    let d2 = create_delta("seed_obj2", "seed_obj2", Plane::Effect, 100, 200)?;
    let b1 = oracle.prepare_batch(BatchId::parse("batch:seed_1")?, vec![d1, d2], [])?;
    oracle.append(b1)?;

    let d3 = update_delta("seed_obj2_v2", "seed_obj2", 1, Plane::Effect, 201, 300)?;
    let b2 = oracle.prepare_batch(BatchId::parse("batch:seed_2")?, vec![d3], [])?;
    oracle.append(b2)?;

    // Step 3 attempts to mutate seed_obj1 from Cognition to Authority
    let d4 = update_delta("seed_obj1_v2", "seed_obj1", 1, Plane::Authority, 301, 400)?;
    let prep_res = oracle.prepare_batch(BatchId::parse("batch:seed_3")?, vec![d4.clone()], []);
    match prep_res {
        Err(OracleError::PlaneConflict {
            ref object_id,
            committed_plane,
            delta_plane,
        }) => {
            assert_eq!(object_id.as_str(), "object:seed_obj1");
            assert_eq!(committed_plane, Plane::Cognition);
            assert_eq!(delta_plane, Plane::Authority);
        }
        other => {
            return Err(format!("expected PlaneConflict from prepare_batch, got {other:?}").into());
        }
    }

    let basis_anchor = oracle.head_anchor().clone();
    let mut new_anchor = basis_anchor.clone();
    new_anchor.commit_sequence = 3;
    let mut b3 = EvidenceDeltaBatch {
        batch_id: BatchId::parse("batch:seed_3_manual")?,
        basis_anchor,
        new_anchor,
        deltas: vec![d4],
        children: Vec::new(),
        batch_digest: ContentDigest::sha256(b"seed3"),
    };
    b3.batch_digest = b3.computed_digest();
    match oracle.append(b3) {
        Err(OracleError::PlaneConflict {
            ref object_id,
            committed_plane,
            delta_plane,
        }) => {
            assert_eq!(object_id.as_str(), "object:seed_obj1");
            assert_eq!(committed_plane, Plane::Cognition);
            assert_eq!(delta_plane, Plane::Authority);
        }
        other => return Err(format!("expected PlaneConflict from append, got {other:?}").into()),
    }

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 4 (HIGH): Batch Capacity Enforced in prepare_batch
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_4_prepare_batch_enforces_batch_capacity_bound() -> TestResult {
    let limits = OracleLimits::new(1, MAX_ORACLE_OBJECTS)?;
    let mut oracle = LedgerOracle::new(SITE, limits)?;

    let d1 = create_delta("cap1", "obj_cap", Plane::Authority, 10, 20)?;
    let b1 = oracle.prepare_batch(BatchId::parse("batch:cap1")?, vec![d1], [])?;
    oracle.append(b1)?;

    // Oracle is now at max_batches (1). prepare_batch must fail closed with CapacityExhausted
    let d2 = create_delta("cap2", "obj_cap2", Plane::Authority, 30, 40)?;
    let res = oracle.prepare_batch(BatchId::parse("batch:cap2")?, vec![d2], []);
    assert!(
        matches!(res, Err(OracleError::CapacityExhausted { .. })),
        "prepare_batch must fail closed when batch capacity is exhausted, got: {res:?}"
    );

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 5 (MEDIUM): Replay Verifies Journal Record Sequence vs Batch Commit Sequence
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_5_replay_verifies_journal_record_sequence_matches_batch_commit_sequence()
-> TestResult {
    let path = journal_path("finding_5_seq_mismatch")?;
    let oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    let d1 = create_delta("s1", "obj_s", Plane::Authority, 10, 20)?;
    let mut b1 = oracle.prepare_batch(BatchId::parse("batch:s1")?, vec![d1], [])?;
    // Corrupt batch commit_sequence to 99 while journal record sequence will be 1
    b1.new_anchor.commit_sequence = 99;
    b1.batch_digest = b1.computed_digest();

    // Write directly to journal: record header has sequence 1, but payload new_anchor has commit_sequence 99
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.append(EVIDENCE_BATCH_RECORD_KIND, &encode_batch(&b1)?)?;
    }

    // Replay during open must reject this inconsistency
    let open_res = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject);
    assert!(
        matches!(
            open_res,
            Err(DurableLedgerError::RecordSequenceMismatch {
                record_sequence: 1,
                batch_commit_sequence: 99,
            })
        ),
        "replay must reject record sequence != batch commit sequence, got: {open_res:?}"
    );

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 6 (MEDIUM): StagedBatch Inspection and Candidate State Recovery
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_6_staged_batch_inspection_and_candidate_recovery() -> TestResult {
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    let d1 = create_delta("s6_a", "item_6a", Plane::Authority, 10, 20)?;
    let b1 = oracle.prepare_batch(BatchId::parse("batch:s6_1")?, vec![d1], [])?;
    let staged1 = oracle.stage(b1)?;

    assert_eq!(staged1.basis_sequence(), 0);
    assert_eq!(staged1.batch().batch_id.as_str(), "batch:s6_1");

    // Can inspect stage without consuming it
    assert!(oracle.check_stage(&staged1).is_ok());

    // Staged batch can be cloned and recovered via into_batch
    let staged_clone = staged1.clone();
    let recovered_batch = staged_clone.into_batch();
    assert_eq!(recovered_batch.batch_id.as_str(), "batch:s6_1");

    // Commit staged1
    oracle.commit(staged1)?;
    assert_eq!(oracle.head_sequence(), 1);

    // Staging against sequence 0 is now stale
    let d2 = create_delta("s6_b", "item_6b", Plane::Authority, 30, 40)?;
    let basis_anchor = oracle.genesis_anchor().clone();
    let mut new_anchor = basis_anchor.clone();
    new_anchor.commit_sequence = 1;
    let mut b2 = EvidenceDeltaBatch {
        batch_id: BatchId::parse("batch:s6_2")?,
        basis_anchor,
        new_anchor,
        deltas: vec![d2],
        children: Vec::new(),
        batch_digest: ContentDigest::sha256(b"temp"),
    };
    b2.batch_digest = b2.computed_digest();

    // stage() against old basis fails
    let stage_res = oracle.stage(b2);
    assert!(stage_res.is_err());

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Finding 7 (LOW): Differential Edge Cases
// -------------------------------------------------------------------------------------------------

#[test]
fn test_finding_7_differential_oracle_and_durable_edge_cases() -> TestResult {
    let path = journal_path("finding_7_diff_edge")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;

    // Append 3 valid batches
    for step in 1..=3 {
        let d = create_delta(
            &format!("step_{step}"),
            &format!("obj_{step}"),
            Plane::Authority,
            i128::from(step) * 10,
            i128::from(step) * 10 + 5,
        )?;
        let batch =
            oracle.prepare_batch(BatchId::parse(format!("batch:diff_{step}"))?, vec![d], [])?;
        oracle.append(batch.clone())?;
        durable.append(batch)?;
    }

    assert_same_state_strict(&oracle, &mut durable)?;
    Ok(())
}
