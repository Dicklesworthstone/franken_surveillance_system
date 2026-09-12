//! Contract tests for the FSS-016 in-memory canonical ledger oracle.
//!
//! Ref: fss-x4a.7.4 / FSS-016.
//!
//! Failure tests come first: out-of-order, duplicate, conflicting, forked, malformed, read past
//! the head anchor, capacity bounds, stale/cancelled stages, and replay determinism. Differential
//! tests then drive identical batches through `LedgerOracle` and the durable
//! `DurableReferenceLedger` journal (including injected indeterminate appends and restart) and
//! compare state, history, and rejection classification. Known classification differences are
//! asserted as an explicit mapping; the one state divergence found is retained as negative
//! evidence in `divergence_batch_id_reuse_is_rejected_by_oracle_but_accepted_by_durable_journal`.
//!
//! Every scenario emits one bounded, secret-free JSON line on stdout with scenario, seed, fixture
//! root, anchor epochs, transitions, outcome, digests, and a reproduction command.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::PathBuf;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    LedgerSnapshot, ObjectId, Plane, ReferenceLedger, TimestampNs,
};
use fss_ledger::{
    AnchorField, AppendPhase, BatchCodecError, DurableAppendReconciliation, DurableLedgerError,
    DurableReferenceLedger, IncompleteTailPolicy, JournalError, LedgerOracle, MAX_ORACLE_BATCHES,
    MAX_ORACLE_CHILDREN_PER_BATCH, MAX_ORACLE_DELTAS_PER_BATCH, MAX_ORACLE_OBJECTS,
    MAX_ORACLE_TEXT_BYTES, ObjectRead, OracleBoundField, OracleConfigField, OracleError,
    OracleGuidance, OracleLimits, OracleReadError, OracleReplayError,
};

type TestResult = Result<(), Box<dyn Error>>;
type Step = (BatchId, Vec<EvidenceDelta>, Vec<ContentDigest>);

const SITE: &str = "site:oracle-contract";
const MAX_LOG_TRANSITIONS: usize = 256;
const PROPERTY_SEEDS: [u64; 5] = [1, 7, 42, 0xFEED, 2026];
const PROPERTY_BATCHES: u64 = 24;

/// Pinned history-chain root of `canonical_fixture()` (domain `fss.ledger_oracle_history.v1`).
const GOLDEN_HISTORY_ROOT: &str =
    "sha256:5bc40c5bfd1d6421ed6e945d7b13dd979ae87747002751ea0e46b76fb8f5aaae";
/// Pinned head state root of `canonical_fixture()` (domain `fss.reference_state.v1`).
const GOLDEN_STATE_ROOT: &str =
    "sha256:3fa3ba13816cdf0cdcbbce65f100831f73fab0d9d7dbdb861e63ef5b0c3a2b26";

// ---------------------------------------------------------------------------------------------
// Structured scenario log
// ---------------------------------------------------------------------------------------------

struct ScenarioLog {
    scenario: &'static str,
    seed: u64,
    transitions: Vec<String>,
}

impl ScenarioLog {
    fn new(scenario: &'static str, seed: u64) -> Self {
        Self {
            scenario,
            seed,
            transitions: Vec::new(),
        }
    }

    fn record(&mut self, transition: impl Into<String>) -> TestResult {
        if self.transitions.len() >= MAX_LOG_TRANSITIONS {
            return Err(format!(
                "scenario {} exceeded {MAX_LOG_TRANSITIONS} logged transitions",
                self.scenario
            )
            .into());
        }
        self.transitions.push(transition.into());
        Ok(())
    }

    fn emit(&self, oracle: &LedgerOracle, outcome: &str) {
        let fingerprint = oracle.fingerprint();
        let anchor = &fingerprint.head_anchor;
        let transitions = self
            .transitions
            .iter()
            .map(|transition| format!("\"{transition}\""))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"contract\":\"FSS-016\",\"scenario\":\"{scenario}\",\"seed\":{seed},\
\"fixture_root\":\"in-memory:crates/fss-ledger/tests/ledger_oracle_contract.rs\",\
\"site_lineage\":\"{site}\",\"ledger_epoch\":{ledger_epoch},\"schema_epoch\":{schema_epoch},\
\"policy_epoch\":{policy_epoch},\"privacy_epoch\":{privacy_epoch},\
\"authority_scope\":\"single-owner-oracle\",\"transitions\":[{transitions}],\
\"outcome\":\"{outcome}\",\"head_sequence\":{head},\"batch_count\":{batches},\
\"object_count\":{objects},\"state_root\":\"{state_root}\",\"history_root\":\"{history_root}\",\
\"repro\":\"cargo +nightly-2026-08-31 test -p fss-ledger --test ledger_oracle_contract -- \
{scenario} --exact --nocapture\"}}",
            scenario = self.scenario,
            seed = self.seed,
            site = anchor.site_lineage,
            ledger_epoch = anchor.ledger_epoch,
            schema_epoch = anchor.schema_epoch,
            policy_epoch = anchor.policy_epoch,
            privacy_epoch = anchor.privacy_epoch,
            head = anchor.commit_sequence,
            batches = fingerprint.batch_count,
            objects = fingerprint.object_count,
            state_root = anchor.state_root,
            history_root = fingerprint.history_root,
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn interval(step: u64) -> Result<CaptureInterval, ContractError> {
    let start = i128::from(step) * 10;
    CaptureInterval::new(TimestampNs(start), TimestampNs(start + 5))
}

fn delta(
    tag: &str,
    object: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation,
        new_generation,
        validity: interval(new_generation)?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

fn create(tag: &str, object: &str) -> Result<EvidenceDelta, Box<dyn Error>> {
    delta(tag, object, None, 1)
}

fn update(tag: &str, object: &str, prior: u64) -> Result<EvidenceDelta, Box<dyn Error>> {
    delta(tag, object, Some(prior), prior + 1)
}

fn object(name: &str) -> Result<ObjectId, ContractError> {
    ObjectId::parse(format!("object:{name}"))
}

fn batch_id(name: &str) -> Result<BatchId, ContractError> {
    BatchId::parse(format!("batch:{name}"))
}

fn child(name: &str) -> ContentDigest {
    ContentDigest::sha256(format!("child:{name}").as_bytes())
}

fn oracle() -> Result<LedgerOracle, OracleError> {
    LedgerOracle::new(SITE, OracleLimits::CEILING)
}

fn reseal(mut batch: EvidenceDeltaBatch) -> EvidenceDeltaBatch {
    batch.batch_digest = batch.computed_digest();
    batch
}

fn at(batches: &[EvidenceDeltaBatch], index: usize) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    batches
        .get(index)
        .cloned()
        .ok_or_else(|| format!("fixture has no batch at index {index}").into())
}

/// Canonical three-batch inputs, deliberately given in non-canonical delta/child order.
fn fixture_steps() -> Result<Vec<Step>, Box<dyn Error>> {
    Ok(vec![
        (
            batch_id("1")?,
            vec![create("1b", "b")?, create("1a", "a")?],
            vec![child("1"), child("1")],
        ),
        (
            batch_id("2")?,
            vec![create("2c", "c")?, update("2a", "a", 1)?],
            Vec::new(),
        ),
        (
            batch_id("3")?,
            vec![update("3c", "c", 1)?, update("3b", "b", 1)?],
            vec![child("3b"), child("3a")],
        ),
    ])
}

fn canonical_fixture() -> Result<Vec<EvidenceDeltaBatch>, Box<dyn Error>> {
    let mut builder = oracle()?;
    let mut batches = Vec::new();
    for (id, deltas, children) in fixture_steps()? {
        let batch = builder.prepare_batch(id, deltas, children)?;
        builder.append(batch.clone())?;
        batches.push(batch);
    }
    Ok(batches)
}

fn expect_err<T: Debug>(result: Result<T, OracleError>) -> Result<OracleError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected an oracle rejection, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn expect_read_err<T: Debug>(
    result: Result<T, OracleReadError>,
) -> Result<OracleReadError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a read rejection, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn expect_present(read: ObjectRead<'_>) -> Result<(u64, u64), Box<dyn Error>> {
    match read {
        ObjectRead::Present {
            revision,
            committed_sequence,
        } => Ok((revision.generation, committed_sequence)),
        ObjectRead::AbsentAtAnchor { sequence } => {
            Err(format!("expected a present object, absent at {sequence}").into())
        }
    }
}

fn journal_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fss-ledger-oracle-contract");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{name}.journal"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

/// Fails with a retained divergence description when oracle and durable state differ.
fn assert_same_state(oracle: &LedgerOracle, durable: &DurableReferenceLedger) -> TestResult {
    let head = oracle.view_at(oracle.head_sequence())?;
    let oracle_snapshot = head.snapshot();
    if oracle_snapshot != *durable.current() {
        return Err(format!(
            "DIVERGENCE state: oracle head {:?} vs durable head {:?}",
            oracle_snapshot.anchor,
            durable.current().anchor
        )
        .into());
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

fn durable_contract_error(
    result: Result<&LedgerSnapshot, DurableLedgerError>,
) -> Result<ContractError, Box<dyn Error>> {
    match result {
        Err(DurableLedgerError::Contract(error)) => Ok(error),
        Err(other) => Err(format!("expected a durable contract rejection, got {other}").into()),
        Ok(snapshot) => Err(format!(
            "DIVERGENCE durable accepted a batch the oracle rejected at {:?}",
            snapshot.anchor
        )
        .into()),
    }
}

fn durable_codec_error(
    result: Result<&LedgerSnapshot, DurableLedgerError>,
) -> Result<BatchCodecError, Box<dyn Error>> {
    match result {
        Err(DurableLedgerError::Codec(error)) => Ok(error),
        Err(other) => Err(format!("expected a durable codec rejection, got {other}").into()),
        Ok(snapshot) => Err(format!(
            "DIVERGENCE durable accepted an over-bound batch at {:?}",
            snapshot.anchor
        )
        .into()),
    }
}

// ---------------------------------------------------------------------------------------------
// Failure tests: ordering, duplicates, conflicts
// ---------------------------------------------------------------------------------------------

#[test]
fn out_of_order_batch_is_rejected_as_sequence_gap_without_state_change() -> TestResult {
    let mut log = ScenarioLog::new(
        "out_of_order_batch_is_rejected_as_sequence_gap_without_state_change",
        0,
    );
    let fixture = canonical_fixture()?;
    let mut oracle = oracle()?;
    let genesis = oracle.fingerprint();

    let error = expect_err(oracle.append(at(&fixture, 1)?))?;
    assert_eq!(
        error,
        OracleError::SequenceGap {
            head_sequence: 0,
            basis_sequence: 1
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-SEQUENCE-GAP-001");
    assert_eq!(error.guidance(), OracleGuidance::SupplyPredecessors);
    assert_eq!(oracle.fingerprint(), genesis);
    log.record(format!("offer batch:2 at head 0 -> {}", error.code()))?;

    oracle.append(at(&fixture, 0)?)?;
    let after_first = oracle.fingerprint();
    let error = expect_err(oracle.append(at(&fixture, 2)?))?;
    assert_eq!(
        error,
        OracleError::SequenceGap {
            head_sequence: 1,
            basis_sequence: 2
        }
    );
    assert_eq!(oracle.fingerprint(), after_first);
    log.record(format!("offer batch:3 at head 1 -> {}", error.code()))?;

    oracle.append(at(&fixture, 1)?)?;
    oracle.append(at(&fixture, 2)?)?;
    assert_eq!(oracle.head_sequence(), 3);
    log.record("commit batch:2 then batch:3 in order")?;
    log.emit(&oracle, "rejected_then_committed_in_order");
    Ok(())
}

#[test]
fn duplicate_batch_is_rejected_with_its_committed_sequence() -> TestResult {
    let mut log = ScenarioLog::new("duplicate_batch_is_rejected_with_its_committed_sequence", 0);
    let fixture = canonical_fixture()?;
    let mut oracle = oracle()?;
    oracle.append(at(&fixture, 0)?)?;
    oracle.append(at(&fixture, 1)?)?;
    let before = oracle.fingerprint();

    for (index, sequence) in [(0_usize, 1_u64), (1, 2)] {
        let offered = at(&fixture, index)?;
        let error = expect_err(oracle.append(offered.clone()))?;
        assert_eq!(
            error,
            OracleError::DuplicateBatch {
                batch_id: offered.batch_id.clone(),
                committed_sequence: sequence
            }
        );
        assert_eq!(error.code(), "ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001");
        assert_eq!(error.guidance(), OracleGuidance::AlreadyCommitted);
        assert_eq!(oracle.fingerprint(), before);
        log.record(format!("re-offer {} -> {}", offered.batch_id, error.code()))?;
    }
    log.emit(&oracle, "duplicates_rejected");
    Ok(())
}

#[test]
fn conflicting_batch_identity_reuse_is_rejected() -> TestResult {
    let mut log = ScenarioLog::new("conflicting_batch_identity_reuse_is_rejected", 0);
    let fixture = canonical_fixture()?;
    let first = at(&fixture, 0)?;
    let mut oracle = oracle()?;
    oracle.append(first.clone())?;
    let before = oracle.fingerprint();

    let reuse = oracle.prepare_batch(first.batch_id.clone(), vec![create("x", "x")?], [])?;
    let error = expect_err(oracle.append(reuse.clone()))?;
    assert_eq!(
        error,
        OracleError::BatchIdConflict {
            batch_id: first.batch_id.clone(),
            committed_sequence: 1,
            committed_digest: first.batch_digest,
            offered_digest: reuse.batch_digest,
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001");
    assert_eq!(error.guidance(), OracleGuidance::RejectInput);
    assert_eq!(oracle.fingerprint(), before);
    log.record(format!(
        "reuse {} with new content -> {}",
        first.batch_id,
        error.code()
    ))?;
    log.emit(&oracle, "batch_id_conflict_rejected");
    Ok(())
}

#[test]
fn conflicting_successor_loses_first_committer_race_and_can_rebase() -> TestResult {
    let mut log = ScenarioLog::new(
        "conflicting_successor_loses_first_committer_race_and_can_rebase",
        0,
    );
    let mut oracle = oracle()?;
    let winner = oracle.prepare_batch(batch_id("winner")?, vec![create("w", "w")?], [])?;
    let loser = oracle.prepare_batch(batch_id("loser")?, vec![create("l", "l")?], [])?;
    oracle.append(winner.clone())?;
    let before = oracle.fingerprint();

    let error = expect_err(oracle.append(loser))?;
    assert_eq!(
        error,
        OracleError::SuccessorConflict {
            basis_sequence: 0,
            head_sequence: 1,
            committed_batch_id: winner.batch_id.clone(),
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-SUCCESSOR-CONFLICT-001");
    assert_eq!(error.guidance(), OracleGuidance::Rebase);
    assert_eq!(oracle.fingerprint(), before);
    log.record(format!("loser on basis 0 -> {}", error.code()))?;

    let rebased = oracle.prepare_batch(batch_id("loser")?, vec![create("l", "l")?], [])?;
    let receipt = oracle.append(rebased)?;
    assert_eq!(receipt.sequence, 2);
    log.record("rebased loser committed at 2")?;
    log.emit(&oracle, "first_committer_wins");
    Ok(())
}

#[test]
fn forked_basis_anchor_is_rejected() -> TestResult {
    let mut log = ScenarioLog::new("forked_basis_anchor_is_rejected", 0);
    let mut oracle = oracle()?;
    let before = oracle.fingerprint();

    let foreign = LedgerOracle::new("site:foreign", OracleLimits::CEILING)?;
    let foreign_batch = foreign.prepare_batch(batch_id("foreign")?, vec![create("f", "f")?], [])?;
    let error = expect_err(oracle.append(foreign_batch))?;
    assert_eq!(error, OracleError::BasisForked { basis_sequence: 0 });
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-BASIS-FORKED-001");
    assert_eq!(oracle.fingerprint(), before);
    log.record(format!("foreign lineage basis -> {}", error.code()))?;

    oracle.append(oracle.prepare_batch(batch_id("1")?, vec![create("a", "a")?], [])?)?;
    let mut forked = oracle.prepare_batch(batch_id("2")?, vec![create("b", "b")?], [])?;
    forked.basis_anchor.state_root = ContentDigest::sha256(b"forked-state");
    let error = expect_err(oracle.append(reseal(forked)))?;
    assert_eq!(error, OracleError::BasisForked { basis_sequence: 1 });
    log.record(format!(
        "same-sequence different-root basis -> {}",
        error.code()
    ))?;
    log.emit(&oracle, "forks_rejected");
    Ok(())
}

#[test]
fn malformed_batches_are_rejected_with_typed_errors_and_no_state_change() -> TestResult {
    let mut log = ScenarioLog::new(
        "malformed_batches_are_rejected_with_typed_errors_and_no_state_change",
        0,
    );
    let mut oracle = oracle()?;
    oracle.append(oracle.prepare_batch(batch_id("1")?, vec![create("1a", "a")?], [])?)?;
    let before = oracle.fingerprint();
    let valid = oracle.prepare_batch(
        batch_id("2")?,
        vec![update("2a", "a", 1)?, create("2d", "d")?],
        [],
    )?;

    // Digest does not cover tampered content.
    let mut tampered = valid.clone();
    tampered
        .deltas
        .first_mut()
        .ok_or("fixture has no delta")?
        .payload_digest = ContentDigest::sha256(b"tampered");
    let computed = tampered.computed_digest();
    let error = expect_err(oracle.append(tampered))?;
    assert_eq!(
        error,
        OracleError::BatchDigestMismatch {
            batch_id: valid.batch_id.clone(),
            declared: valid.batch_digest,
            computed,
        }
    );
    log.record(error.code())?;

    // Non-canonical delta order.
    let mut reversed = valid.clone();
    reversed.deltas.reverse();
    let error = expect_err(oracle.append(reseal(reversed)))?;
    assert_eq!(
        error,
        OracleError::NonCanonicalOrdering {
            batch_id: valid.batch_id.clone()
        }
    );
    log.record(error.code())?;

    // Non-canonical (duplicate) child roots.
    let mut duplicate_children = valid.clone();
    duplicate_children.children = vec![child("x"), child("x")];
    let error = expect_err(oracle.append(reseal(duplicate_children)))?;
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-NON-CANONICAL-001");

    // Successor anchor must follow its basis in every field.
    type AnchorMutation = (AnchorField, fn(&mut EvidenceDeltaBatch));
    let mutations: [AnchorMutation; 7] = [
        (AnchorField::SiteLineage, |batch| {
            batch.new_anchor.site_lineage.push_str(":moved");
        }),
        (AnchorField::LedgerEpoch, |batch| {
            batch.new_anchor.ledger_epoch += 1;
        }),
        (AnchorField::CommitSequence, |batch| {
            batch.new_anchor.commit_sequence += 1;
        }),
        (AnchorField::AdapterRegistryEpoch, |batch| {
            batch.new_anchor.adapter_registry_epoch += 1;
        }),
        (AnchorField::SchemaEpoch, |batch| {
            batch.new_anchor.schema_epoch += 1;
        }),
        (AnchorField::PolicyEpoch, |batch| {
            batch.new_anchor.policy_epoch += 1;
        }),
        (AnchorField::PrivacyEpoch, |batch| {
            batch.new_anchor.privacy_epoch += 1;
        }),
    ];
    for (field, mutate) in mutations {
        let mut moved = valid.clone();
        mutate(&mut moved);
        let error = expect_err(oracle.append(reseal(moved)))?;
        assert_eq!(error, OracleError::InvalidSuccessorAnchor { field });
        log.record(format!("{field:?} -> {}", error.code()))?;
    }

    // Generation skips, re-creation, and phantom priors.
    let object_a = object("a")?;
    let generation_cases = [
        (delta("g1", "a", Some(1), 3)?, Some(1), Some(1), 3),
        (delta("g2", "a", None, 1)?, Some(1), None, 1),
        (delta("g3", "z", Some(7), 8)?, None, Some(7), 8),
    ];
    for (bad, committed, prior, new_generation) in generation_cases {
        let object_id = bad.object_id.clone();
        let mut batch = valid.clone();
        batch.deltas = vec![bad];
        let error = expect_err(oracle.append(reseal(batch)))?;
        assert_eq!(
            error,
            OracleError::GenerationConflict {
                object_id,
                committed_generation: committed,
                prior_generation: prior,
                new_generation,
            }
        );
        log.record(error.code())?;
    }

    // Two deltas for one object inside one batch.
    let mut duplicate_object = valid.clone();
    duplicate_object.deltas = vec![update("dup1", "a", 1)?, delta("dup2", "a", Some(2), 3)?];
    let error = expect_err(oracle.append(reseal(duplicate_object)))?;
    assert_eq!(
        error,
        OracleError::DuplicateObjectInBatch {
            object_id: object_a.clone()
        }
    );
    log.record(error.code())?;

    // Declared state root does not match applied deltas.
    let mut wrong_root = valid.clone();
    wrong_root.new_anchor.state_root = ContentDigest::sha256(b"wrong-root");
    let error = expect_err(oracle.append(reseal(wrong_root)))?;
    assert_eq!(
        error,
        OracleError::StateRootMismatch {
            declared: ContentDigest::sha256(b"wrong-root"),
            computed: valid.new_anchor.state_root,
        }
    );
    log.record(error.code())?;

    assert_eq!(oracle.fingerprint(), before);
    oracle.append(valid)?;
    log.record("valid successor committed after every rejection")?;
    log.emit(&oracle, "malformed_rejected_state_unchanged");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Failure tests: anchor-pinned reads
// ---------------------------------------------------------------------------------------------

#[test]
fn reads_are_anchor_pinned_and_never_observe_later_batches() -> TestResult {
    let mut log = ScenarioLog::new("reads_are_anchor_pinned_and_never_observe_later_batches", 0);
    let fixture = canonical_fixture()?;
    let mut oracle = oracle()?;
    oracle.append(at(&fixture, 0)?)?;
    let snapshot_one = oracle.view_at(1)?.snapshot();
    let history_one = oracle.view_at(1)?.history_root();

    oracle.append(at(&fixture, 1)?)?;
    oracle.append(at(&fixture, 2)?)?;
    let view_one = oracle.view_at(1)?;
    assert_eq!(view_one.snapshot(), snapshot_one);
    assert_eq!(view_one.history_root(), history_one);
    assert_eq!(view_one.batches().count(), 1);
    assert_eq!(expect_present(view_one.object(&object("a")?))?, (1, 1));
    assert_eq!(
        view_one.object(&object("c")?),
        ObjectRead::AbsentAtAnchor { sequence: 1 }
    );
    log.record("view 1 unchanged after commits 2 and 3")?;

    let view_two = oracle.view_at(2)?;
    assert_eq!(expect_present(view_two.object(&object("a")?))?, (2, 2));
    assert_eq!(expect_present(view_two.object(&object("b")?))?, (1, 1));
    assert_eq!(expect_present(view_two.object(&object("c")?))?, (1, 2));

    let genesis = oracle.view_at(0)?;
    assert!(genesis.snapshot().objects.is_empty());
    assert_eq!(genesis.anchor(), oracle.genesis_anchor());
    assert_eq!(
        genesis.object(&object("a")?),
        ObjectRead::AbsentAtAnchor { sequence: 0 }
    );

    let exact = oracle.view_at_anchor(&at(&fixture, 1)?.new_anchor)?;
    assert_eq!(exact.sequence(), 2);
    log.record("exact anchor 2 resolves")?;
    log.emit(&oracle, "anchor_pinned_reads_stable");
    Ok(())
}

#[test]
fn read_past_head_anchor_is_rejected() -> TestResult {
    let mut log = ScenarioLog::new("read_past_head_anchor_is_rejected", 0);
    let fixture = canonical_fixture()?;
    let mut oracle = oracle()?;
    oracle.append(at(&fixture, 0)?)?;
    oracle.append(at(&fixture, 1)?)?;

    let error = expect_read_err(oracle.view_at(3))?;
    assert_eq!(
        error,
        OracleReadError::BeyondHead {
            requested: 3,
            head: 2
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-READ-BEYOND-HEAD-001");
    log.record(format!("view_at 3 at head 2 -> {}", error.code()))?;

    let error = expect_read_err(oracle.view_at(u64::MAX))?;
    assert_eq!(
        error,
        OracleReadError::BeyondHead {
            requested: u64::MAX,
            head: 2
        }
    );

    let future_anchor = at(&fixture, 2)?.new_anchor;
    let error = expect_read_err(oracle.view_at_anchor(&future_anchor))?;
    assert_eq!(
        error,
        OracleReadError::BeyondHead {
            requested: 3,
            head: 2
        }
    );
    log.record(format!("anchor of uncommitted batch:3 -> {}", error.code()))?;

    let mut forged = at(&fixture, 0)?.new_anchor;
    forged.state_root = ContentDigest::sha256(b"forged");
    let error = expect_read_err(oracle.view_at_anchor(&forged))?;
    assert_eq!(error, OracleReadError::AnchorMismatch { sequence: 1 });
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-READ-ANCHOR-MISMATCH-001");

    let foreign = LedgerOracle::new("site:foreign", OracleLimits::CEILING)?;
    let error = expect_read_err(oracle.view_at_anchor(foreign.genesis_anchor()))?;
    assert_eq!(error, OracleReadError::AnchorMismatch { sequence: 0 });
    log.record(format!("forged and foreign anchors -> {}", error.code()))?;
    log.emit(&oracle, "reads_past_head_rejected");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Failure tests: capacity bounds at exactly the bound and bound + 1
// ---------------------------------------------------------------------------------------------

#[test]
fn limit_configuration_is_validated_at_bound_and_bound_plus_one() -> TestResult {
    assert_eq!(
        OracleLimits::new(0, 1),
        Err(OracleError::InvalidConfig {
            field: OracleConfigField::MaxBatches,
            value: 0,
            maximum: MAX_ORACLE_BATCHES
        })
    );
    assert_eq!(
        OracleLimits::new(MAX_ORACLE_BATCHES, MAX_ORACLE_OBJECTS)?,
        OracleLimits::CEILING
    );
    assert_eq!(
        OracleLimits::new(MAX_ORACLE_BATCHES + 1, 1),
        Err(OracleError::InvalidConfig {
            field: OracleConfigField::MaxBatches,
            value: MAX_ORACLE_BATCHES + 1,
            maximum: MAX_ORACLE_BATCHES
        })
    );
    assert_eq!(
        OracleLimits::new(1, 0),
        Err(OracleError::InvalidConfig {
            field: OracleConfigField::MaxObjects,
            value: 0,
            maximum: MAX_ORACLE_OBJECTS
        })
    );
    assert_eq!(
        OracleLimits::new(1, MAX_ORACLE_OBJECTS + 1),
        Err(OracleError::InvalidConfig {
            field: OracleConfigField::MaxObjects,
            value: MAX_ORACLE_OBJECTS + 1,
            maximum: MAX_ORACLE_OBJECTS
        })
    );

    let at_bound = "s".repeat(MAX_ORACLE_TEXT_BYTES);
    let oracle = LedgerOracle::new(at_bound.clone(), OracleLimits::CEILING)?;
    assert_eq!(oracle.genesis_anchor().site_lineage, at_bound);
    let error = expect_err(LedgerOracle::new(
        "s".repeat(MAX_ORACLE_TEXT_BYTES + 1),
        OracleLimits::CEILING,
    ))?;
    assert_eq!(
        error,
        OracleError::InvalidConfig {
            field: OracleConfigField::SiteLineage,
            value: MAX_ORACLE_TEXT_BYTES + 1,
            maximum: MAX_ORACLE_TEXT_BYTES
        }
    );
    assert_eq!(error.guidance(), OracleGuidance::RepairConfiguration);
    let error = expect_err(LedgerOracle::new("", OracleLimits::CEILING))?;
    assert_eq!(
        error,
        OracleError::InvalidConfig {
            field: OracleConfigField::SiteLineage,
            value: 0,
            maximum: MAX_ORACLE_TEXT_BYTES
        }
    );
    Ok(())
}

#[test]
fn batch_capacity_admits_exactly_the_bound_and_rejects_bound_plus_one() -> TestResult {
    let mut log = ScenarioLog::new(
        "batch_capacity_admits_exactly_the_bound_and_rejects_bound_plus_one",
        0,
    );
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::new(3, MAX_ORACLE_OBJECTS)?)?;
    let mut committed = Vec::new();
    for index in 1..=3 {
        let name = index.to_string();
        let batch = oracle.prepare_batch(batch_id(&name)?, vec![create(&name, &name)?], [])?;
        oracle.append(batch.clone())?;
        committed.push(batch);
        log.record(format!("commit batch:{index}"))?;
    }
    assert_eq!(oracle.batch_count(), 3);
    let full = oracle.fingerprint();

    let fourth = oracle.prepare_batch(batch_id("4")?, vec![create("4", "4")?], [])?;
    let error = expect_err(oracle.append(fourth))?;
    assert_eq!(error, OracleError::CapacityExhausted { max_batches: 3 });
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-CAPACITY-001");
    assert_eq!(error.guidance(), OracleGuidance::ArchiveOrRotate);
    assert_eq!(oracle.fingerprint(), full);
    log.record(format!("batch:4 at capacity 3 -> {}", error.code()))?;

    let error = expect_err(oracle.append(at(&committed, 0)?))?;
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001");
    log.emit(&oracle, "capacity_bound_enforced");
    Ok(())
}

#[test]
fn object_capacity_admits_exactly_the_bound_and_rejects_bound_plus_one() -> TestResult {
    let mut log = ScenarioLog::new(
        "object_capacity_admits_exactly_the_bound_and_rejects_bound_plus_one",
        0,
    );
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::new(16, 2)?)?;
    let mut unbounded = self::oracle()?;
    let first = oracle.prepare_batch(
        batch_id("1")?,
        vec![create("1a", "a")?, create("1b", "b")?],
        [],
    )?;
    oracle.append(first.clone())?;
    unbounded.append(first)?;
    let full = oracle.fingerprint();
    log.record("two objects at object capacity 2")?;

    let error = expect_err(oracle.prepare_batch(batch_id("2")?, vec![create("2c", "c")?], []))?;
    assert_eq!(
        error,
        OracleError::ObjectCapacityExhausted {
            max_objects: 2,
            required: 3
        }
    );
    let third = unbounded.prepare_batch(batch_id("2")?, vec![create("2c", "c")?], [])?;
    let error = expect_err(oracle.append(third))?;
    assert_eq!(
        error,
        OracleError::ObjectCapacityExhausted {
            max_objects: 2,
            required: 3
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-OBJECT-CAPACITY-001");
    assert_eq!(oracle.fingerprint(), full);
    log.record(format!("third object -> {}", error.code()))?;

    let updates = oracle.prepare_batch(
        batch_id("3")?,
        vec![update("3a", "a", 1)?, update("3b", "b", 1)?],
        [],
    )?;
    oracle.append(updates)?;
    log.record("updates at capacity still commit")?;
    log.emit(&oracle, "object_capacity_enforced");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Failure tests: staged, cancelled, and stale publications
// ---------------------------------------------------------------------------------------------

#[test]
fn staged_batches_are_invisible_cancellable_and_refused_when_stale() -> TestResult {
    let mut log = ScenarioLog::new(
        "staged_batches_are_invisible_cancellable_and_refused_when_stale",
        0,
    );
    let mut oracle = oracle()?;
    let genesis = oracle.fingerprint();
    let first = oracle.prepare_batch(batch_id("1")?, vec![create("a", "a")?], [])?;

    let staged = oracle.stage(first.clone())?;
    assert_eq!(staged.basis_sequence(), 0);
    assert_eq!(staged.batch(), &first);
    assert_eq!(oracle.fingerprint(), genesis);
    assert_eq!(
        expect_read_err(oracle.view_at(1))?,
        OracleReadError::BeyondHead {
            requested: 1,
            head: 0
        }
    );
    drop(staged);
    assert_eq!(oracle.fingerprint(), genesis);
    log.record("stage then drop leaves genesis")?;

    let left = oracle.prepare_batch(batch_id("left")?, vec![create("x", "x")?], [])?;
    let right = oracle.prepare_batch(batch_id("right")?, vec![create("y", "y")?], [])?;
    let staged_left = oracle.stage(left)?;
    let staged_right = oracle.stage(right)?;
    let promised_root = staged_left.history_root();
    let receipt = oracle.commit(staged_left)?;
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.history_root, promised_root);
    assert_eq!(receipt.history_root, oracle.head_history_root());
    let after_left = oracle.fingerprint();

    let error = expect_err(oracle.commit(staged_right))?;
    assert_eq!(
        error,
        OracleError::StaleStage {
            staged_basis_sequence: 0,
            head_sequence: 1
        }
    );
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-STALE-STAGE-001");
    assert_eq!(error.guidance(), OracleGuidance::Restage);
    assert_eq!(oracle.fingerprint(), after_left);
    log.record(format!("commit stale right stage -> {}", error.code()))?;

    let mut other = self::oracle()?;
    other.append(other.prepare_batch(batch_id("other")?, vec![create("o", "o")?], [])?)?;
    let foreign_stage =
        other.stage(other.prepare_batch(batch_id("q")?, vec![create("q", "q")?], [])?)?;
    let error = expect_err(oracle.commit(foreign_stage))?;
    assert_eq!(
        error,
        OracleError::StaleStage {
            staged_basis_sequence: 1,
            head_sequence: 1
        }
    );
    assert_eq!(oracle.fingerprint(), after_left);
    log.record(format!(
        "commit stage from another history -> {}",
        error.code()
    ))?;
    log.emit(&oracle, "stage_lifecycle_enforced");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Replay determinism
// ---------------------------------------------------------------------------------------------

#[test]
fn replay_rebuild_is_bit_identical_and_prefix_consistent() -> TestResult {
    let mut log = ScenarioLog::new("replay_rebuild_is_bit_identical_and_prefix_consistent", 0);
    let fixture = canonical_fixture()?;
    let first = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, fixture.clone())?;
    let second = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, fixture.clone())?;
    assert_eq!(first.fingerprint(), second.fingerprint());
    let exported: Vec<EvidenceDeltaBatch> = first.batches().cloned().collect();
    assert_eq!(exported, fixture);
    let third = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, exported)?;
    assert_eq!(third.fingerprint(), first.fingerprint());

    for length in 0..=fixture.len() {
        let prefix = fixture.get(..length).ok_or("prefix out of range")?.to_vec();
        let rebuilt = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, prefix)?;
        let view = first.view_at(u64::try_from(length)?)?;
        assert_eq!(rebuilt.head_history_root(), view.history_root());
        assert_eq!(
            rebuilt.view_at(rebuilt.head_sequence())?.snapshot(),
            view.snapshot()
        );
        log.record(format!("prefix {length} root {}", view.history_root()))?;
    }

    println!(
        "golden history_root={} state_root={}",
        first.head_history_root(),
        first.head_anchor().state_root
    );
    assert_eq!(first.head_history_root().to_string(), GOLDEN_HISTORY_ROOT);
    assert_eq!(
        first.head_anchor().state_root.to_string(),
        GOLDEN_STATE_ROOT
    );

    let gapped = vec![at(&fixture, 0)?, at(&fixture, 2)?];
    let error = match LedgerOracle::rebuild(SITE, OracleLimits::CEILING, gapped) {
        Ok(oracle) => {
            return Err(format!("gapped replay succeeded: {:?}", oracle.fingerprint()).into());
        }
        Err(error) => error,
    };
    assert_eq!(
        error,
        OracleReplayError::Batch {
            position: 1,
            error: Box::new(OracleError::SequenceGap {
                head_sequence: 1,
                basis_sequence: 2
            })
        }
    );
    let error = match LedgerOracle::rebuild("", OracleLimits::CEILING, fixture) {
        Ok(oracle) => {
            return Err(format!("empty lineage accepted: {:?}", oracle.fingerprint()).into());
        }
        Err(error) => error,
    };
    assert!(matches!(
        error,
        OracleReplayError::Config(OracleError::InvalidConfig {
            field: OracleConfigField::SiteLineage,
            ..
        })
    ));
    log.emit(&first, "replay_bit_identical");
    Ok(())
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

fn random_history(seed: u64, length: u64) -> Result<Vec<EvidenceDeltaBatch>, Box<dyn Error>> {
    const FAMILIES: [&str; 3] = ["sensor_capsule", "track", "coverage"];
    const PLANES: [Plane; 3] = [Plane::Authority, Plane::Cognition, Plane::Effect];
    let mut rng = SplitMix64::new(seed);
    let mut builder = oracle()?;
    let mut history = Vec::new();
    for step in 1..=length {
        let touch = 1 + rng.below(4);
        let mut chosen = BTreeSet::new();
        while u64::try_from(chosen.len())? < touch {
            chosen.insert(rng.below(8));
        }
        let mut deltas = Vec::new();
        for slot in chosen {
            let object_id = ObjectId::parse(format!("object:prop:{slot}"))?;
            let head = builder.view_at(builder.head_sequence())?;
            let prior = match head.object(&object_id) {
                ObjectRead::Present { revision, .. } => Some(revision.generation),
                ObjectRead::AbsentAtAnchor { .. } => None,
            };
            let new_generation = match prior {
                Some(generation) => generation.checked_add(1).ok_or("generation overflow")?,
                None => 1,
            };
            let family = FAMILIES
                .get(usize::try_from(rng.below(3))?)
                .ok_or("family index")?;
            let plane = *PLANES
                .get(usize::try_from(rng.below(3))?)
                .ok_or("plane index")?;
            let salt = rng.next_u64();
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:{seed}:{step}:{slot}"),
                family: (*family).to_owned(),
                object_id,
                prior_generation: prior,
                new_generation,
                validity: interval(step)?,
                plane,
                payload_digest: ContentDigest::sha256(
                    format!("payload:{seed}:{step}:{slot}:{salt}").as_bytes(),
                ),
                witness_digest: if rng.below(2) == 0 {
                    None
                } else {
                    Some(ContentDigest::sha256(
                        format!("witness:{seed}:{step}:{slot}").as_bytes(),
                    ))
                },
                operation_id: None,
            });
        }
        let children: Vec<ContentDigest> = (0..rng.below(3))
            .map(|index| child(&format!("{seed}:{step}:{index}")))
            .collect();
        let batch = builder.prepare_batch(
            BatchId::parse(format!("batch:prop:{seed}:{step}"))?,
            deltas,
            children,
        )?;
        builder.append(batch.clone())?;
        history.push(batch);
    }
    Ok(history)
}

#[test]
fn seeded_histories_replay_identically_and_reject_reorders_metamorphically() -> TestResult {
    for seed in PROPERTY_SEEDS {
        let mut log = ScenarioLog::new(
            "seeded_histories_replay_identically_and_reject_reorders_metamorphically",
            seed,
        );
        let history = random_history(seed, PROPERTY_BATCHES)?;
        let first = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, history.clone())?;
        let second = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, history.clone())?;
        assert_eq!(first.fingerprint(), second.fingerprint());
        log.record(format!("rebuild x2 root {}", first.head_history_root()))?;

        // N-version agreement with the core reference ledger at every anchor.
        let core = ReferenceLedger::replay(SITE, history.clone())?;
        assert_eq!(&core.current().anchor, first.head_anchor());
        for sequence in 0..=PROPERTY_BATCHES {
            let view = first.view_at(sequence)?;
            let core_snapshot = core
                .snapshot_at(sequence)
                .ok_or_else(|| format!("core has no snapshot at {sequence}"))?;
            if view.snapshot() != *core_snapshot {
                return Err(format!("DIVERGENCE seed {seed} sequence {sequence}").into());
            }
            let prefix = history
                .get(..usize::try_from(sequence)?)
                .ok_or("prefix out of range")?
                .to_vec();
            let rebuilt = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, prefix)?;
            assert_eq!(rebuilt.head_history_root(), view.history_root());
        }
        log.record("core snapshots and prefix roots agree at every anchor")?;

        // Metamorphic: swapping adjacent batches is always rejected at the swap point.
        let mut rng = SplitMix64::new(seed ^ 0xA5A5);
        let swap = usize::try_from(rng.below(PROPERTY_BATCHES - 1))?;
        let mut swapped = history.clone();
        swapped.swap(swap, swap + 1);
        let error = match LedgerOracle::rebuild(SITE, OracleLimits::CEILING, swapped) {
            Ok(oracle) => {
                return Err(format!("swapped replay succeeded: {:?}", oracle.fingerprint()).into());
            }
            Err(error) => error,
        };
        let head = u64::try_from(swap)?;
        assert_eq!(
            error,
            OracleReplayError::Batch {
                position: swap,
                error: Box::new(OracleError::SequenceGap {
                    head_sequence: head,
                    basis_sequence: head + 1
                })
            }
        );
        log.record(format!("swap {swap}<->{} -> sequence gap", swap + 1))?;

        // Metamorphic: resubmitting any committed batch is a duplicate at its sequence.
        let resubmit = usize::try_from(rng.below(PROPERTY_BATCHES))?;
        let offered = at(&history, resubmit)?;
        assert_eq!(
            expect_err(first.stage(offered.clone()))?,
            OracleError::DuplicateBatch {
                batch_id: offered.batch_id,
                committed_sequence: u64::try_from(resubmit)? + 1
            }
        );
        log.record(format!("resubmit index {resubmit} -> duplicate"))?;
        log.emit(&first, "property_invariants_hold");
    }
    Ok(())
}

#[test]
fn oracle_and_core_reference_prepare_bit_identical_batches() -> TestResult {
    let mut log = ScenarioLog::new("oracle_and_core_reference_prepare_bit_identical_batches", 0);
    let mut oracle = oracle()?;
    let mut core = ReferenceLedger::new(SITE);
    assert_eq!(oracle.genesis_anchor(), &core.current().anchor);
    for (id, deltas, children) in fixture_steps()? {
        let from_oracle = oracle.prepare_batch(id.clone(), deltas.clone(), children.clone())?;
        let from_core = core.prepare_batch(id, deltas, children)?;
        assert_eq!(from_oracle, from_core);
        oracle.append(from_oracle)?;
        core.append(from_core)?;
        assert_eq!(
            oracle.view_at(oracle.head_sequence())?.snapshot(),
            *core.current()
        );
        log.record(format!("sequence {} identical", oracle.head_sequence()))?;
    }
    log.emit(&oracle, "n_version_prepare_identical");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Differential tests against the durable fss-ledger journal
// ---------------------------------------------------------------------------------------------

#[test]
fn differential_oracle_matches_durable_journal_batch_by_batch_and_after_restart() -> TestResult {
    let mut log = ScenarioLog::new(
        "differential_oracle_matches_durable_journal_batch_by_batch_and_after_restart",
        0,
    );
    let path = journal_path("differential_batch_by_batch")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut oracle = oracle()?;
    assert_same_state(&oracle, &durable)?;

    let fixture = canonical_fixture()?;
    for batch in &fixture {
        let receipt = oracle.append(batch.clone())?;
        let durable_anchor = durable.append(batch.clone())?.anchor.clone();
        assert_eq!(durable_anchor, receipt.anchor);
        assert_same_state(&oracle, &durable)?;
        log.record(format!(
            "both commit {} at {}",
            batch.batch_id, receipt.sequence
        ))?;
    }

    // Negative cases offered to both at head 3. Classification map (oracle -> durable).
    let next = oracle.prepare_batch(
        batch_id("4")?,
        vec![update("4a", "a", 2)?, create("4d", "d")?],
        [],
    )?;
    let alternative = LedgerOracle::rebuild(
        SITE,
        OracleLimits::CEILING,
        fixture.get(..2).ok_or("prefix")?.to_vec(),
    )?
    .prepare_batch(batch_id("alt")?, vec![create("alt", "alt")?], [])?;
    let mut ahead = oracle.clone();
    ahead.append(next.clone())?;
    let gapped = ahead.prepare_batch(batch_id("5")?, vec![create("5e", "e")?], [])?;
    let mut forked = next.clone();
    forked.basis_anchor.state_root = ContentDigest::sha256(b"forked");
    let forked = reseal(forked);
    let mut tampered = next.clone();
    tampered
        .deltas
        .first_mut()
        .ok_or("fixture has no delta")?
        .payload_digest = ContentDigest::sha256(b"tampered");
    let tampered_digest = tampered.computed_digest();
    let mut reversed = next.clone();
    reversed.deltas.reverse();
    let mut epoch = next.clone();
    epoch.new_anchor.policy_epoch += 1;
    let mut skipped = next.clone();
    skipped.deltas = vec![delta("4a", "a", Some(2), 4)?, create("4d", "d")?];
    let mut duplicate_object = next.clone();
    duplicate_object.deltas = vec![create("4d", "d")?, delta("4d2", "d", Some(1), 2)?];
    let mut wrong_root = next.clone();
    wrong_root.new_anchor.state_root = ContentDigest::sha256(b"wrong-root");

    let cases: Vec<(&str, EvidenceDeltaBatch, OracleError, ContractError)> = vec![
        (
            "duplicate_first",
            at(&fixture, 0)?,
            OracleError::DuplicateBatch {
                batch_id: batch_id("1")?,
                committed_sequence: 1,
            },
            ContractError::StaleAnchor,
        ),
        (
            "duplicate_head",
            at(&fixture, 2)?,
            OracleError::DuplicateBatch {
                batch_id: batch_id("3")?,
                committed_sequence: 3,
            },
            ContractError::StaleAnchor,
        ),
        (
            "successor_conflict",
            alternative,
            OracleError::SuccessorConflict {
                basis_sequence: 2,
                head_sequence: 3,
                committed_batch_id: batch_id("3")?,
            },
            ContractError::StaleAnchor,
        ),
        (
            "sequence_gap",
            gapped,
            OracleError::SequenceGap {
                head_sequence: 3,
                basis_sequence: 4,
            },
            ContractError::StaleAnchor,
        ),
        (
            "basis_forked",
            forked,
            OracleError::BasisForked { basis_sequence: 3 },
            ContractError::StaleAnchor,
        ),
        (
            "digest_mismatch",
            tampered,
            OracleError::BatchDigestMismatch {
                batch_id: batch_id("4")?,
                declared: next.batch_digest,
                computed: tampered_digest,
            },
            ContractError::DigestMismatch,
        ),
        (
            "non_canonical",
            reseal(reversed),
            OracleError::NonCanonicalOrdering {
                batch_id: batch_id("4")?,
            },
            ContractError::NonCanonicalOrdering,
        ),
        (
            "invalid_successor",
            reseal(epoch),
            OracleError::InvalidSuccessorAnchor {
                field: AnchorField::PolicyEpoch,
            },
            ContractError::InvalidAnchorSuccessor,
        ),
        (
            "generation_skip",
            reseal(skipped),
            OracleError::GenerationConflict {
                object_id: object("a")?,
                committed_generation: Some(2),
                prior_generation: Some(2),
                new_generation: 4,
            },
            ContractError::GenerationConflict,
        ),
        (
            "duplicate_object",
            reseal(duplicate_object),
            OracleError::DuplicateObjectInBatch {
                object_id: object("d")?,
            },
            ContractError::GenerationConflict,
        ),
        (
            "state_root_mismatch",
            reseal(wrong_root),
            OracleError::StateRootMismatch {
                declared: ContentDigest::sha256(b"wrong-root"),
                computed: next.new_anchor.state_root,
            },
            ContractError::DigestMismatch,
        ),
    ];

    for (name, batch, oracle_expected, durable_expected) in cases {
        let oracle_before = oracle.fingerprint();
        let journal_before = durable.journal_root();
        let oracle_error = expect_err(oracle.append(batch.clone()))?;
        if oracle_error != oracle_expected {
            return Err(format!("{name}: oracle {oracle_error:?} != {oracle_expected:?}").into());
        }
        let durable_error = durable_contract_error(durable.append(batch))?;
        if durable_error != durable_expected {
            return Err(
                format!("{name}: durable {durable_error:?} != {durable_expected:?}").into(),
            );
        }
        assert_eq!(oracle.fingerprint(), oracle_before);
        assert_eq!(durable.journal_root(), journal_before);
        assert_same_state(&oracle, &durable)?;
        log.record(format!(
            "{name}: oracle {} durable {}",
            oracle_error.code(),
            durable_error.code()
        ))?;
    }

    oracle.append(next.clone())?;
    durable.append(next)?;
    assert_same_state(&oracle, &durable)?;
    let journal_root = durable.verify_storage()?;
    log.record(format!("both commit batch:4; journal root {journal_root}"))?;

    drop(durable);
    let reopened = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    assert_same_state(&oracle, &reopened)?;
    assert_eq!(reopened.journal_root(), journal_root);
    let rebuilt = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, reopened.batches().to_vec())?;
    assert_eq!(rebuilt.fingerprint(), oracle.fingerprint());
    log.record("restart: reopened journal and rebuilt oracle agree")?;
    log.emit(&oracle, "differential_agree");
    Ok(())
}

#[test]
fn differential_fault_injected_appends_reconcile_to_oracle_state() -> TestResult {
    let mut log = ScenarioLog::new(
        "differential_fault_injected_appends_reconcile_to_oracle_state",
        0,
    );
    let path = journal_path("differential_fault_reconcile")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut oracle = oracle()?;

    // Crash after the commit trailer is durable: reconciliation proves Committed.
    let first = oracle.prepare_batch(batch_id("1")?, vec![create("a", "a")?], [child("1")])?;
    let staged = oracle.stage(first.clone())?;
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    let outcome = durable.append(first.clone());
    if !matches!(
        outcome,
        Err(DurableLedgerError::Journal(
            JournalError::AppendIndeterminate {
                phase: AppendPhase::CommitSync,
                ..
            }
        ))
    ) {
        return Err(format!("expected indeterminate CommitSync append, got {outcome:?}").into());
    }
    assert_eq!(durable.pending_append_sequence(), Some(1));
    assert_same_state(&oracle, &durable)?;
    log.record("fault CommitSync -> indeterminate; neither side visible")?;
    match durable.reconcile_pending(IncompleteTailPolicy::Reject)? {
        DurableAppendReconciliation::Committed { sequence, batch_id } => {
            assert_eq!(sequence, 1);
            assert_eq!(batch_id, first.batch_id);
            oracle.commit(staged)?;
        }
        other => return Err(format!("expected Committed reconciliation, got {other:?}").into()),
    }
    assert_same_state(&oracle, &durable)?;
    log.record("reconcile Committed -> oracle commits stage")?;

    // Crash after only the body write: reconciliation proves NotCommitted.
    let second = oracle.prepare_batch(batch_id("2")?, vec![update("a2", "a", 1)?], [])?;
    let staged = oracle.stage(second.clone())?;
    durable.fail_journal_after_phase(AppendPhase::BodyWrite);
    let outcome = durable.append(second.clone());
    if !matches!(
        outcome,
        Err(DurableLedgerError::Journal(
            JournalError::AppendIndeterminate {
                phase: AppendPhase::BodyWrite,
                ..
            }
        ))
    ) {
        return Err(format!("expected indeterminate BodyWrite append, got {outcome:?}").into());
    }
    match durable.reconcile_pending(IncompleteTailPolicy::Truncate)? {
        DurableAppendReconciliation::NotCommitted { sequence } => {
            assert_eq!(sequence, 2);
            drop(staged);
        }
        other => {
            return Err(format!("expected NotCommitted reconciliation, got {other:?}").into());
        }
    }
    assert_same_state(&oracle, &durable)?;
    log.record("fault BodyWrite -> reconcile NotCommitted -> oracle drops stage")?;

    oracle.append(second.clone())?;
    durable.append(second)?;
    assert_same_state(&oracle, &durable)?;
    durable.verify_storage()?;
    log.record("retry commits on both")?;
    log.emit(&oracle, "fault_reconciliation_agrees");
    Ok(())
}

fn bulk_deltas(count: usize) -> Result<Vec<EvidenceDelta>, Box<dyn Error>> {
    (0..count)
        .map(|index| {
            Ok(EvidenceDelta {
                delta_id: format!("delta:bulk:{index}"),
                family: "bulk".to_owned(),
                object_id: ObjectId::parse(format!("object:bulk:{index:05}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: interval(1)?,
                plane: Plane::Cognition,
                payload_digest: ContentDigest::sha256(format!("bulk:{index}").as_bytes()),
                witness_digest: None,
                operation_id: None,
            })
        })
        .collect()
}

fn bulk_children(count: usize) -> Vec<ContentDigest> {
    (0..count)
        .map(|index| child(&format!("bulk:{index}")))
        .collect()
}

#[test]
fn per_batch_bounds_match_durable_codec_at_bound_and_bound_plus_one() -> TestResult {
    let mut log = ScenarioLog::new(
        "per_batch_bounds_match_durable_codec_at_bound_and_bound_plus_one",
        0,
    );
    let path = journal_path("per_batch_bounds")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut oracle = oracle()?;

    // Bound + 1: the core reference prepares these without bounds; both sides must refuse.
    let core = ReferenceLedger::new(SITE);
    let over_deltas = core.prepare_batch(
        batch_id("over-deltas")?,
        bulk_deltas(MAX_ORACLE_DELTAS_PER_BATCH + 1)?,
        [],
    )?;
    let over_children = core.prepare_batch(
        batch_id("over-children")?,
        vec![create("oc", "oc")?],
        bulk_children(MAX_ORACLE_CHILDREN_PER_BATCH + 1),
    )?;
    let mut long_family = create("lf", "lf")?;
    long_family.family = "f".repeat(MAX_ORACLE_TEXT_BYTES + 1);
    let over_family = core.prepare_batch(batch_id("over-family")?, vec![long_family], [])?;
    let mut long_id = create("li", "li")?;
    long_id.delta_id = "d".repeat(MAX_ORACLE_TEXT_BYTES + 1);
    let over_delta_id = core.prepare_batch(batch_id("over-delta-id")?, vec![long_id], [])?;

    let over_cases = [
        (
            over_deltas,
            OracleBoundField::Deltas,
            MAX_ORACLE_DELTAS_PER_BATCH,
            "deltas",
        ),
        (
            over_children,
            OracleBoundField::Children,
            MAX_ORACLE_CHILDREN_PER_BATCH,
            "children",
        ),
        (
            over_family,
            OracleBoundField::FamilyText,
            MAX_ORACLE_TEXT_BYTES,
            "text",
        ),
        (
            over_delta_id,
            OracleBoundField::DeltaIdText,
            MAX_ORACLE_TEXT_BYTES,
            "text",
        ),
    ];
    for (batch, field, maximum, codec_field) in over_cases {
        let error = expect_err(oracle.append(batch.clone()))?;
        assert_eq!(
            error,
            OracleError::BoundExceeded {
                field,
                length: maximum + 1,
                maximum
            }
        );
        assert_eq!(error.code(), "ERR-LEDGER-ORACLE-BOUND-001");
        let codec_error = durable_codec_error(durable.append(batch))?;
        assert_eq!(codec_error, BatchCodecError::BoundExceeded(codec_field));
        assert_same_state(&oracle, &durable)?;
        log.record(format!("{field:?} at bound+1: oracle and codec refuse"))?;
    }
    let error = expect_err(oracle.prepare_batch(
        batch_id("over-deltas")?,
        bulk_deltas(MAX_ORACLE_DELTAS_PER_BATCH + 1)?,
        [],
    ))?;
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-BOUND-001");

    // Exactly at each bound: both sides accept and agree.
    let at_deltas = oracle.prepare_batch(
        batch_id("at-deltas")?,
        bulk_deltas(MAX_ORACLE_DELTAS_PER_BATCH)?,
        [],
    )?;
    oracle.append(at_deltas.clone())?;
    durable.append(at_deltas)?;
    assert_same_state(&oracle, &durable)?;
    log.record("deltas exactly at bound commit on both")?;

    let mut family_at_bound = create("fb", "fb")?;
    family_at_bound.family = "f".repeat(MAX_ORACLE_TEXT_BYTES);
    let mut id_at_bound = create("ib", "ib")?;
    id_at_bound.delta_id = "d".repeat(MAX_ORACLE_TEXT_BYTES);
    let at_children = oracle.prepare_batch(
        batch_id("at-children")?,
        vec![family_at_bound, id_at_bound],
        bulk_children(MAX_ORACLE_CHILDREN_PER_BATCH),
    )?;
    oracle.append(at_children.clone())?;
    durable.append(at_children)?;
    assert_same_state(&oracle, &durable)?;
    durable.verify_storage()?;
    log.record("children and text exactly at bound commit on both")?;
    log.emit(&oracle, "bounds_agree_with_codec");
    Ok(())
}

#[test]
fn durable_replay_of_same_batches_is_byte_identical_and_matches_oracle() -> TestResult {
    let mut log = ScenarioLog::new(
        "durable_replay_of_same_batches_is_byte_identical_and_matches_oracle",
        PROPERTY_SEEDS[2],
    );
    let history = random_history(PROPERTY_SEEDS[2], 12)?;
    let left_path = journal_path("replay_identical_left")?;
    let right_path = journal_path("replay_identical_right")?;
    for path in [&left_path, &right_path] {
        let mut durable = DurableReferenceLedger::open(path, SITE, IncompleteTailPolicy::Reject)?;
        for batch in &history {
            durable.append(batch.clone())?;
        }
        durable.verify_storage()?;
    }
    assert_eq!(fs::read(&left_path)?, fs::read(&right_path)?);
    log.record("two journals from the same batches are byte-identical")?;

    let reopened = DurableReferenceLedger::open(&left_path, SITE, IncompleteTailPolicy::Reject)?;
    let oracle = LedgerOracle::rebuild(SITE, OracleLimits::CEILING, history.clone())?;
    let from_journal =
        LedgerOracle::rebuild(SITE, OracleLimits::CEILING, reopened.batches().to_vec())?;
    assert_eq!(from_journal.fingerprint(), oracle.fingerprint());
    assert_same_state(&oracle, &reopened)?;
    log.record("oracle rebuilt from journal equals oracle rebuilt from source batches")?;
    log.emit(&oracle, "durable_replay_identical");
    Ok(())
}

/// Retained negative evidence (divergence D-FSS016-001).
///
/// `fss_core::ReferenceLedger`, and therefore `DurableReferenceLedger`, does not index batch
/// identities: a new successor that reuses a committed `BatchId` with different content is
/// accepted, so two canonical batches share one stable ID. The oracle refuses it with
/// `ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001`. This test pins the current durable behavior so a
/// fix to the durable ledger must update this record deliberately rather than silently.
#[test]
fn divergence_batch_id_reuse_is_rejected_by_oracle_but_accepted_by_durable_journal() -> TestResult {
    let mut log = ScenarioLog::new(
        "divergence_batch_id_reuse_is_rejected_by_oracle_but_accepted_by_durable_journal",
        0,
    );
    let path = journal_path("divergence_batch_id_reuse")?;
    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    let mut oracle = oracle()?;
    let first = oracle.prepare_batch(batch_id("1")?, vec![create("a", "a")?], [])?;
    oracle.append(first.clone())?;
    durable.append(first.clone())?;
    assert_same_state(&oracle, &durable)?;

    let reuse = oracle.prepare_batch(first.batch_id.clone(), vec![create("b", "b")?], [])?;
    let error = expect_err(oracle.append(reuse.clone()))?;
    assert_eq!(error.code(), "ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001");
    durable.append(reuse.clone())?;
    let sharing = durable
        .batches()
        .iter()
        .filter(|batch| batch.batch_id == reuse.batch_id)
        .count();
    assert_eq!(sharing, 2);
    assert!(assert_same_state(&oracle, &durable).is_err());
    log.record("oracle rejects batch id reuse; durable accepts it (retained divergence)")?;
    log.emit(
        &oracle,
        "divergence_retained_durable_accepts_batch_id_reuse",
    );
    Ok(())
}
