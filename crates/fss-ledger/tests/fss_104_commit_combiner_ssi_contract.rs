#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-104` (`fss-x4a.9.11`):
//! Deterministic commit combiner and semantic SSI conflict oracle.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, Completeness, ContentDigest, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, LedgerAnchor, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    AppendPhase, CombiningRoundOutcome, CommitCombinerError, CommitIntent, ConflictKind,
    DeterministicCommitCombiner, DurableAppendReconciliation, DurableReferenceLedger,
    IncompleteTailPolicy, IntentAuthorityContext, IntentOutcome, LedgerOracle, NegativeWitness,
    OracleLimits, PositiveWitness, SemanticWitness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..32 {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("fss-104-combiner-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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
    delta_id: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: "source_evidence".to_owned(),
        object_id: ObjectId::parse(object_id)?,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        plane,
        payload_digest: d(&format!("{delta_id}:{object_id}:{new_generation}")),
        witness_digest: None,
        operation_id: None,
    })
}

fn coverage(anchor: LedgerAnchor, certified: bool) -> CoverageWitness {
    let domain: BTreeSet<String> = ["sensor:cam-1".to_owned(), "sensor:cam-2".to_owned()]
        .into_iter()
        .collect();
    let observed = if certified {
        domain.clone()
    } else {
        ["sensor:cam-1".to_owned()].into_iter().collect()
    };
    CoverageWitness {
        anchor,
        authorized_domain: domain,
        observed_domain: observed,
        excluded_domain: BTreeSet::new(),
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
        negative_predicate: "no_conflicting_lease".to_owned(),
        stop_reason: if certified {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 2,
        observed_generation: 2,
    }
}

#[test]
fn canonical_order_invariance_ssi_write_skew_and_negative_phantom_detection() -> TestResult {
    // Seed two identical oracles to prove submission-order invariance.
    let mut oracle_a = LedgerOracle::new("site-fss-104", OracleLimits::CEILING)?;
    let mut oracle_b = LedgerOracle::new("site-fss-104", OracleLimits::CEILING)?;

    let seed_batch = oracle_a.prepare_batch(
        BatchId::parse("batch:seed-104")?,
        vec![
            delta("d-seed-x", "obj:slot-x", None, 1, Plane::Authority)?,
            delta("d-seed-y", "obj:slot-y", None, 1, Plane::Authority)?,
        ],
        vec![],
    )?;
    oracle_a.append(seed_batch.clone())?;
    oracle_b.append(seed_batch)?;

    let anchor1 = oracle_a.head_anchor().clone();
    let hist1 = oracle_a.head_history_root();
    let obj_x = ObjectId::parse("obj:slot-x")?;
    let obj_y = ObjectId::parse("obj:slot-y")?;
    let obj_absent = ObjectId::parse("obj:lease-z")?;

    let pos_x = SemanticWitness::Positive(PositiveWitness::from_oracle(&oracle_a, 1, &obj_x)?);
    let pos_y = SemanticWitness::Positive(PositiveWitness::from_oracle(&oracle_a, 1, &obj_y)?);
    let neg_z_cert = SemanticWitness::Negative(NegativeWitness::from_oracle(
        &oracle_a,
        1,
        &obj_absent,
        coverage(anchor1.clone(), true),
    )?);

    let auth = IntentAuthorityContext::active(1, 1, [Plane::Authority, Plane::Cognition]);

    // Classic SSI write-skew pair:
    //   intent_1 reads X and writes Y (gen 2)
    //   intent_2 reads Y and writes X (gen 2)
    // Disjoint write sets! Exactly ONE must commit in canonical order, and the other MUST abort
    // with PositiveReadStale or SsiDangerousWriteSkew regardless of submission order!
    let intent_1 = CommitIntent {
        intent_id: "intent:skew-1".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![pos_x],
        writes: vec![delta("d-y2", "obj:slot-y", Some(1), 2, Plane::Authority)?],
        child_roots: vec![d("child:1")],
        authority: auth.clone(),
    };
    let intent_2 = CommitIntent {
        intent_id: "intent:skew-2".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![pos_y],
        writes: vec![delta("d-x2", "obj:slot-x", Some(1), 2, Plane::Authority)?],
        child_roots: vec![d("child:2")],
        authority: auth.clone(),
    };
    // Independent third intent writing disjoint object guarded by certified negative witness.
    let intent_3 = CommitIntent {
        intent_id: "intent:disjoint-z".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![neg_z_cert],
        writes: vec![delta("d-z1", "obj:lease-z", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth.clone(),
    };

    let mut comb_a = DeterministicCommitCombiner::new();
    let mut comb_b = DeterministicCommitCombiner::new();

    let out_a = comb_a.execute_round_oracle(
        &mut oracle_a,
        vec![intent_1.clone(), intent_2.clone(), intent_3.clone()],
        false,
    )?;
    let out_b = comb_b.execute_round_oracle(
        &mut oracle_b,
        vec![intent_3.clone(), intent_2.clone(), intent_1.clone()],
        false,
    )?;
    assert_eq!(
        out_a, out_b,
        "submission order must produce bit-identical combining round outcomes"
    );

    let CombiningRoundOutcome::Committed { outcomes, .. } = out_a else {
        return Err("expected Committed round".into());
    };
    assert!(matches!(
        outcomes.get("intent:disjoint-z"),
        Some(IntentOutcome::Committed(_))
    ));
    let committed_skew = ["intent:skew-1", "intent:skew-2"]
        .into_iter()
        .filter(|id| matches!(outcomes.get(*id), Some(IntentOutcome::Committed(_))))
        .count();
    let aborted_skew = ["intent:skew-1", "intent:skew-2"]
        .into_iter()
        .filter(|id| {
            matches!(
                outcomes.get(*id),
                Some(IntentOutcome::Aborted(cw))
                    if matches!(
                        cw.kind,
                        ConflictKind::PositiveReadStale | ConflictKind::SsiDangerousWriteSkew
                    )
            )
        })
        .count();
    assert_eq!(
        committed_skew, 1,
        "exactly one write-skew intent may commit"
    );
    assert_eq!(aborted_skew, 1, "the second write-skew intent must abort");

    // Negative phantom write: a second intent against anchor 1 claiming obj:lease-z is absent MUST
    // abort with NegativePhantomWrite because round 1 inserted obj:lease-z!
    let neg_z_stale = SemanticWitness::Negative(NegativeWitness::from_oracle(
        &oracle_a,
        1,
        &obj_absent,
        coverage(anchor1.clone(), true),
    )?);
    let phantom_intent = CommitIntent {
        intent_id: "intent:phantom-reader".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![neg_z_stale],
        writes: vec![delta("d-p1", "obj:after-z", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth.clone(),
    };

    // Uncertified absence basis (gapped coverage) MUST abort with UncertifiedAbsenceBasis!
    let neg_uncert = SemanticWitness::Negative(NegativeWitness::from_oracle(
        &oracle_a,
        2,
        &ObjectId::parse("obj:never-seen")?,
        coverage(oracle_a.head_anchor().clone(), false),
    )?);
    let uncert_intent = CommitIntent {
        intent_id: "intent:uncert-neg".to_owned(),
        basis_anchor: oracle_a.head_anchor().clone(),
        basis_history_root: oracle_a.head_history_root(),
        read_witnesses: vec![neg_uncert],
        writes: vec![delta("d-u1", "obj:u-target", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth,
    };

    let round2 = comb_a.execute_round_oracle(
        &mut oracle_a,
        vec![phantom_intent, uncert_intent, intent_3.clone()],
        false,
    )?;
    let CombiningRoundOutcome::NoNewCommit { outcomes: out2, .. } = round2 else {
        return Err("expected NoNewCommit when all intents replay or conflict".into());
    };
    assert!(matches!(
        out2.get("intent:phantom-reader"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::NegativePhantomWrite
    ));
    assert!(matches!(
        out2.get("intent:uncert-neg"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::UncertifiedAbsenceBasis
    ));
    assert!(matches!(
        out2.get("intent:disjoint-z"),
        Some(IntentOutcome::IdempotentReplay(_))
    ));

    // Semantic idempotency conflict: reusing intent:disjoint-z with different writes fails closed!
    let mut conflicting_replay = intent_3;
    conflicting_replay.writes = vec![delta("d-z-evil", "obj:evil", None, 1, Plane::Authority)?];
    let round3 = comb_a.execute_round_oracle(&mut oracle_a, vec![conflicting_replay], false)?;
    let CombiningRoundOutcome::NoNewCommit { outcomes: out3, .. } = round3 else {
        return Err("expected NoNewCommit on idempotency conflict".into());
    };
    assert!(matches!(
        out3.get("intent:disjoint-z"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::SemanticIdempotencyConflict
    ));

    // Pass-2 regression: forged self-consistent PositiveWitness claiming a nonexistent object
    // existed at head anchor MUST abort with InvalidReadWitness (not silently commit!).
    let head_anchor = oracle_a.head_anchor().clone();
    let head_hist = oracle_a.head_history_root();
    let forged_pos = SemanticWitness::Positive(PositiveWitness::seal(
        head_anchor.clone(),
        head_hist,
        ObjectId::parse("obj:phantom-nonexistent")?,
        fss_core::ObjectRevision {
            family: "source_evidence".to_owned(),
            generation: 1,
            plane: Plane::Authority,
            payload_digest: d("forged-payload"),
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        },
        1,
        None,
    )?);
    let forged_pos_intent = CommitIntent {
        intent_id: "intent:forged-positive".to_owned(),
        basis_anchor: head_anchor.clone(),
        basis_history_root: head_hist,
        read_witnesses: vec![forged_pos],
        writes: vec![delta("d-fp1", "obj:fp-target", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    // Pass-2 regression: forged NegativeWitness claiming already-present `obj:slot-x` is absent
    // MUST abort with InvalidReadWitness (distinct from post-basis NegativePhantomWrite!).
    let forged_neg = SemanticWitness::Negative(NegativeWitness::seal(
        head_anchor.clone(),
        head_hist,
        obj_x,
        coverage(head_anchor.clone(), true),
        None,
    )?);
    let forged_neg_intent = CommitIntent {
        intent_id: "intent:forged-negative".to_owned(),
        basis_anchor: head_anchor,
        basis_history_root: head_hist,
        read_witnesses: vec![forged_neg],
        writes: vec![delta("d-fn1", "obj:fn-target", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    let round4 = comb_a.execute_round_oracle(
        &mut oracle_a,
        vec![forged_pos_intent, forged_neg_intent],
        false,
    )?;
    let CombiningRoundOutcome::NoNewCommit { outcomes: out4, .. } = round4 else {
        return Err("expected NoNewCommit when both read witnesses are forged".into());
    };
    assert!(matches!(
        out4.get("intent:forged-positive"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::InvalidReadWitness
    ));
    assert!(matches!(
        out4.get("intent:forged-negative"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::InvalidReadWitness
    ));

    emit_caplog(
        "fss104_order_invariance_ssi_phantom_and_idempotency",
        "order_invariant_ssi_skew_phantom_uncertified_and_idempotency_verified",
        "order_invariant_ssi_skew_phantom_uncertified_and_idempotency_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn durable_combiner_authority_cancel_write_conflict_and_indeterminate_reconciliation() -> TestResult
{
    let dir = TempDir::new()?;
    let journal = dir.0.join("combiner.journal");
    let mut durable =
        DurableReferenceLedger::open(&journal, "site-fss-104-dur", IncompleteTailPolicy::Reject)?;
    let mut comb = DeterministicCommitCombiner::new();

    let genesis_anchor = durable.current().anchor.clone();
    let genesis_hist = durable.head_history_root();
    let auth_only = IntentAuthorityContext::active(3, 1, [Plane::Authority]);

    // 1. Cooperative cancellation refuses cleanly without mutating durable state.
    let ok_intent = CommitIntent {
        intent_id: "intent:dur-1".to_owned(),
        basis_anchor: genesis_anchor.clone(),
        basis_history_root: genesis_hist,
        read_witnesses: vec![],
        writes: vec![delta("dd-1", "obj:dur-a", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth_only.clone(),
    };
    assert_eq!(
        comb.execute_round_durable(&mut durable, vec![ok_intent.clone()], true),
        Err(CommitCombinerError::Cancelled)
    );
    assert_eq!(durable.current().anchor.commit_sequence, 0);

    // 2. Unauthorized plane (Cognition write under Authority-only capability) & write-write collision.
    let bad_plane = CommitIntent {
        intent_id: "intent:bad-plane".to_owned(),
        basis_anchor: genesis_anchor.clone(),
        basis_history_root: genesis_hist,
        read_witnesses: vec![],
        writes: vec![delta("dd-bad", "obj:dur-cog", None, 1, Plane::Cognition)?],
        child_roots: vec![],
        authority: auth_only.clone(),
    };
    let colliding_writer = CommitIntent {
        intent_id: "intent:dur-1-rival".to_owned(),
        basis_anchor: genesis_anchor.clone(),
        basis_history_root: genesis_hist,
        read_witnesses: vec![],
        writes: vec![delta("dd-rival", "obj:dur-a", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth_only.clone(),
    };
    let r1 = comb.execute_round_durable(
        &mut durable,
        vec![ok_intent, bad_plane, colliding_writer],
        false,
    )?;
    let CombiningRoundOutcome::Committed { outcomes: o1, .. } = r1 else {
        return Err("expected Committed durable round".into());
    };
    assert!(matches!(
        o1.get("intent:bad-plane"),
        Some(IntentOutcome::Aborted(cw)) if cw.kind == ConflictKind::AuthorityOrPrivacyRefused
    ));
    let winners = ["intent:dur-1", "intent:dur-1-rival"]
        .into_iter()
        .filter(|id| matches!(o1.get(*id), Some(IntentOutcome::Committed(_))))
        .count();
    let ww_aborts = ["intent:dur-1", "intent:dur-1-rival"]
        .into_iter()
        .filter(|id| {
            matches!(
                o1.get(*id),
                Some(IntentOutcome::Aborted(cw))
                    if cw.kind == ConflictKind::WriteWriteGenerationConflict
            )
        })
        .count();
    assert_eq!(winners, 1);
    assert_eq!(ww_aborts, 1);

    // 3. Durable AppendIndeterminate propagates Indeterminate and blocks subsequent rounds until reconciled!
    let next_intent = CommitIntent {
        intent_id: "intent:dur-2".to_owned(),
        basis_anchor: durable.current().anchor.clone(),
        basis_history_root: durable.head_history_root(),
        read_witnesses: vec![],
        writes: vec![delta("dd-2", "obj:dur-b", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth_only.clone(),
    };
    durable.fail_journal_after_phase(AppendPhase::CommitSync);
    let r2 = comb.execute_round_durable(&mut durable, vec![next_intent], false)?;
    assert!(matches!(
        r2,
        CombiningRoundOutcome::Indeterminate {
            pending_sequence: 2,
            ..
        }
    ));

    // Submitting a new round while pending_sequence == 2 MUST fail closed with PendingReconciliation!
    let blocked_intent = CommitIntent {
        intent_id: "intent:dur-3".to_owned(),
        basis_anchor: durable.current().anchor.clone(),
        basis_history_root: durable.head_history_root(),
        read_witnesses: vec![],
        writes: vec![delta("dd-3", "obj:dur-c", None, 1, Plane::Authority)?],
        child_roots: vec![],
        authority: auth_only,
    };
    assert_eq!(
        comb.execute_round_durable(&mut durable, vec![blocked_intent.clone()], false),
        Err(CommitCombinerError::PendingReconciliation { sequence: 2 })
    );

    // Reconcile pending append, then verify subsequent round succeeds cleanly!
    assert!(matches!(
        durable.reconcile_pending(IncompleteTailPolicy::Reject)?,
        DurableAppendReconciliation::Committed { sequence: 2, .. }
    ));
    let mut rebased = blocked_intent;
    rebased.basis_anchor = durable.current().anchor.clone();
    rebased.basis_history_root = durable.head_history_root();
    let r3 = comb.execute_round_durable(&mut durable, vec![rebased], false)?;
    assert!(matches!(r3, CombiningRoundOutcome::Committed { .. }));
    assert_eq!(durable.current().anchor.commit_sequence, 3);

    emit_caplog(
        "fss104_durable_authority_cancel_ww_and_indeterminate",
        "durable_combiner_faults_and_indeterminate_isolation_verified",
        "durable_combiner_faults_and_indeterminate_isolation_verified",
        "pass",
    );
    Ok(())
}
