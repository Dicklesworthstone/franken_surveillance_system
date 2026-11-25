#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-105` (`fss-x4a.9.12`): intent-replay / structural /
//! commutative merge certificate ladder composing `FSS-103`, `FSS-104`, and `LedgerOracle`.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CaptureInterval, Completeness, ContentDigest, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EvidenceDelta, LedgerAnchor, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    CombiningRoundOutcome, CommitIntent, CommutativeFamilyRegistry, DeterministicCommitCombiner,
    IntentAuthorityContext, IntentOutcome, LEDGER_MERGE_CERTIFICATE_DOMAIN, LedgerOracle,
    MERGE_CERT_MAGIC, MERGE_CERT_VERSION, MergeCertificate, MergeGuidance, MergeLadder,
    MergeLadderError, MergeOutcome, MergeRefusalReason, MergeRung, NegativeWitness, ObjectRead,
    OracleLimits, PositiveWitness, SemanticWitness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    family: &str,
    object_id: &str,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn std::error::Error>> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: family.to_owned(),
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
    let domain: BTreeSet<String> = ["cam-1".to_owned(), "cam-2".to_owned()]
        .into_iter()
        .collect();
    let observed = if certified {
        domain.clone()
    } else {
        ["cam-1".to_owned()].into_iter().collect()
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
        negative_predicate: "no_conflict".to_owned(),
        stop_reason: if certified {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 1,
        observed_generation: 1,
    }
}

#[test]
fn three_rung_merge_ladder_commits_through_combiner_and_wire_roundtrips() -> TestResult {
    let mut oracle = LedgerOracle::new("site-fss-105", OracleLimits::CEILING)?;
    let mut combiner = DeterministicCommitCombiner::new();
    let comm_reg = CommutativeFamilyRegistry::new(["monotonic_counter".to_owned()])?;
    let auth = IntentAuthorityContext::active(2, 1, [Plane::Authority, Plane::Cognition]);

    // Seed batch 1 with `obj:a`, `obj:counter`, `obj:config`.
    let b1 = oracle.prepare_batch(
        BatchId::parse("batch:seed-105")?,
        vec![
            delta("d1", "source_evidence", "obj:a", None, 1, Plane::Authority)?,
            delta(
                "d2",
                "monotonic_counter",
                "obj:counter",
                None,
                1,
                Plane::Authority,
            )?,
            delta(
                "d3",
                "policy_config",
                "obj:config",
                None,
                1,
                Plane::Authority,
            )?,
        ],
        vec![],
    )?;
    oracle.append(b1)?;
    let anchor1 = oracle.head_anchor().clone();
    let hist1 = oracle.head_history_root();

    let obj_a = ObjectId::parse("obj:a")?;
    let obj_absent = ObjectId::parse("obj:never-written")?;
    let obj_config = ObjectId::parse("obj:config")?;

    // Prepare three stale-basis intents at anchor 1 BEFORE batch 2 commits!
    // (A) Structural non-overlapping intent: reads `obj:a`, asserts `obj:never-written` absent,
    //     writes disjoint `obj:new-1`.
    let structural_intent = CommitIntent {
        intent_id: "intent:structural-rebase".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![
            SemanticWitness::Positive(PositiveWitness::from_oracle(&oracle, 1, &obj_a)?),
            SemanticWitness::Negative(NegativeWitness::from_oracle(
                &oracle,
                1,
                &obj_absent,
                coverage(anchor1.clone(), true),
            )?),
        ],
        writes: vec![delta(
            "d-new-1",
            "source_evidence",
            "obj:new-1",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: auth.clone(),
    };

    // (B) Commutative algebraic intent: reads `obj:a` (unchanged), writes `obj:counter`
    //     in registered commutative family `monotonic_counter` (which batch 2 ALSO increments!).
    let commutative_intent = CommitIntent {
        intent_id: "intent:commutative-counter".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![SemanticWitness::Positive(PositiveWitness::from_oracle(
            &oracle, 1, &obj_a,
        )?)],
        writes: vec![delta(
            "d-cnt-stale",
            "monotonic_counter",
            "obj:counter",
            Some(1),
            2,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: auth.clone(),
    };

    // (C) Non-commutative conflict intent: reads & writes `obj:config` (which batch 2 mutates!).
    let replay_intent = CommitIntent {
        intent_id: "intent:replay-config".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![SemanticWitness::Positive(PositiveWitness::from_oracle(
            &oracle,
            1,
            &obj_config,
        )?)],
        writes: vec![delta(
            "d-cfg-stale",
            "policy_config",
            "obj:config",
            Some(1),
            2,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: auth,
    };

    // Commit batch 2 mutating `obj:counter` (commutative family) and `obj:config` (non-commutative!).
    let b2 = oracle.prepare_batch(
        BatchId::parse("batch:intervening-2")?,
        vec![
            delta(
                "d2-b",
                "monotonic_counter",
                "obj:counter",
                Some(1),
                2,
                Plane::Authority,
            )?,
            delta(
                "d3-b",
                "policy_config",
                "obj:config",
                Some(1),
                2,
                Plane::Authority,
            )?,
        ],
        vec![],
    )?;
    oracle.append(b2)?;

    // 1. Rung 2 (StructuralNonOverlapping) certifies `structural_intent` and commits cleanly via FSS-104 combiner!
    let MergeOutcome::Certified {
        rebased_intent: rebased_struct,
        certificate: cert_struct,
    } = MergeLadder::certify_merge(&oracle, &structural_intent, &comm_reg, None, false)?
    else {
        return Err("expected StructuralNonOverlapping certification".into());
    };
    assert_eq!(cert_struct.rung, MergeRung::StructuralNonOverlapping);
    assert_eq!(cert_struct.intervening_batch_digests.len(), 1);
    assert_eq!(
        LEDGER_MERGE_CERTIFICATE_DOMAIN,
        "fss.ledger_merge_certificate.v1"
    );

    // 2. Rung 1 (CommutativeAlgebraic) certifies `commutative_intent` advancing `obj:counter` gen 2 -> 3!
    let MergeOutcome::Certified {
        rebased_intent: rebased_comm,
        certificate: cert_comm,
    } = MergeLadder::certify_merge(&oracle, &commutative_intent, &comm_reg, None, false)?
    else {
        return Err("expected CommutativeAlgebraic certification".into());
    };
    assert_eq!(cert_comm.rung, MergeRung::CommutativeAlgebraic);
    assert_eq!(rebased_comm.writes[0].prior_generation, Some(2));
    assert_eq!(rebased_comm.writes[0].new_generation, 3);

    // 3. Without a replay compiler, non-commutative `replay_intent` fails closed as IrreconcilableSemanticConflict!
    let refused = MergeLadder::certify_merge(&oracle, &replay_intent, &comm_reg, None, false)?;
    assert!(matches!(
        refused,
        MergeOutcome::Refused {
            reason: MergeRefusalReason::IrreconcilableSemanticConflict,
            guidance: MergeGuidance::EscalateSemanticConflict,
            ..
        }
    ));

    // 4. With a pure deterministic replay compiler (Rung 3), `replay_intent` recomputes cleanly at head!
    let replay_compiler = |ora: &LedgerOracle,
                           orig: &CommitIntent|
     -> Result<Option<CommitIntent>, MergeLadderError> {
        let head = ora.head_anchor().clone();
        let head_hist = ora.head_history_root();
        let head_seq = head.commit_sequence;
        let obj_cfg =
            ObjectId::parse("obj:config").map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        let view = ora
            .view_at(head_seq)
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        let cur_gen = match view.object(&obj_cfg) {
            ObjectRead::Present { revision, .. } => Some(revision.generation),
            ObjectRead::AbsentAtAnchor { .. } => None,
        };
        let fresh_pos = PositiveWitness::from_oracle(ora, head_seq, &obj_cfg)
            .map_err(|e| MergeLadderError::Ledger(e.to_string()))?;
        let mut updated = orig.writes[0].clone();
        updated.prior_generation = cur_gen;
        updated.new_generation = cur_gen.map_or(1, |g| g + 1);
        Ok(Some(CommitIntent {
            intent_id: orig.intent_id.clone(),
            basis_anchor: head,
            basis_history_root: head_hist,
            read_witnesses: vec![SemanticWitness::Positive(fresh_pos)],
            writes: vec![updated],
            child_roots: orig.child_roots.clone(),
            authority: orig.authority.clone(),
        }))
    };
    let MergeOutcome::Certified {
        rebased_intent: rebased_replay,
        certificate: cert_replay,
    } = MergeLadder::certify_merge(
        &oracle,
        &replay_intent,
        &comm_reg,
        Some(&replay_compiler),
        false,
    )?
    else {
        return Err("expected DeterministicIntentReplay certification".into());
    };
    assert_eq!(cert_replay.rung, MergeRung::DeterministicIntentReplay);

    // Feed ALL THREE certified rebased intents directly into FSS-104 DeterministicCommitCombiner!
    let round = combiner.execute_round_oracle(
        &mut oracle,
        vec![*rebased_struct, *rebased_comm, *rebased_replay],
        false,
    )?;
    let CombiningRoundOutcome::Committed { outcomes, .. } = round else {
        return Err("expected all 3 rebased intents to commit in combiner round".into());
    };
    assert!(matches!(
        outcomes.get("intent:structural-rebase"),
        Some(IntentOutcome::Committed(_))
    ));
    assert!(matches!(
        outcomes.get("intent:commutative-counter"),
        Some(IntentOutcome::Committed(_))
    ));
    assert!(matches!(
        outcomes.get("intent:replay-config"),
        Some(IntentOutcome::Committed(_))
    ));

    // Binary wire codec round-trip (`FSSMC001` v1).
    let wire = cert_comm.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &MERGE_CERT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        MERGE_CERT_VERSION
    );
    assert_eq!(MergeCertificate::from_canonical_bytes(&wire)?, *cert_comm);

    emit_caplog(
        "fss105_three_rung_ladder_and_combiner_commit",
        "structural_commutative_and_replay_rungs_certified_and_committed",
        "structural_commutative_and_replay_rungs_certified_and_committed",
        "pass",
    );
    Ok(())
}

#[test]
fn merge_ladder_refuses_revoked_authority_uncertified_coverage_cancel_and_hostile_wire()
-> TestResult {
    let mut oracle = LedgerOracle::new("site-fss-105-faults", OracleLimits::CEILING)?;
    let comm_reg = CommutativeFamilyRegistry::default();
    let b1 = oracle.prepare_batch(
        BatchId::parse("batch:f1")?,
        vec![delta(
            "df1",
            "source_evidence",
            "obj:x",
            None,
            1,
            Plane::Authority,
        )?],
        vec![],
    )?;
    oracle.append(b1)?;
    let anchor1 = oracle.head_anchor().clone();
    let hist1 = oracle.head_history_root();

    // 1. Revoked capability refuses BEFORE merge evaluation.
    let mut revoked_auth = IntentAuthorityContext::active(1, 1, [Plane::Authority]);
    revoked_auth.capability_active = false;
    let rev_intent = CommitIntent {
        intent_id: "intent:revoked".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![],
        writes: vec![delta(
            "dw1",
            "source_evidence",
            "obj:y",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: revoked_auth,
    };
    assert!(matches!(
        MergeLadder::certify_merge(&oracle, &rev_intent, &comm_reg, None, false)?,
        MergeOutcome::Refused {
            reason: MergeRefusalReason::AuthorityOrPrivacyRefused,
            ..
        }
    ));

    // 2. Cooperative cancellation returns Cancelled.
    assert_eq!(
        MergeLadder::certify_merge(&oracle, &rev_intent, &comm_reg, None, true),
        Err(MergeLadderError::Cancelled)
    );

    // 3. Uncertified/gapped negative witness refuses as UncertifiedAbsenceBasis!
    let uncert_neg = SemanticWitness::Negative(NegativeWitness::from_oracle(
        &oracle,
        1,
        &ObjectId::parse("obj:absent")?,
        coverage(anchor1.clone(), false),
    )?);
    let uncert_intent = CommitIntent {
        intent_id: "intent:uncert".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![uncert_neg],
        writes: vec![delta(
            "dw2",
            "source_evidence",
            "obj:z",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    assert!(matches!(
        MergeLadder::certify_merge(&oracle, &uncert_intent, &comm_reg, None, false)?,
        MergeOutcome::Refused {
            reason: MergeRefusalReason::UncertifiedAbsenceBasis,
            guidance: MergeGuidance::WaitForCertifiedCoverage,
            ..
        }
    ));

    // 4. Hostile wire decoding on `FSSMC001`.
    let clean_intent = CommitIntent {
        intent_id: "intent:clean".to_owned(),
        basis_anchor: anchor1,
        basis_history_root: hist1,
        read_witnesses: vec![],
        writes: vec![delta(
            "dw3",
            "source_evidence",
            "obj:clean",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    let MergeOutcome::Certified { certificate, .. } =
        MergeLadder::certify_merge(&oracle, &clean_intent, &comm_reg, None, false)?
    else {
        return Err("expected Certified for clean intent".into());
    };
    let wire = certificate.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        MergeCertificate::from_canonical_bytes(&bad_magic),
        Err(MergeLadderError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&77_u32.to_be_bytes());
    assert_eq!(
        MergeCertificate::from_canonical_bytes(&bad_ver),
        Err(MergeLadderError::UnsupportedVersion { version: 77 })
    );
    assert!(matches!(
        MergeCertificate::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(MergeLadderError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        MergeCertificate::from_canonical_bytes(&bit_flip),
        Err(MergeLadderError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x00);
    assert!(matches!(
        MergeCertificate::from_canonical_bytes(&trailing),
        Err(MergeLadderError::MalformedWire(_))
    ));

    emit_caplog(
        "fss105_faults_authority_uncertified_cancel_and_wire",
        "all_merge_ladder_faults_and_wire_checks_failed_closed",
        "all_merge_ladder_faults_and_wire_checks_failed_closed",
        "pass",
    );
    Ok(())
}
