#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-108` (`fss-x4a.9.15`): counterfactual branch overlay and
//! live-intent recompilation composing `LedgerOracle`, `FSS-103`, `FSS-104`, and `FSS-105`.

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    BranchAuthorityContext, COUNTERFACTUAL_RECEIPT_MAGIC, COUNTERFACTUAL_RECEIPT_VERSION,
    CombiningRoundOutcome, CommitIntent, CommutativeFamilyRegistry, CounterfactualBranchOverlay,
    CounterfactualError, CounterfactualGuidance, CounterfactualRecompileReceipt,
    DeterministicCommitCombiner, IntentAuthorityContext, IntentOutcome,
    LEDGER_COUNTERFACTUAL_RECEIPT_DOMAIN, LedgerOracle, MergeRung, ObjectRead, OracleLimits,
    OverlayReadState, PositiveWitness, RecompileOutcome, RecompileRefusalReason, RecompileStrategy,
    SemanticWitness,
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

#[test]
fn counterfactual_overlay_isolation_diff_and_live_head_recompilation_commit() -> TestResult {
    let mut oracle = LedgerOracle::new("site-fss-108", OracleLimits::CEILING)?;
    let b1 = oracle.prepare_batch(
        BatchId::parse("batch:seed-108")?,
        vec![
            delta(
                "d1",
                "source_evidence",
                "obj:cam-1",
                None,
                1,
                Plane::Authority,
            )?,
            delta(
                "d2",
                "monotonic_counter",
                "obj:hits",
                None,
                1,
                Plane::Authority,
            )?,
        ],
        vec![],
    )?;
    oracle.append(b1)?;
    let canonical_root_before = oracle.head_history_root();
    let anchor1 = oracle.head_anchor().clone();

    let branch_auth = BranchAuthorityContext::active(
        d("contract-basis-108"),
        3,
        2,
        [Plane::Authority, Plane::Cognition],
    );
    let mut branch =
        CounterfactualBranchOverlay::open("branch:what-if-1", &oracle, branch_auth, 16, false)?;

    // Layer two hypothetical deltas inside the branch (updating `obj:cam-1` and creating `obj:hypo-only`).
    branch.apply_hypothetical_delta(
        &oracle,
        delta(
            "hd1",
            "source_evidence",
            "obj:cam-1",
            Some(1),
            2,
            Plane::Authority,
        )?,
        false,
    )?;
    branch.apply_hypothetical_delta(
        &oracle,
        delta(
            "hd2",
            "hypothesis",
            "obj:hypo-only",
            None,
            1,
            Plane::Cognition,
        )?,
        false,
    )?;

    // Canonical oracle MUST remain 100% untouched!
    assert_eq!(oracle.head_history_root(), canonical_root_before);
    assert_eq!(oracle.batch_count(), 1);
    assert!(matches!(
        oracle
            .view_at(1)?
            .object(&ObjectId::parse("obj:hypo-only")?),
        ObjectRead::AbsentAtAnchor { .. }
    ));

    // Overlay reads explicitly distinguish canonical vs hypothetical created/updated/absent!
    assert!(matches!(
        branch.read_object(&oracle, &ObjectId::parse("obj:hits")?)?,
        OverlayReadState::CanonicalUnmodified { .. }
    ));
    assert!(matches!(
        branch.read_object(&oracle, &ObjectId::parse("obj:cam-1")?)?,
        OverlayReadState::HypotheticallyUpdated { .. }
    ));
    assert!(matches!(
        branch.read_object(&oracle, &ObjectId::parse("obj:hypo-only")?)?,
        OverlayReadState::HypotheticallyCreated { .. }
    ));
    assert_eq!(
        branch.read_object(&oracle, &ObjectId::parse("obj:never")?)?,
        OverlayReadState::AbsentInBoth
    );
    assert_eq!(branch.diff_from_canonical(&oracle)?.len(), 2);

    // 1. Direct head match recompilation (canonical head has not moved yet).
    let intent_auth = IntentAuthorityContext::active(3, 2, [Plane::Authority, Plane::Cognition]);
    let direct_intent = CommitIntent {
        intent_id: "intent:cf-direct".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: canonical_root_before,
        read_witnesses: vec![SemanticWitness::Positive(PositiveWitness::from_oracle(
            &oracle,
            1,
            &ObjectId::parse("obj:cam-1")?,
        )?)],
        writes: vec![delta(
            "w-direct",
            "source_evidence",
            "obj:live-action",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: intent_auth.clone(),
    };
    let comm_reg = CommutativeFamilyRegistry::new(["monotonic_counter".to_owned()])?;
    let RecompileOutcome::Compiled {
        live_intent: direct_live,
        merge_certificate: direct_cert,
        receipt: direct_receipt,
    } = branch.recompile_for_live_head(
        &oracle,
        &direct_intent,
        &comm_reg,
        None,
        TimestampNs(1_700_000_108_100),
        false,
    )?
    else {
        return Err("expected DirectHeadMatch compilation".into());
    };
    assert!(direct_cert.is_none());
    assert_eq!(direct_receipt.strategy, RecompileStrategy::DirectHeadMatch);
    assert_eq!(
        LEDGER_COUNTERFACTUAL_RECEIPT_DOMAIN,
        "fss.ledger_counterfactual_receipt.v1"
    );

    // 2. Advance live canonical head on `obj:hits` (commutative!) and recompile a branch intent
    //    prepared at anchor1 through `FSS-105` MergeLadder, then commit via `FSS-104` combiner!
    let b2 = oracle.prepare_batch(
        BatchId::parse("batch:live-advance-2")?,
        vec![delta(
            "d2-live",
            "monotonic_counter",
            "obj:hits",
            Some(1),
            2,
            Plane::Authority,
        )?],
        vec![],
    )?;
    oracle.append(b2)?;

    let stale_comm_intent = CommitIntent {
        intent_id: "intent:cf-rebased".to_owned(),
        basis_anchor: anchor1,
        basis_history_root: canonical_root_before,
        read_witnesses: vec![SemanticWitness::Positive(PositiveWitness::from_oracle(
            &oracle,
            1,
            &ObjectId::parse("obj:cam-1")?,
        )?)],
        writes: vec![delta(
            "w-comm",
            "monotonic_counter",
            "obj:hits",
            Some(1),
            2,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: intent_auth,
    };
    let RecompileOutcome::Compiled {
        live_intent: rebased_live,
        merge_certificate: Some(merge_cert),
        receipt: rebased_receipt,
    } = branch.recompile_for_live_head(
        &oracle,
        &stale_comm_intent,
        &comm_reg,
        None,
        TimestampNs(1_700_000_108_200),
        false,
    )?
    else {
        return Err("expected MergeLadderRebased compilation".into());
    };
    assert_eq!(
        rebased_receipt.strategy,
        RecompileStrategy::MergeLadderRebased(MergeRung::CommutativeAlgebraic)
    );
    assert_eq!(
        rebased_receipt.merge_certificate_digest,
        Some(merge_cert.certificate_digest)
    );

    // Submit recompiled live intent directly into FSS-104 DeterministicCommitCombiner!
    let mut combiner = DeterministicCommitCombiner::new();
    let round = combiner.execute_round_oracle(&mut oracle, vec![*rebased_live], false)?;
    let CombiningRoundOutcome::Committed { outcomes, .. } = round else {
        return Err("expected recompiled intent to commit through combiner".into());
    };
    assert!(matches!(
        outcomes.get("intent:cf-rebased"),
        Some(IntentOutcome::Committed(_))
    ));
    let _ = direct_live;

    // Binary wire codec round-trip (`FSSCFBR1` v1).
    let wire = rebased_receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &COUNTERFACTUAL_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        COUNTERFACTUAL_RECEIPT_VERSION
    );
    assert_eq!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&wire)?,
        *rebased_receipt
    );

    emit_caplog(
        "fss108_overlay_isolation_and_live_recompilation",
        "branch_isolated_recompiled_through_merge_ladder_and_committed",
        "branch_isolated_recompiled_through_merge_ladder_and_committed",
        "pass",
    );
    Ok(())
}

#[test]
fn counterfactual_refuses_effect_authority_laundering_cancel_and_hostile_wire() -> TestResult {
    let mut oracle = LedgerOracle::new("site-fss-108-faults", OracleLimits::CEILING)?;
    let b1 = oracle.prepare_batch(
        BatchId::parse("batch:f1")?,
        vec![delta(
            "df1",
            "source_evidence",
            "obj:cam-a",
            None,
            1,
            Plane::Authority,
        )?],
        vec![],
    )?;
    oracle.append(b1)?;
    let anchor1 = oracle.head_anchor().clone();
    let hist1 = oracle.head_history_root();

    // 1. Forbidden effect authority fails closed on branch open!
    let mut bad_auth = BranchAuthorityContext::active(d("cb"), 1, 1, [Plane::Authority]);
    bad_auth.grants_effect_authority = true;
    assert!(matches!(
        CounterfactualBranchOverlay::open("branch:bad-auth", &oracle, bad_auth, 8, false),
        Err(CounterfactualError::AuthorityRefused(_))
    ));

    // 2. Cooperative cancellation fails closed cleanly.
    let auth = BranchAuthorityContext::active(d("cb"), 1, 1, [Plane::Authority]);
    assert_eq!(
        CounterfactualBranchOverlay::open("branch:cancel", &oracle, auth.clone(), 8, true)
            .unwrap_err(),
        CounterfactualError::Cancelled
    );

    // 3. Laundering a hypothetical overlay generation into a live commit intent fails closed!
    let mut branch = CounterfactualBranchOverlay::open("branch:launder", &oracle, auth, 8, false)?;
    branch.apply_hypothetical_delta(
        &oracle,
        delta(
            "hl1",
            "source_evidence",
            "obj:cam-a",
            Some(1),
            2,
            Plane::Authority,
        )?,
        false,
    )?;
    // Intent attempts to write gen 2 -> 3 assuming hypothetical gen 2 is canonical!
    let laundering_intent = CommitIntent {
        intent_id: "intent:launder".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![],
        writes: vec![delta(
            "wl",
            "source_evidence",
            "obj:cam-a",
            Some(2),
            3,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    let comm_reg = CommutativeFamilyRegistry::default();
    let refused = branch.recompile_for_live_head(
        &oracle,
        &laundering_intent,
        &comm_reg,
        None,
        TimestampNs(1_700_000_108_300),
        false,
    )?;
    assert!(matches!(
        refused,
        RecompileOutcome::Refused {
            reason: RecompileRefusalReason::CounterfactualAssumptionNotCanonical,
            guidance: CounterfactualGuidance::RemoveCounterfactualDependency,
            ..
        }
    ));

    // 3b. Counterfactual read-witness laundering (PositiveWitness carrying unpromoted overlay rev)
    //     and branch semantic-plane escalation MUST fail closed!
    let forged_overlay_read = PositiveWitness::seal(
        anchor1.clone(),
        hist1,
        ObjectId::parse("obj:cam-a")?,
        fss_core::ObjectRevision {
            family: "source_evidence".to_owned(),
            generation: 2,
            plane: Plane::Authority,
            payload_digest: d("hl1:obj:cam-a:2"),
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        },
        1,
        None,
    )?;
    let read_launder_intent = CommitIntent {
        intent_id: "intent:read-launder".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![SemanticWitness::Positive(forged_overlay_read)],
        writes: vec![delta(
            "wrl",
            "source_evidence",
            "obj:downstream",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    assert!(matches!(
        branch.recompile_for_live_head(
            &oracle,
            &read_launder_intent,
            &comm_reg,
            None,
            TimestampNs(1_700_000_108_320),
            false,
        )?,
        RecompileOutcome::Refused {
            reason: RecompileRefusalReason::CounterfactualAssumptionNotCanonical,
            guidance: CounterfactualGuidance::RemoveCounterfactualDependency,
            ..
        }
    ));

    let wider_plane_intent = CommitIntent {
        intent_id: "intent:wider-planes".to_owned(),
        basis_anchor: anchor1.clone(),
        basis_history_root: hist1,
        read_witnesses: vec![],
        writes: vec![delta(
            "wwp",
            "source_evidence",
            "obj:wp-new",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority, Plane::Effect]),
    };
    assert!(matches!(
        branch.recompile_for_live_head(
            &oracle,
            &wider_plane_intent,
            &comm_reg,
            None,
            TimestampNs(1_700_000_108_330),
            false,
        )?,
        RecompileOutcome::Refused {
            reason: RecompileRefusalReason::AuthorityOrPrivacyRefused,
            guidance: CounterfactualGuidance::ReauthorizeBranch,
            ..
        }
    ));

    // 4. Hostile wire decoding on `FSSCFBR1`.
    let clean_intent = CommitIntent {
        intent_id: "intent:clean".to_owned(),
        basis_anchor: anchor1,
        basis_history_root: hist1,
        read_witnesses: vec![],
        writes: vec![delta(
            "wc",
            "source_evidence",
            "obj:clean-new",
            None,
            1,
            Plane::Authority,
        )?],
        child_roots: vec![],
        authority: IntentAuthorityContext::active(1, 1, [Plane::Authority]),
    };
    let RecompileOutcome::Compiled { receipt, .. } = branch.recompile_for_live_head(
        &oracle,
        &clean_intent,
        &comm_reg,
        None,
        TimestampNs(1_700_000_108_400),
        false,
    )?
    else {
        return Err("expected Compiled for clean intent".into());
    };
    let wire = receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&bad_magic),
        Err(CounterfactualError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&bad_ver),
        Err(CounterfactualError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(CounterfactualError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&bit_flip),
        Err(CounterfactualError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAA);
    assert!(matches!(
        CounterfactualRecompileReceipt::from_canonical_bytes(&trailing),
        Err(CounterfactualError::MalformedWire(_))
    ));

    emit_caplog(
        "fss108_faults_laundering_authority_cancel_wire",
        "effect_auth_laundering_cancel_and_hostile_wire_failed_closed",
        "effect_auth_laundering_cancel_and_hostile_wire_failed_closed",
        "pass",
    );
    Ok(())
}
