#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-128` (`fss-x4a.13.12`): RaptorQ / systematic GF(256)
//! post-repair canonical digest gate (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §6, `XFER-INV-006`).

use fss_core::{ContentDigest, TimestampNs};
use fss_object::closure::{
    AtpArchiveGraphCatalog, ClosureAuthorityContext, ClosureBudget, ClosureEdge, ClosureEdgeKind,
    ClosureVerdict, ClosureVerifier, CustodyLevel, InspectedObject,
};
use fss_object::repair_gate::{
    ATP_POST_REPAIR_RECEIPT_DOMAIN, ATP_REPAIR_PLAN_DOMAIN, PostRepairDigestGate,
    PostRepairReceipt, REPAIR_RECEIPT_MAGIC, REPAIR_RECEIPT_VERSION, RepairAuthorityContext,
    RepairGateError, RepairGateState, RepairGuidance, RepairLease, RepairPlan,
    RepairSymbolEnvelope, gf_inv, gf_mul,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(73).wrapping_add(19)) & 0xFF) as u8)
        .collect()
}

fn lease_for(plan: &RepairPlan, fence: u64, auth_gen: u64, expires_ns: i128) -> RepairLease {
    RepairLease {
        lease_id: format!("repair-lease-f{fence}"),
        plan_digest: plan.plan_digest,
        fence,
        authority_generation: auth_gen,
        expires_at: TimestampNs(expires_ns),
        active: true,
    }
}

#[test]
fn gf256_multi_erasure_reconstruction_closure_bridge_and_durability_gated_refresh() -> TestResult {
    // 1. Verify GF(2^8) multiplicative inverse over ALL 255 nonzero field elements!
    assert_eq!(gf_inv(0), 0);
    for a in 1_u8..=255 {
        let inv = gf_inv(a);
        assert_eq!(
            gf_mul(a, inv),
            1,
            "GF(256) inverse failed for element {a} (inv={inv})"
        );
    }

    // 2. Non-aligned payload (1,003 bytes -> 16 source symbols @ 64 bytes + 5 Cauchy repair symbols).
    let payload = sample_payload(1_003);
    let target_digest = ContentDigest::sha256(&payload);
    let root_digest = ContentDigest::sha256(b"archive-root:fss128");
    let basis_digest = ContentDigest::sha256(b"contract-basis:seq42");

    let plan = RepairPlan::seal(
        root_digest,
        target_digest,
        payload.len() as u64,
        2, // source_generation
        basis_digest,
        5,  // expected_authority_generation
        64, // symbol_size
        5,  // repair_symbol_count
    )?;
    assert_eq!(plan.source_symbol_count, 16);
    assert_eq!(plan.repair_symbol_count, 5);
    assert_eq!(ATP_REPAIR_PLAN_DOMAIN, "fss.atp_repair_plan.v1");
    assert_eq!(
        ATP_POST_REPAIR_RECEIPT_DOMAIN,
        "fss.atp_post_repair_receipt.v1"
    );

    let all_symbols = plan.encode_symbols(&payload)?;
    assert_eq!(all_symbols.len(), 21);

    // 3. Lose 5 arbitrary source symbols (ESIs 0, 3, 7, 11, 15 — including the padded tail symbol!)
    //    and replace them with all 5 repair symbols (ESIs 16..=20), shuffled + with duplicates!
    let lost: std::collections::BTreeSet<u32> = [0, 3, 7, 11, 15].into_iter().collect();
    let mut surviving: Vec<RepairSymbolEnvelope> = all_symbols
        .iter()
        .filter(|s| !lost.contains(&s.esi))
        .cloned()
        .collect();
    surviving.reverse();
    // Add 2 duplicate symbols to prove idempotent deduplication.
    surviving.push(all_symbols[16].clone());
    surviving.push(all_symbols[1].clone());

    let auth = RepairAuthorityContext::active(basis_digest, 5, 3);
    let lease = lease_for(&plan, 1, 5, 10_000);

    let result = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        1,
        &surviving,
        TimestampNs(1_000),
        false,
        false,
    )?;

    assert_eq!(
        result.receipt.state,
        RepairGateState::VerifiedCanonicalMatch
    );
    assert_eq!(result.verified_bytes.as_deref(), Some(payload.as_slice()));
    assert_eq!(
        result.receipt.observed_reconstructed_digest,
        Some(target_digest)
    );
    assert_eq!(result.receipt.observed_byte_len, payload.len() as u64);
    assert_eq!(result.receipt.source_symbols_used, 11);
    assert_eq!(result.receipt.repair_symbols_used, 5);
    assert_eq!(result.receipt.duplicate_symbols_ignored, 2);
    assert_eq!(result.receipt.corrupt_symbols_rejected, 0);

    // Permutation invariance: reversed input vs sorted input yields identical receipt digest!
    let mut sorted_surviving = surviving.clone();
    sorted_surviving.sort_by_key(|s| s.esi);
    let result_sorted = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        1,
        &sorted_surviving,
        TimestampNs(1_000),
        false,
        false,
    )?;
    assert_eq!(result.receipt, result_sorted.receipt);

    // 4. Mark Published (still grants zero effect authority) and enforce §6 step 7:
    //    Symbol refresh MUST fail below CustodyLevel::Durable and pass at Durable/Replicated.
    let published =
        result
            .receipt
            .mark_published(&plan, &auth, &lease, 1, TimestampNs(2_000), false)?;
    assert_eq!(published.state, RepairGateState::Published);

    for insufficient in [
        CustodyLevel::Staged,
        CustodyLevel::Verified,
        CustodyLevel::Visible,
    ] {
        let err = published
            .authorize_symbol_refresh(&plan, &auth, insufficient)
            .expect_err("symbol refresh below Durable must fail closed");
        assert_eq!(
            err,
            RepairGateError::SourceDurabilityInsufficient {
                observed: insufficient,
                required: CustodyLevel::Durable,
            }
        );
        assert_eq!(err.guidance(), RepairGuidance::AwaitSourceDurability);
    }
    let refresh_token = published.authorize_symbol_refresh(&plan, &auth, CustodyLevel::Durable)?;
    assert_eq!(refresh_token, published.receipt_digest);

    // 5. Direct composition with FSS-127 (`ClosureVerifier`): feed `published.to_inspected_object`
    //    into `AtpArchiveGraphCatalog` and verify closure passes with `post_repair_verified == true`!
    let mut graph = AtpArchiveGraphCatalog::new();
    graph.insert(
        target_digest,
        published.to_inspected_object(CustodyLevel::Durable, vec![])?,
    );
    graph.insert(
        root_digest,
        InspectedObject::Present {
            custody: CustodyLevel::Durable,
            byte_len: 128,
            post_repair_verified: false,
            edges: vec![ClosureEdge {
                kind: ClosureEdgeKind::ManifestChild,
                target: target_digest,
            }],
        },
    );
    let closure_auth = ClosureAuthorityContext::active_all_edges(basis_digest, 5, 3);
    let witness = ClosureVerifier::verify_closure(
        &graph,
        root_digest,
        &closure_auth,
        CustodyLevel::Durable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(witness.verdict, ClosureVerdict::VerifiedComplete);
    let repaired_member = witness
        .ordered_members
        .iter()
        .find(|m| m.digest == target_digest)
        .expect("repaired child present in closure");
    assert!(repaired_member.post_repair_verified);

    // 6. Binary wire round-trip (`FSSPRG01` v1).
    let wire = published.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &REPAIR_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        REPAIR_RECEIPT_VERSION
    );
    assert_eq!(PostRepairReceipt::from_canonical_bytes(&wire)?, published);

    emit_caplog(
        "fss128_gf256_repair_closure_bridge_and_durability_refresh",
        "5_erasure_recovery_closure_bridge_and_durable_refresh_verified",
        "5_erasure_recovery_closure_bridge_and_durable_refresh_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn corruption_quarantine_stale_generation_authority_escalation_lease_and_hostile_wire() -> TestResult
{
    let payload = sample_payload(515);
    let target_digest = ContentDigest::sha256(&payload);
    let root_digest = ContentDigest::sha256(b"archive-root:fss128-faults");
    let basis_digest = ContentDigest::sha256(b"contract-basis:seq99");

    let plan = RepairPlan::seal(
        root_digest,
        target_digest,
        payload.len() as u64,
        4,
        basis_digest,
        9,
        64,
        3,
    )?;
    let symbols = plan.encode_symbols(&payload)?;
    let auth = RepairAuthorityContext::active(basis_digest, 9, 2);
    let lease = lease_for(&plan, 2, 9, 50_000);

    // 1. Forged 1-bit flip inside a repair symbol WITH recomputed valid `symbol_digest`:
    //    Decodes to wrong bytes -> Post-repair canonical SHA-256 gate MUST Quarantine & return
    //    `verified_bytes = None`, and `mark_published` MUST refuse!
    let mut forged_set: Vec<RepairSymbolEnvelope> = symbols[1..10].to_vec(); // missing ESI 0, includes ESI 9
    let mut forged_parity = forged_set.pop().expect("parity symbol");
    forged_parity.payload[17] ^= 0x01; // 1-bit flip
    forged_parity.symbol_digest = forged_parity.compute_digest()?; // attacker resealed symbol envelope
    forged_set.push(forged_parity);

    let quarantined = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &forged_set,
        TimestampNs(5_000),
        false,
        false,
    )?;
    assert_eq!(quarantined.receipt.state, RepairGateState::Quarantined);
    assert!(quarantined.verified_bytes.is_none());
    assert_ne!(
        quarantined.receipt.observed_reconstructed_digest,
        Some(target_digest)
    );
    assert_eq!(
        quarantined
            .receipt
            .mark_published(&plan, &auth, &lease, 2, TimestampNs(6_000), false,),
        Err(RepairGateError::UnverifiedPublicationRefused {
            state: RepairGateState::Quarantined,
        })
    );
    assert!(matches!(
        quarantined
            .receipt
            .to_inspected_object(CustodyLevel::Durable, vec![])?,
        InspectedObject::Corrupt { .. }
    ));

    // 2. Forged 1-bit flip strictly in the trailing padding bytes of the last source symbol:
    //    Even though truncated payload bytes still hash to `target_object_digest`, non-zero
    //    padding MUST Quarantine rather than silently accepting corrupted symbol framing!
    let mut bad_pad_set: Vec<RepairSymbolEnvelope> = symbols[..9].to_vec();
    let last_src = bad_pad_set.last_mut().expect("last source symbol");
    last_src.payload[63] ^= 0x80; // byte 575 is padding (payload ends at 515)
    last_src.symbol_digest = last_src.compute_digest()?;
    let pad_quarantined = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &bad_pad_set,
        TimestampNs(5_500),
        false,
        false,
    )?;
    assert_eq!(pad_quarantined.receipt.state, RepairGateState::Quarantined);
    assert!(pad_quarantined.verified_bytes.is_none());

    // 3. Transport-corrupted symbol (payload flipped WITHOUT resealing symbol_digest) +
    //    insufficient clean symbols remaining -> Quarantined with corrupt_symbols_rejected == 1.
    let mut broken_set: Vec<RepairSymbolEnvelope> = symbols[..9].to_vec();
    broken_set[2].payload[0] ^= 0xFF;
    let insuf = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &broken_set,
        TimestampNs(5_600),
        false,
        false,
    )?;
    assert_eq!(insuf.receipt.state, RepairGateState::Quarantined);
    assert_eq!(insuf.receipt.corrupt_symbols_rejected, 1);
    assert!(insuf.verified_bytes.is_none());

    // 3b. Pass-2 regression: equivocating ESI (distinct valid-digest payloads claiming same ESI 0)
    //     MUST reject all copies of ESI 0 with 100% permutation-invariant counters, while still
    //     recovering cleanly if enough remaining honest symbols exist!
    let mut equiv_alt = symbols[0].clone();
    equiv_alt.payload[0] ^= 0x55;
    equiv_alt.symbol_digest = equiv_alt.compute_digest()?;
    let mut equiv_fwd = vec![symbols[0].clone(), equiv_alt.clone(), symbols[0].clone()];
    equiv_fwd.extend_from_slice(&symbols[1..10]); // ESIs 1..=9 (9 honest symbols == k!)
    let mut equiv_rev = vec![equiv_alt, symbols[0].clone(), symbols[0].clone()];
    equiv_rev.extend_from_slice(&symbols[1..10]);
    let eq_res_fwd = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &equiv_fwd,
        TimestampNs(5_650),
        false,
        false,
    )?;
    let eq_res_rev = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &equiv_rev,
        TimestampNs(5_650),
        false,
        false,
    )?;
    assert_eq!(eq_res_fwd.receipt, eq_res_rev.receipt);
    assert_eq!(
        eq_res_fwd.receipt.state,
        RepairGateState::VerifiedCanonicalMatch
    );
    assert_eq!(eq_res_fwd.receipt.corrupt_symbols_rejected, 3);
    assert_eq!(eq_res_fwd.receipt.duplicate_symbols_ignored, 0);
    assert_eq!(
        eq_res_fwd.verified_bytes.as_deref(),
        Some(payload.as_slice())
    );

    // 4. Stale source generation symbol fails closed immediately with StaleOrMismatchedSymbol!
    let mut stale_set = symbols[..9].to_vec();
    stale_set[0].source_generation = 3; // stale (plan expects 4)
    let stale_err = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &stale_set,
        TimestampNs(5_700),
        false,
        false,
    )
    .expect_err("stale source_generation symbol must fail closed");
    assert!(matches!(
        stale_err,
        RepairGateError::StaleOrMismatchedSymbol { esi: 0, .. }
    ));

    // 5. XFER-INV-006: Attempting to smuggle `grants_effect_authority = true` fails closed!
    let mut escalated_auth = auth.clone();
    escalated_auth.grants_effect_authority = true;
    let esc_err = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &escalated_auth,
        &lease,
        2,
        &symbols,
        TimestampNs(5_800),
        false,
        false,
    )
    .expect_err("effect authority escalation in repair must fail closed");
    assert_eq!(esc_err, RepairGateError::AuthorityEscalationRefused);
    assert_eq!(
        esc_err.guidance(),
        RepairGuidance::StripEffectAuthorityFromRepair
    );

    // 6. Expired lease, stale fence, revoked capability, cancellation, and Indeterminate I/O.
    assert!(matches!(
        PostRepairDigestGate::reconstruct_and_verify(
            &plan,
            &auth,
            &lease,
            2,
            &symbols,
            TimestampNs(50_000), // now >= expires_at
            false,
            false,
        ),
        Err(RepairGateError::InvalidOrExpiredLease(_))
    ));
    assert!(matches!(
        PostRepairDigestGate::reconstruct_and_verify(
            &plan,
            &auth,
            &lease,
            3, // min_fence > lease.fence (2)
            &symbols,
            TimestampNs(5_900),
            false,
            false,
        ),
        Err(RepairGateError::InvalidOrExpiredLease(_))
    ));
    let mut revoked_auth = auth.clone();
    revoked_auth.repair_capability_active = false;
    assert!(matches!(
        PostRepairDigestGate::reconstruct_and_verify(
            &plan,
            &revoked_auth,
            &lease,
            2,
            &symbols,
            TimestampNs(5_900),
            false,
            false,
        ),
        Err(RepairGateError::AuthorityRevoked(_))
    ));
    assert_eq!(
        PostRepairDigestGate::reconstruct_and_verify(
            &plan,
            &auth,
            &lease,
            2,
            &symbols,
            TimestampNs(5_900),
            false,
            true,
        ),
        Err(RepairGateError::Cancelled)
    );
    let indet = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &auth,
        &lease,
        2,
        &symbols,
        TimestampNs(6_000),
        true,
        false,
    )?;
    assert_eq!(indet.receipt.state, RepairGateState::Indeterminate);
    assert!(indet.verified_bytes.is_none());
    assert!(matches!(
        indet
            .receipt
            .to_inspected_object(CustodyLevel::Durable, vec![])?,
        InspectedObject::Indeterminate { .. }
    ));

    // 7. Hostile wire decoding on `FSSPRG01` receipt bytes.
    let wire = quarantined.receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        PostRepairReceipt::from_canonical_bytes(&bad_magic),
        Err(RepairGateError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&7_u32.to_be_bytes());
    assert_eq!(
        PostRepairReceipt::from_canonical_bytes(&bad_ver),
        Err(RepairGateError::UnsupportedVersion { version: 7 })
    );
    assert!(matches!(
        PostRepairReceipt::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(RepairGateError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        PostRepairReceipt::from_canonical_bytes(&bit_flip),
        Err(RepairGateError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAA);
    assert!(matches!(
        PostRepairReceipt::from_canonical_bytes(&trailing),
        Err(RepairGateError::MalformedWire(_))
    ));

    emit_caplog(
        "fss128_quarantine_stale_gen_authority_escalation_lease_and_wire",
        "all_post_repair_faults_and_xfer_inv_006_failed_closed",
        "all_post_repair_faults_and_xfer_inv_006_failed_closed",
        "pass",
    );
    Ok(())
}
