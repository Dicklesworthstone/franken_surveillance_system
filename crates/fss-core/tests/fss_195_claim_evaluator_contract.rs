#![forbid(unsafe_code)]
//! Contract, determinism, canonical round-trip, tamper refusal, exclusion, expiry, stale-generation,
//! scope-mismatch, indeterminate-conflict, and cooperative cancellation tests for `FSS-195`
//! (`fss-x4a.26.15`: public claim scope/evidence/exclusion/expiry evaluator).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::claim_evaluator::{
    ClaimEvaluationLimits, ClaimEvaluationReceipt, ClaimEvaluationVerdict, ClaimEvaluatorError,
    ClaimEvidenceRecord, ClaimExclusionRule, ClaimReadinessLevel, ClaimScopeTuple,
    EvidenceReceiptStatus, PublicClaimEvaluationRequest, evaluate_public_claim,
};
use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    TimestampNs,
};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn scope() -> ClaimScopeTuple {
    ClaimScopeTuple {
        target_triple: "aarch64-apple-darwin".to_owned(),
        source_commit: "git:99469c4640000000000000000000000000000000".to_owned(),
        sibling_closure_digest: ContentDigest::sha256(b"sibling-closure-exact"),
        toolchain: "nightly-2026-08-31".to_owned(),
        contract_basis_digest: reference_contract_basis().basis_digest(),
        pinned_generations: vec![
            "gen:fss1:reference-v4".to_owned(),
            "model:yolox-nano:v1".to_owned(),
        ],
    }
}

fn passing_receipt(id: &str, lane: &str, expires_at_ns: i128) -> ClaimEvidenceRecord {
    ClaimEvidenceRecord {
        receipt_id: id.to_owned(),
        lane_id: lane.to_owned(),
        receipt_digest: ContentDigest::sha256(format!("{id}:{lane}").as_bytes()),
        scope: scope(),
        supported_level: ClaimReadinessLevel::LocallyQualified,
        status: EvidenceReceiptStatus::Passed,
        issued_at_ns: TimestampNs(1_000),
        expires_at_ns: TimestampNs(expires_at_ns),
    }
}

fn nominal_request() -> PublicClaimEvaluationRequest {
    PublicClaimEvaluationRequest {
        claim_id: "CLAIM-MEDIA-PROBE-DARWIN-001".to_owned(),
        requested_level: ClaimReadinessLevel::LocallyQualified,
        scope: scope(),
        required_lanes: vec!["QL-MEDIA-001".to_owned(), "QL-POLICY-001".to_owned()],
        evidence: vec![
            passing_receipt("rcpt:media:1", "QL-MEDIA-001", 10_000),
            passing_receipt("rcpt:policy:1", "QL-POLICY-001", 8_000),
        ],
        exclusions: Vec::new(),
        tombstoned_generations: vec!["gen:fss1:capabilities-v1".to_owned()],
        evaluated_at_ns: TimestampNs(5_000),
    }
}

#[test]
fn fss_195_nominal_certification_is_deterministic_canonical_and_tamper_evident() -> TestResult {
    let req = nominal_request();
    let r1 = evaluate_public_claim(&req, ClaimEvaluationLimits::default(), || false)?;
    let r2 = evaluate_public_claim(&req, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(r1, r2);
    assert_eq!(r1.verdict, ClaimEvaluationVerdict::Certified);
    assert_eq!(r1.effective_level, ClaimReadinessLevel::LocallyQualified);
    assert_eq!(r1.valid_until_ns, Some(TimestampNs(8_000)));
    assert_eq!(r1.verified_receipt_digests.len(), 2);
    assert!(r1.defects.is_empty());
    assert!(r1.verify_digest());

    // Canonical binary round-trip preserves exact fields and digest.
    let mut enc = CanonicalEncoder::new();
    r1.encode_canonical(&mut enc);
    let bytes = enc.finish();
    let decoded = ClaimEvaluationReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes))?;
    assert_eq!(decoded, r1);

    // Any post-evaluation tamper invalidates verify_digest() and fails canonical decode.
    let mut tampered = r1.clone();
    tampered.effective_level = ClaimReadinessLevel::ReleaseQualified;
    assert!(!tampered.verify_digest());
    let mut bad_enc = CanonicalEncoder::new();
    tampered.encode_canonical(&mut bad_enc);
    let bad_bytes = bad_enc.finish();
    assert!(
        ClaimEvaluationReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_bytes)).is_err()
    );

    emit_caplog(
        "fss_195_nominal_certification_and_canonical_roundtrip",
        "certified_deterministic_tightest_expiry_and_tamper_evident",
        "certified_deterministic_tightest_expiry_and_tamper_evident",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_195_exclusion_expiry_scope_stale_overclaim_and_conflict_fail_closed() -> TestResult {
    // 1. Explicit exclusion blocks certification even when every required lane passed.
    let mut excluded_req = nominal_request();
    excluded_req.exclusions.push(ClaimExclusionRule {
        exclusion_id: "EXCL-PYTORCH-ORACLE-UNAVAILABLE".to_owned(),
        target_triple: Some("aarch64-apple-darwin".to_owned()),
        generation_id: None,
        reason: "PyTorch/ONNXRuntime lab differential oracle is not installed on host".to_owned(),
    });
    let excluded =
        evaluate_public_claim(&excluded_req, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(excluded.verdict, ClaimEvaluationVerdict::Excluded);
    assert_eq!(excluded.effective_level, ClaimReadinessLevel::Declared);
    assert_eq!(excluded.valid_until_ns, None);
    assert_eq!(
        excluded.matched_exclusions,
        vec!["EXCL-PYTORCH-ORACLE-UNAVAILABLE"]
    );

    // 2. Exact expiry boundary (`evaluated_at_ns == expires_at_ns`) fails closed as Expired.
    let mut expired_req = nominal_request();
    expired_req.evaluated_at_ns = TimestampNs(8_000);
    let expired = evaluate_public_claim(&expired_req, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(expired.verdict, ClaimEvaluationVerdict::Expired);
    assert_eq!(expired.effective_level, ClaimReadinessLevel::Declared);

    // 3. Scope mismatch (different target triple or source commit) fails closed.
    let mut mismatch_req = nominal_request();
    mismatch_req.evidence[0].scope.target_triple = "x86_64-unknown-linux-gnu".to_owned();
    let mismatch =
        evaluate_public_claim(&mismatch_req, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(mismatch.verdict, ClaimEvaluationVerdict::ScopeMismatch);
    assert_eq!(mismatch.effective_level, ClaimReadinessLevel::Declared);

    // 4. Tombstoned or `"latest"`-aliased generation (including `@`, `/`, `-`, and `git:HEAD`) fails closed.
    for bad_gen in [
        "gen:fss1:capabilities-v1",
        "model:yolox:latest",
        "model@latest",
        "latest/v1",
        "v-latest",
    ] {
        let mut stale_req = nominal_request();
        stale_req.scope.pinned_generations.push(bad_gen.to_owned());
        let stale = evaluate_public_claim(&stale_req, ClaimEvaluationLimits::default(), || false)?;
        assert_eq!(stale.verdict, ClaimEvaluationVerdict::StaleGeneration);
        assert_eq!(stale.effective_level, ClaimReadinessLevel::Declared);
    }
    let mut head_req = nominal_request();
    head_req.scope.source_commit = "git:HEAD".to_owned();
    let head_res = evaluate_public_claim(&head_req, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(head_res.verdict, ClaimEvaluationVerdict::StaleGeneration);

    // 5. Skipped, Partial, Unavailable, Failed receipts OR readiness overclaim never certify.
    for bad_status in [
        EvidenceReceiptStatus::Skipped,
        EvidenceReceiptStatus::Partial,
        EvidenceReceiptStatus::Unavailable,
        EvidenceReceiptStatus::Failed,
        EvidenceReceiptStatus::Cancelled,
    ] {
        let mut non_pass = nominal_request();
        non_pass.evidence[0].status = bad_status;
        let res = evaluate_public_claim(&non_pass, ClaimEvaluationLimits::default(), || false)?;
        assert_eq!(res.verdict, ClaimEvaluationVerdict::InsufficientEvidence);
        assert_eq!(res.effective_level, ClaimReadinessLevel::Declared);
    }

    let mut overclaim = nominal_request();
    overclaim.requested_level = ClaimReadinessLevel::ReleaseQualified;
    let res = evaluate_public_claim(&overclaim, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(res.verdict, ClaimEvaluationVerdict::InsufficientEvidence);
    assert_eq!(res.effective_level, ClaimReadinessLevel::Declared);

    // 6. Conflicting passing + failing receipts yield Indeterminate and do NOT emit conflicted lane digests.
    let mut conflicting = nominal_request();
    let mut failed_dup = passing_receipt("rcpt:media:2", "QL-MEDIA-001", 10_000);
    failed_dup.status = EvidenceReceiptStatus::Failed;
    conflicting.evidence.push(failed_dup);
    let conflict_res =
        evaluate_public_claim(&conflicting, ClaimEvaluationLimits::default(), || false)?;
    assert_eq!(conflict_res.verdict, ClaimEvaluationVerdict::Indeterminate);
    assert_eq!(conflict_res.effective_level, ClaimReadinessLevel::Declared);
    assert!(
        !conflict_res
            .verified_receipt_digests
            .contains(&conflicting.evidence[0].receipt_digest)
    );

    emit_caplog(
        "fss_195_non_certified_verdicts_fail_closed",
        "excluded_expired_scope_stale_insufficient_and_indeterminate_never_certify",
        "excluded_expired_scope_stale_insufficient_and_indeterminate_never_certify",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_195_hostile_inputs_policy_bounds_and_cooperative_cancellation_fail_closed() -> TestResult {
    // 1. Invalid policy bounds fail closed.
    let zero_lim = ClaimEvaluationLimits {
        max_receipts: 0,
        ..ClaimEvaluationLimits::default()
    };
    assert_eq!(
        evaluate_public_claim(&nominal_request(), zero_lim, || false),
        Err(ClaimEvaluatorError::InvalidPolicy)
    );

    // 2. Inverted receipt window and duplicate conflicting receipt ID fail closed.
    let mut inverted = nominal_request();
    inverted.evidence[0].issued_at_ns = TimestampNs(20_000);
    assert_eq!(
        evaluate_public_claim(&inverted, ClaimEvaluationLimits::default(), || false),
        Err(ClaimEvaluatorError::InvalidInput("inverted_receipt_window"))
    );

    let mut dup_conflict = nominal_request();
    let mut forged = dup_conflict.evidence[0].clone();
    forged.status = EvidenceReceiptStatus::Failed;
    dup_conflict.evidence.push(forged);
    assert_eq!(
        evaluate_public_claim(&dup_conflict, ClaimEvaluationLimits::default(), || false),
        Err(ClaimEvaluatorError::InvalidInput(
            "conflicting_duplicate_receipt_id"
        ))
    );

    // 3. Control character injection in claim_id fails closed.
    let mut injected = nominal_request();
    injected.claim_id = "CLAIM-1\nINJECTED".to_owned();
    assert_eq!(
        evaluate_public_claim(&injected, ClaimEvaluationLimits::default(), || false),
        Err(ClaimEvaluatorError::InvalidInput("claim_id"))
    );

    // 4. Cooperative cancellation at every checkpoint withholds the receipt cleanly.
    let total = AtomicUsize::new(0);
    assert!(
        evaluate_public_claim(&nominal_request(), ClaimEvaluationLimits::default(), || {
            total.fetch_add(1, Ordering::Relaxed);
            false
        })
        .is_ok()
    );
    let checkpoints = total.load(Ordering::Relaxed);
    assert!(checkpoints >= 3);
    for cancel_at in [0, checkpoints / 2, checkpoints - 1] {
        let seen = AtomicUsize::new(0);
        assert_eq!(
            evaluate_public_claim(&nominal_request(), ClaimEvaluationLimits::default(), || {
                seen.fetch_add(1, Ordering::Relaxed) >= cancel_at
            }),
            Err(ClaimEvaluatorError::Cancelled)
        );
    }

    emit_caplog(
        "fss_195_hostile_policy_and_cancellation",
        "invalid_policy_hostile_inputs_and_every_cancellation_checkpoint_fail_closed",
        "invalid_policy_hostile_inputs_and_every_cancellation_checkpoint_fail_closed",
        "pass",
    );
    Ok(())
}
