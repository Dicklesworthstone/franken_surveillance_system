#![forbid(unsafe_code)]
//! Integration and contract tests for prepared-effect and receipt schemas (FSS-008).
//!
//! Verifies:
//! - Canonical versioned schemas and Rust types for EffectIntent, PreparedEffect,
//!   ProviderObservationReceipt, ProviderFailureReceipt, and EffectReconciliationRecord.
//! - Binary and canonical JSON round-trips are bit-identical.
//! - Invariant: receipts are provider-issued and verified by lookup, never a recomputable digest.
//! - Invariant: outcomes are Delivered, Failed, Indeterminate, or Verified with evidence.
//! - Invariant: idempotency keys cannot be shared across different intents.
//! - Typed decode errors, no aliases, no default-on-error.
//! - Bounds tested at bound and bound+1.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::effect::{
    EffectAuthority, EffectIntent, EffectJournal, EffectReconciliationRecord, EffectSchemaError,
    MAX_DETAIL_LEN, MAX_EFFECT_CLASS_LEN, MAX_ERROR_CODE_LEN, MAX_TERMINAL_PREDICATE_LEN,
    OperationReceipt, PreparedEffect, ProviderFailureReceipt, ProviderObservationReceipt,
    ReceiptLookupStatus, ReconciliationOutcome,
};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, EffectState, IdempotencyKey,
    ObligationId, OperationId, TimestampNs,
};

fn sample_intent() -> Result<EffectIntent, Box<dyn Error>> {
    let op_id = OperationId::parse("op:alert:dispatch:01")?;
    let idem_key = IdempotencyKey::parse("idem:alert:2026-09-12:001")?;
    let req_digest = ContentDigest::sha256(b"alert-request-body");
    let pre_digest = ContentDigest::sha256(b"precondition:event-corroborated");
    Ok(EffectIntent::new(
        op_id,
        idem_key,
        "alert.dispatch",
        req_digest,
        pre_digest,
    )?)
}

fn sample_prepared() -> Result<PreparedEffect, Box<dyn Error>> {
    let intent = sample_intent()?;
    let ob_id = ObligationId::parse("ob:alert:01")?;
    Ok(PreparedEffect::new(
        intent,
        ob_id,
        "provider delivery is independently reconciled",
        TimestampNs(1_700_000_000_000_000_000),
    )?)
}

fn sample_observation_receipt() -> Result<ProviderObservationReceipt, Box<dyn Error>> {
    let nonce = ContentDigest::sha256(b"provider-secret-nonce-12345");
    let msg_digest = ContentDigest::sha256(b"alert-message-payload");
    let prep_digest = ContentDigest::sha256(b"prepared-effect-sample-digest");
    let idem_key = IdempotencyKey::parse("idem:alert:2026-09-12:001")?;
    Ok(ProviderObservationReceipt::new(
        nonce,
        msg_digest,
        prep_digest,
        idem_key,
    ))
}

fn sample_failure_receipt() -> Result<ProviderFailureReceipt, Box<dyn Error>> {
    let nonce = ContentDigest::sha256(b"provider-secret-nonce-99999");
    let msg_digest = ContentDigest::sha256(b"alert-message-payload");
    let prep_digest = ContentDigest::sha256(b"prepared-effect-sample-digest");
    let idem_key = IdempotencyKey::parse("idem:alert:2026-09-12:001")?;
    Ok(ProviderFailureReceipt::new(
        nonce,
        msg_digest,
        prep_digest,
        idem_key,
        "rate_limited",
    )?)
}

fn sample_reconciliation_verified() -> Result<EffectReconciliationRecord, Box<dyn Error>> {
    let op_id = OperationId::parse("op:alert:dispatch:01")?;
    let idem_key = IdempotencyKey::parse("idem:alert:2026-09-12:001")?;
    let prep_digest = ContentDigest::sha256(b"prepared-effect-sample-digest");
    let evidence = ContentDigest::sha256(b"external-delivery-log");
    Ok(EffectReconciliationRecord::new(
        op_id,
        idem_key,
        prep_digest,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(1_700_000_001_000_000_000),
        Some("verified against provider delivery log".to_string()),
    )?)
}

fn sample_operation_receipt() -> Result<OperationReceipt, Box<dyn Error>> {
    let intent = sample_intent()?;
    let authority =
        EffectAuthority::new("principal:operator:sec-ops", "cap:alert:dispatch", Some(42))?;
    // Only the effect journal builds a receipt (its encoding version is private, fss-deir9); a
    // fresh preparation yields exactly the prepared receipt this helper used to spell out.
    let mut journal = EffectJournal::new();
    Ok(journal
        .prepare_with_authority(
            intent,
            ObligationId::parse("obligation:sample-receipt")?,
            "delivery_proved",
            authority,
            TimestampNs(1_700_000_000_000_000_000),
        )?
        .clone())
}

// ---------------------------------------------------------------------------
// 1. Bit-identical Canonical Binary Round Trips
// ---------------------------------------------------------------------------

#[test]
fn test_effect_intent_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_intent()?;
    let bytes1 = original.to_canonical_bytes()?;
    let decoded = EffectIntent::from_canonical_bytes(&bytes1)?;
    assert_eq!(original, decoded);
    let bytes2 = decoded.to_canonical_bytes()?;
    assert_eq!(bytes1, bytes2, "binary encoding must be bit-identical");
    Ok(())
}

#[test]
fn test_prepared_effect_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_prepared()?;
    let bytes1 = original.to_canonical_bytes()?;
    let decoded = PreparedEffect::from_canonical_bytes(&bytes1)?;
    assert_eq!(original, decoded);
    let bytes2 = decoded.to_canonical_bytes()?;
    assert_eq!(bytes1, bytes2, "binary encoding must be bit-identical");
    Ok(())
}

#[test]
fn test_provider_observation_receipt_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_observation_receipt()?;
    let bytes1 = original.to_canonical_bytes()?;
    let decoded = ProviderObservationReceipt::from_canonical_bytes(&bytes1)?;
    assert_eq!(original, decoded);
    let bytes2 = decoded.to_canonical_bytes()?;
    assert_eq!(bytes1, bytes2, "binary encoding must be bit-identical");
    Ok(())
}

#[test]
fn test_provider_failure_receipt_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_failure_receipt()?;
    let bytes1 = original.to_canonical_bytes()?;
    let decoded = ProviderFailureReceipt::from_canonical_bytes(&bytes1)?;
    assert_eq!(original, decoded);
    let bytes2 = decoded.to_canonical_bytes()?;
    assert_eq!(bytes1, bytes2, "binary encoding must be bit-identical");
    Ok(())
}

#[test]
fn test_reconciliation_record_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_reconciliation_verified()?;
    let bytes1 = original.to_canonical_bytes()?;
    let decoded = EffectReconciliationRecord::from_canonical_bytes(&bytes1)?;
    assert_eq!(original, decoded);
    let bytes2 = decoded.to_canonical_bytes()?;
    assert_eq!(bytes1, bytes2, "binary encoding must be bit-identical");
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Bit-identical Canonical JSON Round Trips
// ---------------------------------------------------------------------------

#[test]
fn test_effect_intent_json_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_intent()?;
    let json1 = original.to_canonical_json();
    let decoded = EffectIntent::from_json(&json1)?;
    assert_eq!(original, decoded);
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2, "canonical JSON must be bit-identical");
    Ok(())
}

#[test]
fn test_prepared_effect_json_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_prepared()?;
    let json1 = original.to_canonical_json();
    let decoded = PreparedEffect::from_json(&json1)?;
    assert_eq!(original, decoded);
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2, "canonical JSON must be bit-identical");
    Ok(())
}

#[test]
fn test_provider_observation_receipt_json_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_observation_receipt()?;
    let json1 = original.to_canonical_json();
    let decoded = ProviderObservationReceipt::from_json(&json1)?;
    assert_eq!(original, decoded);
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2, "canonical JSON must be bit-identical");
    Ok(())
}

#[test]
fn test_provider_failure_receipt_json_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_failure_receipt()?;
    let json1 = original.to_canonical_json();
    let decoded = ProviderFailureReceipt::from_json(&json1)?;
    assert_eq!(original, decoded);
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2, "canonical JSON must be bit-identical");
    Ok(())
}

#[test]
fn test_reconciliation_record_json_round_trip() -> Result<(), Box<dyn Error>> {
    let original = sample_reconciliation_verified()?;
    let json1 = original.to_canonical_json();
    let decoded = EffectReconciliationRecord::from_json(&json1)?;
    assert_eq!(original, decoded);
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2, "canonical JSON must be bit-identical");
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Invariant: Receipts are provider-issued and verified by lookup
// ---------------------------------------------------------------------------

#[test]
fn test_receipts_verified_by_lookup_never_recomputable() -> Result<(), Box<dyn Error>> {
    let obs = sample_observation_receipt()?;
    let fail = sample_failure_receipt()?;

    // Build mock provider lookup tables representing issued nonces
    let mut issued_obs: BTreeSet<(ContentDigest, ContentDigest)> = BTreeSet::new();
    let mut issued_fail: BTreeSet<(ContentDigest, ContentDigest, String)> = BTreeSet::new();

    // Before registration, lookup verification MUST fail
    assert!(
        obs.verify_lookup(&issued_obs).is_err(),
        "unissued observation receipt must fail lookup verification"
    );
    assert!(
        fail.verify_lookup(&issued_fail).is_err(),
        "unissued failure receipt must fail lookup verification"
    );

    // Register authentic receipts in provider tables
    issued_obs.insert((obs.provider_nonce, obs.message_digest));
    issued_fail.insert((
        fail.provider_nonce,
        fail.message_digest,
        fail.error_code.clone(),
    ));

    // Now lookup verification succeeds
    assert!(obs.verify_lookup(&issued_obs).is_ok());
    assert!(fail.verify_lookup(&issued_fail).is_ok());

    // Fabricated receipt with same message digest but fabricated nonce fails
    let fake_nonce = ContentDigest::sha256(b"fabricated-attacker-nonce");
    let forged_obs = ProviderObservationReceipt::new(
        fake_nonce,
        obs.message_digest,
        obs.prepared_effect_digest,
        obs.idempotency_key.clone(),
    );
    assert!(
        forged_obs.verify_lookup(&issued_obs).is_err(),
        "forged nonce must fail lookup verification"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Invariant: Outcomes are Delivered, Failed, Indeterminate, or Verified with evidence
// ---------------------------------------------------------------------------

#[test]
fn test_reconciliation_outcome_invariants() -> Result<(), Box<dyn Error>> {
    let op_id = OperationId::parse("op:test:01")?;
    let idem_key = IdempotencyKey::parse("idem:test:01")?;
    let prep_digest = ContentDigest::sha256(b"prep");
    let evidence = ContentDigest::sha256(b"proof-evidence");

    // Verified REQUIRES evidence
    let verified_no_evidence = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Verified,
        None,
        TimestampNs(100),
        None,
    );
    assert!(
        matches!(
            verified_no_evidence,
            Err(EffectSchemaError::InvalidOutcome {
                outcome: "verified",
                ..
            })
        ),
        "Verified outcome without evidence must fail with InvalidOutcome"
    );

    // Verified with evidence succeeds
    let verified_ok = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(100),
        None,
    );
    assert!(verified_ok.is_ok());

    // Failed REQUIRES detail/reason
    let failed_no_detail = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Failed,
        None,
        TimestampNs(100),
        None,
    );
    assert!(
        matches!(
            failed_no_detail,
            Err(EffectSchemaError::InvalidOutcome {
                outcome: "failed",
                ..
            })
        ),
        "Failed outcome without detail must fail"
    );

    // Failed with detail succeeds
    let failed_ok = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Failed,
        None,
        TimestampNs(100),
        Some("provider connection refused".to_string()),
    );
    assert!(failed_ok.is_ok());

    // Indeterminate cannot carry verified evidence
    let indeterminate_with_evidence = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Indeterminate,
        Some(evidence),
        TimestampNs(100),
        Some("timeout awaiting ack".to_string()),
    );
    assert!(
        matches!(
            indeterminate_with_evidence,
            Err(EffectSchemaError::InvalidOutcome {
                outcome: "indeterminate",
                ..
            })
        ),
        "Indeterminate outcome carrying evidence must fail"
    );

    // Delivered REQUIRES evidence witness (Finding 1: transport acceptance is not terminal success)
    let delivered_no_evidence = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Delivered,
        None,
        TimestampNs(100),
        None,
    );
    assert!(
        matches!(
            delivered_no_evidence,
            Err(EffectSchemaError::InvalidOutcome {
                outcome: "delivered",
                ..
            })
        ),
        "Delivered without evidence witness must fail"
    );

    // Delivered with evidence succeeds
    let delivered_ok = EffectReconciliationRecord::new(
        op_id,
        idem_key,
        prep_digest,
        ReconciliationOutcome::Delivered,
        Some(evidence),
        TimestampNs(100),
        None,
    );
    assert!(delivered_ok.is_ok());

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Invariant: Idempotency keys cannot be shared across different intents
// ---------------------------------------------------------------------------

#[test]
fn test_idempotency_keys_cannot_be_shared_across_different_intents() -> Result<(), Box<dyn Error>> {
    let mut journal = EffectJournal::new();
    let intent1 = sample_intent()?;
    let ob_id1 = ObligationId::parse("ob:test:01")?;

    // Prepare first intent
    journal.prepare(intent1.clone(), ob_id1, "predicate", TimestampNs(1))?;

    // Exact same intent with same idempotency key is accepted idempotently
    let retry_ob = ObligationId::parse("ob:test:retry")?;
    let retry_res = journal.prepare(intent1.clone(), retry_ob, "predicate", TimestampNs(2));
    assert!(retry_res.is_ok(), "exact idempotent retry must succeed");

    // Different intent with SAME idempotency key MUST FAIL
    let diff_op = OperationId::parse("op:different:02")?;
    let conflicting_intent = EffectIntent::new(
        diff_op,
        intent1.idempotency_key.clone(), // Same idempotency key!
        "different.class",
        ContentDigest::sha256(b"different-request"),
        intent1.precondition_digest,
    )?;

    let ob_id2 = ObligationId::parse("ob:test:02")?;
    let conflict_res = journal.prepare(conflicting_intent, ob_id2, "predicate", TimestampNs(3));
    assert_eq!(
        conflict_res.err(),
        Some(ContractError::IdempotencyConflict),
        "different intent under same idempotency key must fail with IdempotencyConflict"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Hard bounds tested at bound and bound+1
// ---------------------------------------------------------------------------

#[test]
fn test_effect_class_length_bounds() -> Result<(), Box<dyn Error>> {
    let op_id = OperationId::parse("op:test:bounds")?;
    let idem_key = IdempotencyKey::parse("idem:test:bounds")?;
    let req = ContentDigest::sha256(b"r");
    let pre = ContentDigest::sha256(b"p");

    // Empty fails
    let err_empty = EffectIntent::new(op_id.clone(), idem_key.clone(), "", req, pre);
    assert!(matches!(
        err_empty,
        Err(EffectSchemaError::MissingField {
            field: "effectClass"
        })
    ));

    // Exactly at bound (MAX_EFFECT_CLASS_LEN)
    let at_bound = "a".repeat(MAX_EFFECT_CLASS_LEN);
    let ok = EffectIntent::new(op_id.clone(), idem_key.clone(), at_bound, req, pre);
    assert!(ok.is_ok(), "effect_class at bound must succeed");

    // Bound + 1 strictly fails
    let over_bound = "a".repeat(MAX_EFFECT_CLASS_LEN + 1);
    let err_over = EffectIntent::new(op_id, idem_key, over_bound, req, pre);
    assert!(
        matches!(
            err_over,
            Err(EffectSchemaError::OverLimitLength {
                field: "effectClass",
                limit: MAX_EFFECT_CLASS_LEN,
                actual
            }) if actual == MAX_EFFECT_CLASS_LEN + 1
        ),
        "effect_class at bound + 1 must fail with OverLimitLength"
    );

    Ok(())
}

#[test]
fn test_terminal_predicate_length_bounds() -> Result<(), Box<dyn Error>> {
    let intent = sample_intent()?;
    let ob_id = ObligationId::parse("ob:test:bounds")?;

    // Empty fails
    let err_empty = PreparedEffect::new(intent.clone(), ob_id.clone(), "", TimestampNs(1));
    assert!(matches!(
        err_empty,
        Err(EffectSchemaError::MissingField {
            field: "terminalPredicate"
        })
    ));

    // Exactly at bound (MAX_TERMINAL_PREDICATE_LEN)
    let at_bound = "p".repeat(MAX_TERMINAL_PREDICATE_LEN);
    let ok = PreparedEffect::new(intent.clone(), ob_id.clone(), at_bound, TimestampNs(1));
    assert!(ok.is_ok(), "terminal_predicate at bound must succeed");

    // Bound + 1 strictly fails
    let over_bound = "p".repeat(MAX_TERMINAL_PREDICATE_LEN + 1);
    let err_over = PreparedEffect::new(intent, ob_id, over_bound, TimestampNs(1));
    assert!(
        matches!(
            err_over,
            Err(EffectSchemaError::OverLimitLength {
                field: "terminalPredicate",
                limit: MAX_TERMINAL_PREDICATE_LEN,
                actual
            }) if actual == MAX_TERMINAL_PREDICATE_LEN + 1
        ),
        "terminal_predicate at bound + 1 must fail with OverLimitLength"
    );

    Ok(())
}

#[test]
fn test_failure_error_code_length_bounds() -> Result<(), Box<dyn Error>> {
    let nonce = ContentDigest::sha256(b"n");
    let msg = ContentDigest::sha256(b"m");
    let prep = ContentDigest::sha256(b"p");
    let idem = IdempotencyKey::parse("idem:test:bounds")?;

    // Empty fails
    let err_empty = ProviderFailureReceipt::new(nonce, msg, prep, idem.clone(), "");
    assert!(matches!(
        err_empty,
        Err(EffectSchemaError::MissingField { field: "errorCode" })
    ));

    // Exactly at bound (MAX_ERROR_CODE_LEN)
    let at_bound = "e".repeat(MAX_ERROR_CODE_LEN);
    let ok = ProviderFailureReceipt::new(nonce, msg, prep, idem.clone(), at_bound);
    assert!(ok.is_ok(), "errorCode at bound must succeed");

    // Bound + 1 strictly fails
    let over_bound = "e".repeat(MAX_ERROR_CODE_LEN + 1);
    let err_over = ProviderFailureReceipt::new(nonce, msg, prep, idem, over_bound);
    assert!(
        matches!(
            err_over,
            Err(EffectSchemaError::OverLimitLength {
                field: "errorCode",
                limit: MAX_ERROR_CODE_LEN,
                actual
            }) if actual == MAX_ERROR_CODE_LEN + 1
        ),
        "errorCode at bound + 1 must fail with OverLimitLength"
    );

    Ok(())
}

#[test]
fn test_reconciliation_detail_length_bounds() -> Result<(), Box<dyn Error>> {
    let op_id = OperationId::parse("op:test:reconcile")?;
    let idem_key = IdempotencyKey::parse("idem:test:bounds")?;
    let prep = ContentDigest::sha256(b"p");
    let evidence = ContentDigest::sha256(b"e");

    // Exactly at bound (MAX_DETAIL_LEN)
    let at_bound = "d".repeat(MAX_DETAIL_LEN);
    let ok = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(1),
        Some(at_bound),
    );
    assert!(ok.is_ok(), "detail at bound must succeed");

    // Bound + 1 strictly fails
    let over_bound = "d".repeat(MAX_DETAIL_LEN + 1);
    let err_over = EffectReconciliationRecord::new(
        op_id,
        idem_key,
        prep,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(1),
        Some(over_bound),
    );
    assert!(
        matches!(
            err_over,
            Err(EffectSchemaError::OverLimitLength {
                field: "detail",
                limit: MAX_DETAIL_LEN,
                actual
            }) if actual == MAX_DETAIL_LEN + 1
        ),
        "detail at bound + 1 must fail with OverLimitLength"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Typed Decode Errors (no aliases, no default on error, closed schemas)
// ---------------------------------------------------------------------------

#[test]
fn test_typed_decode_errors_schema_mismatch() -> Result<(), Box<dyn Error>> {
    let json_wrong_schema = r#"{
        "schema": "fss.effect_intent.v999",
        "operationId": "op:1",
        "idempotencyKey": "idem:1",
        "effectClass": "test",
        "requestDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "preconditionDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }"#;
    let res = EffectIntent::from_json(json_wrong_schema);
    assert!(
        matches!(res, Err(EffectSchemaError::SchemaMismatch { expected: "fss.effect_intent.v1", found }) if found == "fss.effect_intent.v999"),
        "Schema mismatch must return typed SchemaMismatch error"
    );
    Ok(())
}

#[test]
fn test_typed_decode_errors_unknown_field_rejected() -> Result<(), Box<dyn Error>> {
    let json_unknown_field = r#"{
        "schema": "fss.effect_intent.v1",
        "operationId": "op:1",
        "idempotencyKey": "idem:1",
        "effectClass": "test",
        "requestDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "preconditionDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "alias_or_extra_field": true
    }"#;
    let res = EffectIntent::from_json(json_unknown_field);
    assert!(
        matches!(res, Err(EffectSchemaError::JsonError { .. })),
        "Closed schema must reject unknown extra fields"
    );
    Ok(())
}

#[test]
fn test_typed_decode_errors_trailing_garbage_rejected() -> Result<(), Box<dyn Error>> {
    let mut json_trailing = sample_intent()?.to_canonical_json();
    json_trailing.push_str("   trailing-garbage");
    let res = EffectIntent::from_json(&json_trailing);
    assert!(
        matches!(res, Err(EffectSchemaError::JsonError { .. })),
        "Trailing garbage must be rejected"
    );
    Ok(())
}

#[test]
fn test_typed_decode_errors_binary_truncated_rejected() -> Result<(), Box<dyn Error>> {
    let bytes = sample_prepared()?.to_canonical_bytes()?;
    let truncated = &bytes[..bytes.len() - 5];
    let res = PreparedEffect::from_canonical_bytes(truncated);
    assert!(res.is_err(), "Truncated binary envelope must fail decoding");
    Ok(())
}

// ---------------------------------------------------------------------------
// Review 562 Failing Tests
// ---------------------------------------------------------------------------

#[test]
fn test_review_562_finding_1_indeterminate_requires_detail_and_no_naked_delivered()
-> Result<(), Box<dyn Error>> {
    let op_id = OperationId::parse("op:test:01")?;
    let idem_key = IdempotencyKey::parse("idem:test:01")?;
    let prep_digest = ContentDigest::sha256(b"prep");
    // Indeterminate without detail must fail closed
    let res_indet = EffectReconciliationRecord::new(
        op_id.clone(),
        idem_key.clone(),
        prep_digest,
        ReconciliationOutcome::Indeterminate,
        None,
        TimestampNs(100),
        None,
    );
    assert!(
        res_indet.is_err(),
        "Indeterminate outcome must require detail"
    );

    // Delivered without evidence must not be a terminal verified outcome
    let res_deliv = EffectReconciliationRecord::new(
        op_id,
        idem_key,
        prep_digest,
        ReconciliationOutcome::Delivered,
        None,
        TimestampNs(100),
        None,
    );
    assert!(
        res_deliv.is_err(),
        "Delivered without evidence witness must not construct reconciliation record"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_1_indeterminate_to_failed_transition_permitted()
-> Result<(), Box<dyn Error>> {
    assert!(
        EffectState::Indeterminate.can_transition_to(EffectState::Failed),
        "Indeterminate state must legally transition to Failed upon reconciliation"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_2_receipts_bind_prepared_effect_and_idempotency_key()
-> Result<(), Box<dyn Error>> {
    let obs = sample_observation_receipt()?;
    let obs_json = obs.to_canonical_json();
    assert!(
        obs_json.contains("\"preparedEffectDigest\""),
        "ProviderObservationReceipt must bind preparedEffectDigest"
    );
    assert!(
        obs_json.contains("\"idempotencyKey\""),
        "ProviderObservationReceipt must bind idempotencyKey"
    );

    let fail_receipt = sample_failure_receipt()?;
    let fail_json = fail_receipt.to_canonical_json();
    assert!(
        fail_json.contains("\"preparedEffectDigest\""),
        "ProviderFailureReceipt must bind preparedEffectDigest"
    );
    assert!(
        fail_json.contains("\"idempotencyKey\""),
        "ProviderFailureReceipt must bind idempotencyKey"
    );

    let rec_record = sample_reconciliation_verified()?;
    let rec_json = rec_record.to_canonical_json();
    assert!(
        rec_json.contains("\"preparedEffectDigest\""),
        "EffectReconciliationRecord must bind preparedEffectDigest"
    );
    assert!(
        rec_json.contains("\"idempotencyKey\""),
        "EffectReconciliationRecord must bind idempotencyKey"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_3_operation_receipt_schema_authority_fields_present()
-> Result<(), Box<dyn Error>> {
    let receipt = sample_operation_receipt()?;
    let json = receipt.to_canonical_json();
    assert!(
        json.contains("\"authority\""),
        "OperationReceipt must include required authority object"
    );
    assert!(
        json.contains("\"principal\""),
        "OperationReceipt authority must include principal"
    );
    assert!(
        json.contains("\"capability\""),
        "OperationReceipt authority must include capability"
    );

    // Also test roundtrip from_json
    let parsed = OperationReceipt::from_json(&json)?;
    assert_eq!(
        receipt, parsed,
        "OperationReceipt must roundtrip through canonical JSON"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_3_prepare_effect_requires_explicit_authority()
-> Result<(), Box<dyn Error>> {
    let mut journal = EffectJournal::new();
    let prepared = sample_prepared()?;
    let authority = EffectAuthority::new(
        "principal:operator:sec-ops",
        "cap:alert:dispatch",
        Some(101),
    )?;
    let receipt = journal.prepare_effect(prepared.clone(), authority.clone())?;
    assert_eq!(receipt.authority, authority);
    assert_eq!(receipt.intent, prepared.intent);
    assert_eq!(receipt.state, EffectState::Prepared);
    Ok(())
}

#[test]
fn test_review_562_finding_4_decode_canonical_enforces_bounds_and_invariants()
-> Result<(), Box<dyn Error>> {
    // Malformed binary payload for EffectReconciliationRecord: Verified with evidence_digest = None
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.effect_reconciliation.v1");
    OperationId::parse("op:test:01")?.encode_canonical(&mut enc);
    IdempotencyKey::parse("idem:test:01")?.encode_canonical(&mut enc);
    ContentDigest::sha256(b"prep").encode_canonical(&mut enc);
    ReconciliationOutcome::Verified.encode_canonical(&mut enc);
    enc.bool(false); // evidence_digest = None (invalid for Verified)
    TimestampNs(100).encode_canonical(&mut enc);
    enc.bool(false); // detail = None
    let bytes = enc.finish();

    let res = EffectReconciliationRecord::from_canonical_bytes(&bytes);
    assert!(
        res.is_err(),
        "decode_canonical must reject Verified outcome without evidence digest"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_5_reconciliation_from_json_accepts_omitted_optional_properties()
-> Result<(), Box<dyn Error>> {
    let json_minimal = r#"{
        "schema": "fss.effect_reconciliation.v1",
        "operationId": "op:test:01",
        "idempotencyKey": "idem:test:01",
        "preparedEffectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "outcome": "failed",
        "reconciledAt": 1000,
        "detail": "failure reason"
    }"#;
    let res = EffectReconciliationRecord::from_json(json_minimal);
    assert!(
        res.is_ok(),
        "from_json must accept JSON omitting optional property evidenceDigest"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_5_reconciliation_rejects_empty_string_detail()
-> Result<(), Box<dyn Error>> {
    let op_id = OperationId::parse("op:test:01")?;
    let idem_key = IdempotencyKey::parse("idem:test:01")?;
    let prep_digest = ContentDigest::sha256(b"prep");
    let evidence = ContentDigest::sha256(b"evidence");
    let res = EffectReconciliationRecord::new(
        op_id,
        idem_key,
        prep_digest,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(100),
        Some("".to_string()),
    );
    assert!(
        res.is_err(),
        "Empty string detail must violate minLength: 1"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_6_terminal_proof_and_failure_proof_domain_separation()
-> Result<(), Box<dyn Error>> {
    let intent = sample_intent()?;
    let predicate_or_err = "failed_timeout";
    let term_proof = intent.terminal_proof(predicate_or_err);
    let fail_proof = intent.failure_proof(predicate_or_err);
    assert_ne!(
        term_proof, fail_proof,
        "Terminal success proof and failure proof must have domain separation"
    );
    Ok(())
}

#[test]
fn test_review_562_finding_7_serialized_receipts_validate_against_disk_schemas()
-> Result<(), Box<dyn Error>> {
    let rec_schema = include_str!("../../../schemas/effect_reconciliation.v1.json");
    let obs_schema = include_str!("../../../schemas/provider_observation_receipt.v1.json");
    let fail_schema = include_str!("../../../schemas/provider_failure_receipt.v1.json");
    let op_schema = include_str!("../../../schemas/operation_receipt.v1.json");

    // All schemas must mandate idempotencyKey and preparedEffectDigest
    assert!(
        rec_schema.contains("\"idempotencyKey\""),
        "rec_schema must define idempotencyKey"
    );
    assert!(
        rec_schema.contains("\"preparedEffectDigest\""),
        "rec_schema must define preparedEffectDigest"
    );
    assert!(
        obs_schema.contains("\"idempotencyKey\""),
        "obs_schema must define idempotencyKey"
    );
    assert!(
        obs_schema.contains("\"preparedEffectDigest\""),
        "obs_schema must define preparedEffectDigest"
    );
    assert!(
        fail_schema.contains("\"idempotencyKey\""),
        "fail_schema must define idempotencyKey"
    );
    assert!(
        fail_schema.contains("\"preparedEffectDigest\""),
        "fail_schema must define preparedEffectDigest"
    );

    // Operation receipt must require authority
    assert!(
        op_schema.contains("\"authority\""),
        "op_schema must define authority"
    );
    assert!(
        op_schema.contains("\"principal\""),
        "op_schema must define principal"
    );
    assert!(
        op_schema.contains("\"capability\""),
        "op_schema must define capability"
    );

    // Serialized instances must contain the bound keys
    let rec_json = sample_reconciliation_verified()?.to_canonical_json();
    assert!(rec_json.contains("\"idempotencyKey\""));
    assert!(rec_json.contains("\"preparedEffectDigest\""));

    let obs_json = sample_observation_receipt()?.to_canonical_json();
    assert!(obs_json.contains("\"idempotencyKey\""));
    assert!(obs_json.contains("\"preparedEffectDigest\""));

    let fail_json = sample_failure_receipt()?.to_canonical_json();
    assert!(fail_json.contains("\"idempotencyKey\""));
    assert!(fail_json.contains("\"preparedEffectDigest\""));

    let op_json = sample_operation_receipt()?.to_canonical_json();
    assert!(op_json.contains("\"authority\""));

    // Deserialization of minimal instance with omitted optional properties works
    let minimal_rec = r#"{
        "schema": "fss.effect_reconciliation.v1",
        "operationId": "op:test:01",
        "idempotencyKey": "idem:test:01",
        "preparedEffectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "outcome": "failed",
        "reconciledAt": 1000,
        "detail": "failure reason"
    }"#;
    let decoded_rec = EffectReconciliationRecord::from_json(minimal_rec)?;
    assert_eq!(decoded_rec.evidence_digest, None);
    assert_eq!(decoded_rec.detail.as_deref(), Some("failure reason"));

    // Unknown fields must fail closed (closed schemas)
    let unknown_field = r#"{
        "schema": "fss.effect_reconciliation.v1",
        "operationId": "op:test:01",
        "idempotencyKey": "idem:test:01",
        "preparedEffectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "outcome": "failed",
        "reconciledAt": 1000,
        "detail": "failure reason",
        "attackerField": "injected"
    }"#;
    assert!(
        EffectReconciliationRecord::from_json(unknown_field).is_err(),
        "from_json must reject unknown injected fields"
    );

    Ok(())
}

struct MockIndeterminateLookup;

impl fss_core::effect::ProviderReceiptLookup for MockIndeterminateLookup {
    fn contains_observation(
        &self,
        _nonce: &ContentDigest,
        _message_digest: &ContentDigest,
    ) -> ReceiptLookupStatus {
        ReceiptLookupStatus::Indeterminate
    }
}

impl fss_core::effect::ProviderFailureLookup for MockIndeterminateLookup {
    fn contains_failure(
        &self,
        _nonce: &ContentDigest,
        _message_digest: &ContentDigest,
        _error_code: &str,
    ) -> ReceiptLookupStatus {
        ReceiptLookupStatus::Indeterminate
    }
}

#[test]
fn test_review_562_finding_1_three_valued_lookup_status() -> Result<(), Box<dyn Error>> {
    let obs = sample_observation_receipt()?;
    let fail = sample_failure_receipt()?;
    let mock = MockIndeterminateLookup;

    let obs_err = obs.verify_lookup(&mock);
    assert!(
        matches!(obs_err, Err(EffectSchemaError::IndeterminateLookup { .. })),
        "Indeterminate lookup must yield IndeterminateLookup error, not UnverifiedReceipt"
    );

    let fail_err = fail.verify_lookup(&mock);
    assert!(
        matches!(fail_err, Err(EffectSchemaError::IndeterminateLookup { .. })),
        "Indeterminate failure lookup must yield IndeterminateLookup error, not UnverifiedReceipt"
    );

    Ok(())
}

/// The canonical digest of `bytes` under `domain`, spelled out independently of the codec.
fn receipt_domain_digest(domain: &str, bytes: &[u8]) -> ContentDigest {
    let mut prefix = CanonicalEncoder::new();
    prefix.text("fss.canonical.v1");
    prefix.text(domain);
    let mut preimage = prefix.finish();
    preimage.extend_from_slice(bytes);
    ContentDigest::sha256(&preimage)
}

/// A v1 receipt of `receipt`'s intent, as only the journal's versioned replay of a v1 record
/// produces one (prepared at `receipt.prepared_at`, system authority).
fn replayed_v1_receipt(receipt: &OperationReceipt) -> Result<OperationReceipt, Box<dyn Error>> {
    use fss_core::{EffectJournalTransition, EffectRecordVersion};
    let journal = EffectJournal::replay_versioned([(
        EffectRecordVersion::V1,
        EffectJournalTransition::Prepare {
            intent: receipt.intent.clone(),
            obligation_id: ObligationId::parse("obligation:replayed-v1")?,
            terminal_predicate: "delivery_proved".to_owned(),
            now: receipt.prepared_at,
        },
    )])?;
    Ok(journal
        .operation(&receipt.intent.operation_id)
        .ok_or(ContractError::NotFound)?
        .clone())
}

/// The pre-deir9 canonical layout of a receipt with no commit time and no result digest.
fn v1_layout(receipt: &OperationReceipt) -> Vec<u8> {
    let mut legacy = CanonicalEncoder::new();
    receipt.intent.encode_canonical(&mut legacy);
    legacy.text(receipt.state.as_str());
    receipt.authority.encode_canonical(&mut legacy);
    receipt.prepared_at.encode_canonical(&mut legacy);
    legacy.bool(false);
    receipt.updated_at.encode_canonical(&mut legacy);
    legacy.bool(false);
    match &receipt.error_code {
        Some(code) => {
            legacy.bool(true);
            legacy.text(code);
        }
        None => legacy.bool(false),
    }
    legacy.finish()
}

/// fss-deir9 (D1): a v1 receipt keeps exactly its pre-deir9 canonical bytes and digest domain, and
/// its indeterminate reason is not in them; a v2 receipt opens with its own domain tag, its digest
/// binds the reason, and every shape round-trips. The public decoder refuses v1 bytes: a v1 receipt
/// exists only as the product of the journal's versioned replay.
#[test]
fn operation_receipt_versions_keep_v1_bytes_and_bind_the_v2_reason() -> Result<(), Box<dyn Error>> {
    use fss_core::{
        CanonicalDecode, CanonicalDecoder, EffectRecordVersion, IndeterminateEffectReason,
    };

    let base = sample_operation_receipt()?;
    // A fresh preparation is v3, which keeps the v2 bytes and digest domain (fss-thzlz).
    assert_eq!(base.record_version(), EffectRecordVersion::V3);
    assert_eq!(base.digest_domain(), OperationReceipt::DIGEST_DOMAIN_V2);
    let v1_base = replayed_v1_receipt(&base)?;
    assert_eq!(v1_base.record_version(), EffectRecordVersion::V1);
    assert_eq!(v1_base.digest_domain(), OperationReceipt::SCHEMA);
    let recorded = IndeterminateEffectReason::Recorded("provider_timeout".to_owned());
    let shapes = [
        (None, None),
        (Some("provider_timeout"), None),
        (None, Some(IndeterminateEffectReason::Unrecorded)),
        (Some("provider_timeout"), Some(recorded)),
    ];
    let mut v2_digests = BTreeSet::new();
    let mut v2_tag = CanonicalEncoder::new();
    v2_tag.u64(0);
    v2_tag.text(OperationReceipt::DIGEST_DOMAIN_V2);
    let v2_tag = v2_tag.finish();
    for (error_code, reason) in shapes {
        let mut receipt = base.clone();
        receipt.error_code = error_code.map(str::to_owned);
        receipt.indeterminate_reason = reason.clone();
        let mut encoder = CanonicalEncoder::new();
        receipt.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        assert!(
            bytes.starts_with(&v2_tag),
            "v2 opens with its tag: {error_code:?}"
        );
        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = OperationReceipt::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        assert_eq!(decoded, receipt, "v2 round trip of {error_code:?}");
        assert_eq!(
            receipt.receipt_digest(),
            receipt_domain_digest(OperationReceipt::DIGEST_DOMAIN_V2, &bytes)
        );
        assert!(
            v2_digests.insert(receipt.receipt_digest()),
            "the v2 digest binds the reason: {error_code:?}"
        );

        // v1: exactly the layout before the reason existed; the reason is not in its bytes.
        let mut v1 = v1_base.clone();
        v1.error_code = error_code.map(str::to_owned);
        let mut without_reason = CanonicalEncoder::new();
        v1.encode_canonical(&mut without_reason);
        let without_reason = without_reason.finish();
        v1.indeterminate_reason = reason;
        let mut with_reason = CanonicalEncoder::new();
        v1.encode_canonical(&mut with_reason);
        let legacy = with_reason.finish();
        assert_eq!(legacy, v1_layout(&v1), "v1 bytes of {error_code:?}");
        assert_eq!(
            legacy, without_reason,
            "a v1 receipt's reason is not digest-bound"
        );
        assert_eq!(
            v1.receipt_digest(),
            receipt_domain_digest(OperationReceipt::SCHEMA, &legacy)
        );
        let refused = OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&legacy));
        assert!(
            matches!(refused, Err(ContractError::LegacyReceiptRequiresJournal)),
            "{error_code:?}: {refused:?}"
        );
    }
    assert_eq!(v2_digests.len(), 4);

    // An unknown v2 reason tag is refused, never read as some reason.
    let mut encoder = CanonicalEncoder::new();
    base.encode_canonical(&mut encoder);
    let mut bytes = encoder.finish();
    let last = bytes.len().checked_sub(1).ok_or("empty receipt bytes")?;
    assert_eq!(bytes.get(last), Some(&0));
    if let Some(tag) = bytes.get_mut(last) {
        *tag = 3;
    }
    let refused = OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes));
    assert!(
        matches!(refused, Err(ContractError::InvalidIdentifier)),
        "{refused:?}"
    );

    // An operation id spelled like the v2 tag is a valid id; its v1 bytes are still v1, refused.
    let mut lookalike = base.clone();
    lookalike.intent.operation_id = OperationId::parse(OperationReceipt::DIGEST_DOMAIN_V2)?;
    let refused =
        OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&v1_layout(&lookalike)));
    assert!(
        matches!(refused, Err(ContractError::LegacyReceiptRequiresJournal)),
        "{refused:?}"
    );
    Ok(())
}

/// fss-deir9 round 4: stripping the 40-byte v2 prefix and the trailing reason byte off a current
/// receipt yields exactly v1 bytes of the same fields, and the public decoder refuses them, so a
/// current receipt cannot be relabelled as legacy (and so carry the legacy unrecorded marker).
#[test]
fn stripped_v2_receipt_cannot_be_decoded_as_legacy() -> Result<(), Box<dyn Error>> {
    use fss_core::{CanonicalDecode, CanonicalDecoder, IndeterminateEffectReason};

    let base = sample_operation_receipt()?;
    for (error_code, reason) in [
        (None, None),
        (None, Some(IndeterminateEffectReason::Unrecorded)),
        (Some("provider_timeout"), None),
    ] {
        let mut receipt = base.clone();
        receipt.error_code = error_code.map(str::to_owned);
        receipt.indeterminate_reason = reason;
        let mut encoder = CanonicalEncoder::new();
        receipt.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        let end = bytes.len().checked_sub(1).ok_or("empty receipt bytes")?;
        let stripped = bytes.get(40..end).ok_or("short receipt bytes")?;
        assert_eq!(stripped, v1_layout(&receipt).as_slice(), "{error_code:?}");
        let refused = OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(stripped));
        assert!(
            matches!(refused, Err(ContractError::LegacyReceiptRequiresJournal)),
            "{error_code:?}: {refused:?}"
        );
    }
    Ok(())
}

/// fss-deir9: every target state has an explicit transition payload rule, and `validate_transition`
/// and `transition` agree on it. The exhaustive matches below stop compiling when a state is added,
/// so a new state must be given its predecessor path and payload rule here too.
#[test]
fn every_effect_state_has_an_explicit_transition_payload_rule() -> Result<(), Box<dyn Error>> {
    let digest = ContentDigest::sha256(b"payload-rule");
    let every_state = [
        EffectState::Prepared,
        EffectState::Committed,
        EffectState::AdapterAccepted,
        EffectState::Observed,
        EffectState::Verified,
        EffectState::Cancelled,
        EffectState::Failed,
        EffectState::Indeterminate,
    ];
    for next in every_state {
        // Legal, payload-correct steps from `prepared` to a state that `next` may follow.
        let path: &[(EffectState, Option<ContentDigest>, Option<&str>)] = match next {
            EffectState::Prepared | EffectState::Committed | EffectState::Cancelled => &[],
            EffectState::AdapterAccepted | EffectState::Failed | EffectState::Indeterminate => {
                &[(EffectState::Committed, None, None)]
            }
            EffectState::Observed => &[
                (EffectState::Committed, None, None),
                (EffectState::AdapterAccepted, None, None),
            ],
            EffectState::Verified => &[
                (EffectState::Committed, None, None),
                (EffectState::AdapterAccepted, None, None),
                (EffectState::Observed, Some(digest), None),
            ],
        };
        // The exact verdict on each (result, error) payload for a transition into `next`: the
        // acceptance, or the typed refusal the journal names.
        let expected_verdict = |result: bool, error: Option<&str>| -> Result<(), ContractError> {
            let names_a_reason = error.is_some_and(|reason| !reason.is_empty());
            let accepted_unless = |refused: bool, refusal: ContractError| {
                if refused { Err(refusal) } else { Ok(()) }
            };
            match next {
                EffectState::Prepared => Err(ContractError::InvalidEffectTransition),
                EffectState::Committed | EffectState::AdapterAccepted => accepted_unless(
                    result || error.is_some(),
                    ContractError::InvalidEffectTransition,
                ),
                EffectState::Observed | EffectState::Verified => {
                    if result {
                        accepted_unless(error.is_some(), ContractError::InvalidEffectTransition)
                    } else {
                        Err(ContractError::EvidenceRequired)
                    }
                }
                // The generic transition cannot carry the cancel-request evidence a cancellation
                // requires, so every payload is refused; `cancel` is the only way to cancel
                // (fss-thzlz).
                EffectState::Cancelled => Err(ContractError::EvidenceRequired),
                EffectState::Failed => {
                    accepted_unless(!result || !names_a_reason, ContractError::EvidenceRequired)
                }
                EffectState::Indeterminate => {
                    accepted_unless(!names_a_reason, ContractError::EvidenceRequired)
                }
            }
        };
        for result in [false, true] {
            for error in [None, Some(""), Some("payload_rule")] {
                let intent = sample_intent()?;
                let operation_id = intent.operation_id.clone();
                let mut journal = EffectJournal::new();
                let _ = journal.prepare(
                    intent,
                    ObligationId::parse("obligation:payload-rule")?,
                    "delivery_proved",
                    TimestampNs(100),
                )?;
                let mut now = 100;
                for &(state, step_digest, step_error) in path {
                    now += 1;
                    let _ = journal.transition(
                        &operation_id,
                        state,
                        TimestampNs(now),
                        step_digest,
                        step_error.map(str::to_owned),
                    )?;
                }
                now += 1;
                let result_digest = result.then_some(digest);
                let expected = expected_verdict(result, error);
                let validated = journal
                    .validate_transition(
                        &operation_id,
                        next,
                        TimestampNs(now),
                        result_digest,
                        error,
                    )
                    .map(|_| ());
                assert_eq!(
                    validated,
                    expected,
                    "validate_transition into {} with result={result} error={error:?}",
                    next.as_str()
                );
                let applied = journal
                    .transition(
                        &operation_id,
                        next,
                        TimestampNs(now),
                        result_digest,
                        error.map(str::to_owned),
                    )
                    .map(|_| ());
                assert_eq!(
                    applied,
                    expected,
                    "transition into {} with result={result} error={error:?}",
                    next.as_str()
                );
            }
        }
    }
    Ok(())
}

/// fss-thzlz: `cancel` is the only way to cancel. `validate_cancel` and `cancel` share its payload
/// rule (a reason is optional, never empty), and the result digest is the bound proof.
#[test]
fn cancel_payload_rule_is_shared_by_validate_cancel_and_cancel() -> Result<(), Box<dyn Error>> {
    let evidence = ContentDigest::sha256(b"cancel-request-evidence");
    for reason in [None, Some(""), Some("operator_revoked")] {
        let intent = sample_intent()?;
        let operation_id = intent.operation_id.clone();
        let mut journal = EffectJournal::new();
        let _ = journal.prepare(
            intent,
            ObligationId::parse("obligation:cancel-rule")?,
            "delivery_proved",
            TimestampNs(100),
        )?;
        let proof = journal.cancellation_proof(&operation_id, evidence)?;
        let expected = if reason == Some("") {
            Err(ContractError::EvidenceRequired)
        } else {
            Ok(proof)
        };
        assert_eq!(
            journal.validate_cancel(&operation_id, TimestampNs(101), evidence, reason),
            expected,
            "{reason:?}"
        );
        let applied = journal
            .cancel(
                &operation_id,
                TimestampNs(101),
                evidence,
                reason.map(str::to_owned),
            )
            .map(|receipt| receipt.result_digest);
        assert_eq!(applied, expected.map(Some), "{reason:?}");
    }
    Ok(())
}
