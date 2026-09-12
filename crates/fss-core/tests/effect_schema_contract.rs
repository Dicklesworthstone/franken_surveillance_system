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
    EffectIntent, EffectJournal, EffectReconciliationRecord, EffectSchemaError, MAX_DETAIL_LEN,
    MAX_EFFECT_CLASS_LEN, MAX_ERROR_CODE_LEN, MAX_TERMINAL_PREDICATE_LEN, PreparedEffect,
    ProviderFailureReceipt, ProviderObservationReceipt, ReconciliationOutcome,
};
use fss_core::{
    ContentDigest, ContractError, IdempotencyKey, ObligationId, OperationId, TimestampNs,
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

fn sample_observation_receipt() -> ProviderObservationReceipt {
    let nonce = ContentDigest::sha256(b"provider-secret-nonce-12345");
    let msg_digest = ContentDigest::sha256(b"alert-message-payload");
    ProviderObservationReceipt::new(nonce, msg_digest)
}

fn sample_failure_receipt() -> Result<ProviderFailureReceipt, Box<dyn Error>> {
    let nonce = ContentDigest::sha256(b"provider-secret-nonce-99999");
    let msg_digest = ContentDigest::sha256(b"alert-message-payload");
    Ok(ProviderFailureReceipt::new(
        nonce,
        msg_digest,
        "rate_limited",
    )?)
}

fn sample_reconciliation_verified() -> Result<EffectReconciliationRecord, Box<dyn Error>> {
    let op_id = OperationId::parse("op:alert:dispatch:01")?;
    let evidence = ContentDigest::sha256(b"external-delivery-log");
    Ok(EffectReconciliationRecord::new(
        op_id,
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(1_700_000_001_000_000_000),
        Some("verified against provider delivery log".to_string()),
    )?)
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
    let original = sample_observation_receipt();
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
    let original = sample_observation_receipt();
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
    let obs = sample_observation_receipt();
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
    let forged_obs = ProviderObservationReceipt::new(fake_nonce, obs.message_digest);
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
    let evidence = ContentDigest::sha256(b"proof-evidence");

    // Verified REQUIRES evidence
    let verified_no_evidence = EffectReconciliationRecord::new(
        op_id.clone(),
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
        ReconciliationOutcome::Verified,
        Some(evidence),
        TimestampNs(100),
        None,
    );
    assert!(verified_ok.is_ok());

    // Failed REQUIRES detail/reason
    let failed_no_detail = EffectReconciliationRecord::new(
        op_id.clone(),
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
        ReconciliationOutcome::Failed,
        None,
        TimestampNs(100),
        Some("provider connection refused".to_string()),
    );
    assert!(failed_ok.is_ok());

    // Indeterminate cannot carry verified evidence
    let indeterminate_with_evidence = EffectReconciliationRecord::new(
        op_id.clone(),
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

    // Delivered succeeds with or without observation evidence
    let delivered_ok = EffectReconciliationRecord::new(
        op_id,
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

    // Empty fails
    let err_empty = ProviderFailureReceipt::new(nonce, msg, "");
    assert!(matches!(
        err_empty,
        Err(EffectSchemaError::MissingField { field: "errorCode" })
    ));

    // Exactly at bound (MAX_ERROR_CODE_LEN)
    let at_bound = "e".repeat(MAX_ERROR_CODE_LEN);
    let ok = ProviderFailureReceipt::new(nonce, msg, at_bound);
    assert!(ok.is_ok(), "errorCode at bound must succeed");

    // Bound + 1 strictly fails
    let over_bound = "e".repeat(MAX_ERROR_CODE_LEN + 1);
    let err_over = ProviderFailureReceipt::new(nonce, msg, over_bound);
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
    let evidence = ContentDigest::sha256(b"e");

    // Exactly at bound (MAX_DETAIL_LEN)
    let at_bound = "d".repeat(MAX_DETAIL_LEN);
    let ok = EffectReconciliationRecord::new(
        op_id.clone(),
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
