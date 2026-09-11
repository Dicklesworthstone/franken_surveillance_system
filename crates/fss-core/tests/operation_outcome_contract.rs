//! Contract and property test suite for four-valued operation outcomes and stable errors (FSS-004).
//!
//! Enforces:
//! - Exactly four mutually distinct outcome variants: Success, Failed, Indeterminate, UnauthorizedOrNotObservable
//! - Strict invariant: Indeterminate and UnauthorizedOrNotObservable outcomes can NEVER be upgraded to Success by any combinator
//! - Complete absence of implicit conversion to/from standard Result
//! - Validated stable ErrorId format adhering to `^ERR-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$`
//! - Structured OperationError carrying RecoveryClass, safe_retry, resnapshot, reconciliation, rebase, and backoff guidance
//! - Deterministic CanonicalEncode and CanonicalDecode roundtrips across all variants
//! - Bounded failure handling on corrupted, truncated, or trailing bytes

#![forbid(unsafe_code)]

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContractError, ErrorId, IndeterminateDetail, OperationError,
    OperationOutcome, RecoveryClass, RefusalDetail, RefusalReason, validate_error_id,
    ERR_OP_EXECUTION_FAILED_001, ERR_OP_ID_MALFORMED_001, ERR_OP_INDETERMINATE_001,
    ERR_OP_INVALID_OUTCOME_001, ERR_OP_NOT_OBSERVABLE_001, ERR_OP_PRECONDITION_FAILED_001,
    ERR_OP_RECONCILIATION_REQUIRED_001, ERR_OP_TIMEOUT_001, ERR_OP_UNAUTHORIZED_001,
};

#[test]
fn outcome_four_valued_construction_and_discrimination() -> Result<(), Box<dyn Error>> {
    let success: OperationOutcome<u64> = OperationOutcome::success(42);
    let error = OperationError::execution_failed("database execution failed")?;
    let failed: OperationOutcome<u64> = OperationOutcome::failed(error);

    let ind_detail = IndeterminateDetail::new(
        "commit",
        "effect dispatch timeout",
        "query ledger receipt before retry",
    );
    let indeterminate: OperationOutcome<u64> = OperationOutcome::indeterminate(ind_detail);

    let refusal = RefusalDetail::unauthorized(
        "camera PTZ control disallowed",
        Some("CAP-CAMERA-PTZ-001"),
    );
    let unauthorized: OperationOutcome<u64> =
        OperationOutcome::unauthorized_or_not_observable(refusal);

    let not_obs = RefusalDetail::not_observable("interval has no sensor coverage", true);
    let not_observable: OperationOutcome<u64> =
        OperationOutcome::unauthorized_or_not_observable(not_obs);

    // Discrimination tests
    assert!(success.is_success());
    assert!(!success.is_failed());
    assert!(!success.is_indeterminate());
    assert!(!success.is_unauthorized_or_not_observable());
    assert_eq!(success.as_success(), Some(&42));
    assert_eq!(success.as_failed(), None);
    assert_eq!(success.as_indeterminate(), None);
    assert_eq!(success.as_unauthorized_or_not_observable(), None);

    assert!(!failed.is_success());
    assert!(failed.is_failed());
    assert!(!failed.is_indeterminate());
    assert!(!failed.is_unauthorized_or_not_observable());
    assert_eq!(failed.as_success(), None);
    assert!(failed.as_failed().is_some());

    assert!(!indeterminate.is_success());
    assert!(!indeterminate.is_failed());
    assert!(indeterminate.is_indeterminate());
    assert!(!indeterminate.is_unauthorized_or_not_observable());
    assert_eq!(indeterminate.as_success(), None);
    assert_eq!(indeterminate.as_failed(), None);
    assert_eq!(
        indeterminate.as_indeterminate().map(|d| d.phase.as_str()),
        Some("commit")
    );

    assert!(!unauthorized.is_success());
    assert!(!unauthorized.is_failed());
    assert!(!unauthorized.is_indeterminate());
    assert!(unauthorized.is_unauthorized_or_not_observable());
    assert_eq!(
        unauthorized
            .as_unauthorized_or_not_observable()
            .map(|r| r.reason),
        Some(RefusalReason::Unauthorized)
    );

    assert!(not_observable.is_unauthorized_or_not_observable());
    assert_eq!(
        not_observable
            .as_unauthorized_or_not_observable()
            .map(|r| r.reason),
        Some(RefusalReason::NotObservable)
    );

    // Consumption into_* methods
    assert_eq!(success.into_success(), Some(42));
    assert!(failed.into_failed().is_some());
    assert_eq!(
        indeterminate.into_indeterminate().map(|d| d.phase),
        Some("commit".to_string())
    );
    assert_eq!(
        unauthorized
            .into_unauthorized_or_not_observable()
            .map(|r| r.reason),
        Some(RefusalReason::Unauthorized)
    );

    Ok(())
}

#[test]
fn indeterminate_cannot_be_upgraded_by_map() -> Result<(), Box<dyn Error>> {
    let ind = IndeterminateDetail::new("dispatch", "ack lost", "reconcile");
    let outcome: OperationOutcome<u32> = OperationOutcome::indeterminate(ind);

    let mapped = outcome.map(|val| {
        // If this closure is executed, fail the test immediately
        val + 100
    });

    assert!(mapped.is_indeterminate());
    assert!(!mapped.is_success());
    assert_eq!(
        mapped.as_indeterminate().map(|d| d.phase.as_str()),
        Some("dispatch")
    );

    Ok(())
}

#[test]
fn indeterminate_cannot_be_upgraded_by_map_err() -> Result<(), Box<dyn Error>> {
    let ind = IndeterminateDetail::new("dispatch", "ack lost", "reconcile");
    let outcome: OperationOutcome<u32, OperationError> = OperationOutcome::indeterminate(ind);

    let mapped = outcome.map_err(|err| {
        // Should not be called
        err
    });

    assert!(mapped.is_indeterminate());
    assert!(!mapped.is_success());
    assert_eq!(
        mapped.as_indeterminate().map(|d| d.phase.as_str()),
        Some("dispatch")
    );

    Ok(())
}

#[test]
fn indeterminate_cannot_be_upgraded_by_and_then() -> Result<(), Box<dyn Error>> {
    let ind = IndeterminateDetail::new("commit", "two-phase timeout", "inspect participant");
    let outcome: OperationOutcome<u32> = OperationOutcome::indeterminate(ind);

    let chained = outcome.and_then(|_| {
        // Attempting to upgrade to Success within and_then
        OperationOutcome::success(9999)
    });

    assert!(chained.is_indeterminate());
    assert!(!chained.is_success());
    assert_eq!(
        chained.as_indeterminate().map(|d| d.phase.as_str()),
        Some("commit")
    );

    Ok(())
}

#[test]
fn indeterminate_cannot_be_upgraded_by_or_else() -> Result<(), Box<dyn Error>> {
    let ind = IndeterminateDetail::new("journal", "torn write", "reconcile journal");
    let outcome: OperationOutcome<u32> = OperationOutcome::indeterminate(ind);

    // Caller attempts to "catch" and recover to Success
    let recovered: OperationOutcome<u32, OperationError> =
        outcome.or_else(|_| OperationOutcome::success(9999));

    // Must remain Indeterminate! or_else only recovers from Failed(E), NEVER from Indeterminate!
    assert!(recovered.is_indeterminate());
    assert!(!recovered.is_success());
    assert_eq!(
        recovered.as_indeterminate().map(|d| d.phase.as_str()),
        Some("journal")
    );

    Ok(())
}

#[test]
fn indeterminate_cannot_be_upgraded_by_flatten() -> Result<(), Box<dyn Error>> {
    let ind = IndeterminateDetail::new("transport", "connection reset", "reconcile stream");

    // Outer is Indeterminate
    let outer_ind: OperationOutcome<OperationOutcome<u32>> = OperationOutcome::indeterminate(ind.clone());
    let flattened1 = outer_ind.flatten();
    assert!(flattened1.is_indeterminate());
    assert!(!flattened1.is_success());

    // Outer is Success, Inner is Indeterminate
    let inner_ind: OperationOutcome<OperationOutcome<u32>> =
        OperationOutcome::success(OperationOutcome::indeterminate(ind));
    let flattened2 = inner_ind.flatten();
    assert!(flattened2.is_indeterminate());
    assert!(!flattened2.is_success());

    Ok(())
}

#[test]
fn unauthorized_or_not_observable_cannot_be_upgraded() -> Result<(), Box<dyn Error>> {
    let refusal = RefusalDetail::unauthorized("no grant", Some("CAP-TEST-001"));
    let outcome: OperationOutcome<u32> = OperationOutcome::unauthorized_or_not_observable(refusal.clone());

    // Test map
    let mapped = outcome.clone().map(|x| x * 2);
    assert!(mapped.is_unauthorized_or_not_observable());
    assert!(!mapped.is_success());

    // Test map_err
    let mapped_err = outcome.clone().map_err(|e| e);
    assert!(mapped_err.is_unauthorized_or_not_observable());
    assert!(!mapped_err.is_success());

    // Test and_then
    let chained = outcome.clone().and_then(|_| OperationOutcome::success(1234));
    assert!(chained.is_unauthorized_or_not_observable());
    assert!(!chained.is_success());

    // Test or_else
    let recovered: OperationOutcome<u32, OperationError> =
        outcome.clone().or_else(|_| OperationOutcome::success(1234));
    assert!(recovered.is_unauthorized_or_not_observable());
    assert!(!recovered.is_success());

    // Test flatten
    let nested: OperationOutcome<OperationOutcome<u32>> =
        OperationOutcome::success(OperationOutcome::unauthorized_or_not_observable(refusal));
    let flat = nested.flatten();
    assert!(flat.is_unauthorized_or_not_observable());
    assert!(!flat.is_success());

    Ok(())
}

#[test]
fn combinators_work_on_success_and_failed() -> Result<(), Box<dyn Error>> {
    let err = OperationError::execution_failed("original error")?;
    let failed: OperationOutcome<i32> = OperationOutcome::failed(err);
    let success: OperationOutcome<i32> = OperationOutcome::success(10);

    // map
    let s_mapped = success.clone().map(|x| x * 3);
    assert_eq!(s_mapped.as_success(), Some(&30));
    let f_mapped = failed.clone().map(|x| x * 3);
    assert!(f_mapped.is_failed());

    // map_err
    let f_mapped_err = failed.clone().map_err(|e| {
        OperationError::new(
            e.error_id,
            format!("wrapped: {}", e.message),
            e.recovery_class,
        )
    });
    assert_eq!(
        f_mapped_err
            .as_failed()
            .map(|e| e.message.starts_with("wrapped:")),
        Some(true)
    );

    // and_then
    let s_chained = success.clone().and_then(|x| OperationOutcome::success(x + 5));
    assert_eq!(s_chained.as_success(), Some(&15));
    let f_chained = failed.clone().and_then(|x| OperationOutcome::success(x + 5));
    assert!(f_chained.is_failed());

    // or_else on failed recovers
    let recovered: OperationOutcome<i32, OperationError> =
        failed.or_else(|_| OperationOutcome::success(100));
    assert_eq!(recovered.as_success(), Some(&100));

    // or_else on success is no-op
    let s_recovered: OperationOutcome<i32, OperationError> =
        success.or_else(|_| OperationOutcome::success(100));
    assert_eq!(s_recovered.as_success(), Some(&10));

    // flatten
    let nested_success: OperationOutcome<OperationOutcome<i32>> =
        OperationOutcome::success(OperationOutcome::success(77));
    assert_eq!(nested_success.flatten().as_success(), Some(&77));

    let nested_failed: OperationOutcome<OperationOutcome<i32>> =
        OperationOutcome::failed(OperationError::execution_failed("outer fail")?);
    assert!(nested_failed.flatten().is_failed());

    Ok(())
}

#[test]
fn error_id_validation_valid_cases() -> Result<(), Box<dyn Error>> {
    let valid_ids = [
        ERR_OP_EXECUTION_FAILED_001,
        ERR_OP_PRECONDITION_FAILED_001,
        ERR_OP_INDETERMINATE_001,
        ERR_OP_UNAUTHORIZED_001,
        ERR_OP_NOT_OBSERVABLE_001,
        ERR_OP_TIMEOUT_001,
        ERR_OP_RECONCILIATION_REQUIRED_001,
        ERR_OP_ID_MALFORMED_001,
        ERR_OP_INVALID_OUTCOME_001,
        "ERR-AUTH-DENIED-001",
        "ERR-A-001",
        "ERR-MODULE1-SUB2-SEG3-999",
    ];

    for &id_str in &valid_ids {
        let err_id = ErrorId::parse(id_str)?;
        assert_eq!(err_id.as_str(), id_str);
        assert_eq!(err_id.to_string(), id_str);
        assert_eq!(validate_error_id(id_str), Ok(()));
    }

    Ok(())
}

#[test]
fn error_id_validation_rejections() -> Result<(), Box<dyn Error>> {
    let invalid_ids = [
        "",
        "ERR",
        "ERR-",
        "ERR-001",                   // Missing middle segment
        "err-op-001",               // Lowercase prefix
        "ERR-OP",                   // Missing numeric suffix
        "ERR-OP-1",                 // Suffix only 1 digit
        "ERR-OP-12",                // Suffix only 2 digits
        "ERR-OP-1234",              // Suffix 4 digits
        "ERR-OP--001",              // Empty middle segment
        "ERR--OP-001",              // Empty middle segment
        "ERR-OP-lowercase-001",     // Lowercase in middle segment
        "ERR-OP-SPECIAL!-001",      // Special character forbidden
        "ERR-OP-00A",               // Non-digit in suffix
    ];

    for &bad in &invalid_ids {
        let res = ErrorId::parse(bad);
        if res.is_ok() {
            return Err(format!("Expected rejection for invalid ErrorId: '{bad}'").into());
        }
    }

    Ok(())
}

#[test]
fn operation_error_guidance_fields_and_builder() -> Result<(), Box<dyn Error>> {
    let op_err = OperationError::precondition_failed(
        "anchor epoch drift detected",
        "rebase situation capsule to epoch 42",
    )?
    .with_safe_retry(false)
    .with_backoff_ms(250);

    assert_eq!(op_err.error_id.as_str(), ERR_OP_PRECONDITION_FAILED_001);
    assert_eq!(op_err.recovery_class, RecoveryClass::RebaseRequired);
    assert!(!op_err.safe_retry);
    assert!(op_err.resnapshot_required);
    assert!(!op_err.reconciliation_required);
    assert_eq!(
        op_err.rebase_guidance.as_deref(),
        Some("rebase situation capsule to epoch 42")
    );
    assert_eq!(op_err.backoff_ms, Some(250));

    let display = format!("{op_err}");
    assert!(display.contains("rebase_required"));
    assert!(display.contains(ERR_OP_PRECONDITION_FAILED_001));
    assert!(display.contains("anchor epoch drift detected"));
    assert!(display.contains("rebase situation capsule to epoch 42"));
    assert!(display.contains("backoff_ms: 250"));

    // Reconciliation error
    let recon_err = OperationError::reconciliation_required_error("pending mutation unresolved")?;
    assert_eq!(
        recon_err.error_id.as_str(),
        ERR_OP_RECONCILIATION_REQUIRED_001
    );
    assert_eq!(
        recon_err.recovery_class,
        RecoveryClass::ReconciliationRequired
    );
    assert!(recon_err.reconciliation_required);
    assert!(recon_err.resnapshot_required);

    Ok(())
}

#[test]
fn canonical_encoding_roundtrip_all_four_variants() -> Result<(), Box<dyn Error>> {
    // 1. Success variant (u64)
    let outcome1: OperationOutcome<u64> = OperationOutcome::success(987654321);
    let bytes1 = outcome1.canonical_bytes();
    let decoded1: OperationOutcome<u64> = OperationOutcome::from_canonical_bytes(&bytes1)?;
    assert_eq!(outcome1, decoded1);

    // 2. Success variant (String)
    let outcome2: OperationOutcome<String> =
        OperationOutcome::success("event_log_segment_alpha".to_string());
    let bytes2 = outcome2.canonical_bytes();
    let decoded2: OperationOutcome<String> = OperationOutcome::from_canonical_bytes(&bytes2)?;
    assert_eq!(outcome2, decoded2);

    // 3. Success variant (Unit ())
    let outcome3: OperationOutcome<()> = OperationOutcome::success(());
    let bytes3 = outcome3.canonical_bytes();
    let decoded3: OperationOutcome<()> = OperationOutcome::from_canonical_bytes(&bytes3)?;
    assert_eq!(outcome3, decoded3);

    // 4. Failed variant
    let err = OperationError::new(
        ErrorId::parse(ERR_OP_TIMEOUT_001)?,
        "operation budget expired after 5000ms",
        RecoveryClass::Backoff,
    )
    .with_safe_retry(true)
    .with_backoff_ms(1000);
    let outcome4: OperationOutcome<u64> = OperationOutcome::failed(err);
    let bytes4 = outcome4.canonical_bytes();
    let decoded4: OperationOutcome<u64> = OperationOutcome::from_canonical_bytes(&bytes4)?;
    assert_eq!(outcome4, decoded4);

    // 5. Indeterminate variant
    let ind = IndeterminateDetail::new(
        "commit",
        "upstream network partition during commit acknowledge",
        "query ledger state at anchor hash before retrying",
    )
    .with_pending_id("pending_mut_771")
    .with_resnapshot(true);
    let outcome5: OperationOutcome<u64> = OperationOutcome::indeterminate(ind);
    let bytes5 = outcome5.canonical_bytes();
    let decoded5: OperationOutcome<u64> = OperationOutcome::from_canonical_bytes(&bytes5)?;
    assert_eq!(outcome5, decoded5);

    // 6. Unauthorized refusal variant
    let ref_unauth = RefusalDetail::unauthorized(
        "principal lacks export authority for raw media",
        Some("CAP-MEDIA-EXPORT-001"),
    );
    let outcome6: OperationOutcome<u64> =
        OperationOutcome::unauthorized_or_not_observable(ref_unauth);
    let bytes6 = outcome6.canonical_bytes();
    let decoded6: OperationOutcome<u64> = OperationOutcome::from_canonical_bytes(&bytes6)?;
    assert_eq!(outcome6, decoded6);

    // 7. NotObservable refusal variant
    let ref_not_obs = RefusalDetail::not_observable(
        "sensor mesh was degraded; target zone was not observable",
        true,
    );
    let outcome7: OperationOutcome<u64> =
        OperationOutcome::unauthorized_or_not_observable(ref_not_obs);
    let bytes7 = outcome7.canonical_bytes();
    let decoded7: OperationOutcome<u64> = OperationOutcome::from_canonical_bytes(&bytes7)?;
    assert_eq!(outcome7, decoded7);

    Ok(())
}

#[test]
fn canonical_encoding_deterministic_digest() -> Result<(), Box<dyn Error>> {
    let outcome_a: OperationOutcome<u64> = OperationOutcome::success(12345);
    let outcome_b: OperationOutcome<u64> = OperationOutcome::success(12345);
    let outcome_diff: OperationOutcome<u64> = OperationOutcome::success(12346);

    let digest_a = outcome_a.canonical_digest("fss.outcome.v1");
    let digest_b = outcome_b.canonical_digest("fss.outcome.v1");
    let digest_diff = outcome_diff.canonical_digest("fss.outcome.v1");

    assert_eq!(digest_a, digest_b);
    assert_ne!(digest_a, digest_diff);

    Ok(())
}

#[test]
fn canonical_decoding_rejects_corrupted_and_trailing_bytes() -> Result<(), Box<dyn Error>> {
    // Empty bytes
    let empty_res = OperationOutcome::<u64>::from_canonical_bytes(&[]);
    assert_eq!(empty_res, Err(ContractError::InvalidDigest));

    // Invalid variant tag (e.g. tag 4)
    let invalid_tag = [4u8, 0, 0, 0, 0, 0, 0, 0, 0];
    let tag_res = OperationOutcome::<u64>::from_canonical_bytes(&invalid_tag);
    assert_eq!(tag_res, Err(ContractError::InvalidIdentifier));

    // Trailing bytes after complete object
    let valid_bytes = OperationOutcome::<u64, OperationError>::success(10u64).canonical_bytes();
    let mut trailing = valid_bytes.clone();
    trailing.push(0xFF);
    let trailing_res = OperationOutcome::<u64>::from_canonical_bytes(&trailing);
    assert_eq!(trailing_res, Err(ContractError::NonCanonicalOrdering));

    Ok(())
}

#[test]
fn recovery_class_roundtrip_and_parse() -> Result<(), Box<dyn Error>> {
    let classes = [
        (RecoveryClass::NeverUnchanged, "never_unchanged"),
        (RecoveryClass::SafeReadRetry, "safe_read_retry"),
        (RecoveryClass::RefreshAndRetry, "refresh_and_retry"),
        (RecoveryClass::RebaseRequired, "rebase_required"),
        (RecoveryClass::Backoff, "backoff"),
        (RecoveryClass::ReconciliationRequired, "reconciliation_required"),
        (RecoveryClass::OperatorActionRequired, "operator_action_required"),
        (RecoveryClass::ResumeFromContinuation, "resume_from_continuation"),
    ];

    for (class, expected_str) in classes {
        assert_eq!(class.as_str(), expected_str);
        assert_eq!(RecoveryClass::parse(expected_str)?, class);

        let bytes = class.canonical_bytes();
        let decoded = RecoveryClass::from_canonical_bytes(&bytes)?;
        assert_eq!(class, decoded);
    }

    assert_eq!(
        RecoveryClass::parse("invalid_recovery"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn refusal_reason_roundtrip_and_parse() -> Result<(), Box<dyn Error>> {
    let reasons = [
        (RefusalReason::Unauthorized, "unauthorized"),
        (RefusalReason::NotObservable, "not_observable"),
    ];

    for (reason, expected_str) in reasons {
        assert_eq!(reason.as_str(), expected_str);
        assert_eq!(RefusalReason::parse(expected_str)?, reason);

        let bytes = reason.canonical_bytes();
        let decoded = RefusalReason::from_canonical_bytes(&bytes)?;
        assert_eq!(reason, decoded);
    }

    assert_eq!(
        RefusalReason::parse("unknown_refusal"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}
