#![forbid(unsafe_code)]
//! Contract and invariant tests for the deterministic test-event and proof-logging substrate.
//!
//! Ref: `fss-x4a.28.40` / `TEST-HARNESS-001`.
//!
//! Validates:
//! - Exact bound and bound+1 sizes for all identifier and payload fields.
//! - Deterministic JSONL serialization and round-trip deserialization.
//! - Secret and credential detection.
//! - Monotone sequence enforcement in `TestEventCollector`.
//! - Typed outcomes and explicit clock duration preservation.

use std::error::Error;

use fss_core::{
    ContentDigest, MAX_TEST_CASE_ID_LEN, MAX_TEST_DETAIL_LEN, MAX_TEST_EVENT_JSON_BYTES,
    MAX_TEST_EVENTS_COUNT, MAX_TEST_PHASE_LEN, MAX_TEST_RUN_ID_LEN, MAX_TEST_STEP_ID_LEN,
    MAX_TEST_TAG_LEN, MAX_TEST_TAGS_COUNT, TEST_EVENT_SCHEMA, TEST_EVENT_VERSION_1,
    TestEventCollector, TestEventError, TestEventRecord, TestOutcome,
};

type TestResult = Result<(), Box<dyn Error>>;

fn sample_record() -> TestEventRecord {
    TestEventRecord {
        schema: TEST_EVENT_SCHEMA,
        version: TEST_EVENT_VERSION_1,
        run_id: "run:2026-09-12-nightly-001".to_string(),
        case_id: "case:crash_consistency_sweep".to_string(),
        step_id: "step:0042".to_string(),
        sequence: 42,
        seed: 1337,
        source_digest: ContentDigest::sha256(b"source:harness_v1"),
        contract_digest: ContentDigest::sha256(b"contract:FSS-017"),
        input_digest: ContentDigest::sha256(b"input:target_operation_42"),
        expected_digest: ContentDigest::sha256(b"expected:oracle_state"),
        actual_digest: ContentDigest::sha256(b"actual:recovered_disk_state"),
        outcome: TestOutcome::Passed,
        duration_ns: 12_500_000,
        phase: Some("ledger_commit".to_string()),
        tags: vec![
            "class:converged".to_string(),
            "phase:journal_sync".to_string(),
        ],
        detail: Some("clean recovery after abort at step 42".to_string()),
    }
}

#[test]
fn test_round_trip_serialization() -> TestResult {
    let original = sample_record();
    let jsonl = original.to_jsonl()?;
    assert!(jsonl.ends_with('\n'), "JSONL must terminate with a newline");

    let parsed = TestEventRecord::from_json_str(&jsonl)?;
    assert_eq!(
        original, parsed,
        "deserialized record must match original exactly"
    );
    Ok(())
}

#[test]
fn test_round_trip_without_optional_fields() -> TestResult {
    let mut original = sample_record();
    original.phase = None;
    original.tags.clear();
    original.detail = None;

    let jsonl = original.to_jsonl()?;
    let parsed = TestEventRecord::from_json_str(&jsonl)?;
    assert_eq!(original, parsed);
    assert_eq!(parsed.phase, None);
    assert!(parsed.tags.is_empty());
    assert_eq!(parsed.detail, None);
    Ok(())
}

#[test]
fn test_all_outcome_variants() -> TestResult {
    let outcomes = [
        (TestOutcome::Passed, "passed"),
        (TestOutcome::Failed, "failed"),
        (TestOutcome::Skipped, "skipped"),
        (TestOutcome::Crashed, "crashed"),
        (TestOutcome::Cancelled, "cancelled"),
        (TestOutcome::Indeterminate, "indeterminate"),
        (TestOutcome::Rejected, "rejected"),
    ];

    for (variant, name) in outcomes {
        assert_eq!(variant.as_str(), name);
        assert_eq!(TestOutcome::parse(name)?, variant);

        let mut rec = sample_record();
        rec.outcome = variant;
        let jsonl = rec.to_jsonl()?;
        let parsed = TestEventRecord::from_json_str(&jsonl)?;
        assert_eq!(parsed.outcome, variant);
    }

    let invalid = TestOutcome::parse("unknown_outcome");
    assert!(matches!(invalid, Err(TestEventError::InvalidOutcome(_))));
    Ok(())
}

#[test]
fn test_run_id_bounds() -> TestResult {
    let mut rec = sample_record();

    // At bound
    rec.run_id = "a".repeat(MAX_TEST_RUN_ID_LEN);
    assert!(rec.validate().is_ok());

    // At bound + 1
    rec.run_id = "a".repeat(MAX_TEST_RUN_ID_LEN + 1);
    match rec.validate() {
        Err(TestEventError::RunIdTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_RUN_ID_LEN);
            assert_eq!(actual, MAX_TEST_RUN_ID_LEN + 1);
        }
        other => return Err(format!("expected RunIdTooLong, got {other:?}").into()),
    }

    // Empty
    rec.run_id.clear();
    match rec.validate() {
        Err(TestEventError::EmptyIdentifier("run_id")) => {}
        other => return Err(format!("expected EmptyIdentifier, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_case_id_bounds() -> TestResult {
    let mut rec = sample_record();

    // At bound
    rec.case_id = "c".repeat(MAX_TEST_CASE_ID_LEN);
    assert!(rec.validate().is_ok());

    // At bound + 1
    rec.case_id = "c".repeat(MAX_TEST_CASE_ID_LEN + 1);
    match rec.validate() {
        Err(TestEventError::CaseIdTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_CASE_ID_LEN);
            assert_eq!(actual, MAX_TEST_CASE_ID_LEN + 1);
        }
        other => return Err(format!("expected CaseIdTooLong, got {other:?}").into()),
    }

    // Empty
    rec.case_id.clear();
    match rec.validate() {
        Err(TestEventError::EmptyIdentifier("case_id")) => {}
        other => return Err(format!("expected EmptyIdentifier, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_step_id_bounds() -> TestResult {
    let mut rec = sample_record();

    // At bound
    rec.step_id = "s".repeat(MAX_TEST_STEP_ID_LEN);
    assert!(rec.validate().is_ok());

    // At bound + 1
    rec.step_id = "s".repeat(MAX_TEST_STEP_ID_LEN + 1);
    match rec.validate() {
        Err(TestEventError::StepIdTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_STEP_ID_LEN);
            assert_eq!(actual, MAX_TEST_STEP_ID_LEN + 1);
        }
        other => return Err(format!("expected StepIdTooLong, got {other:?}").into()),
    }

    // Empty
    rec.step_id.clear();
    match rec.validate() {
        Err(TestEventError::EmptyIdentifier("step_id")) => {}
        other => return Err(format!("expected EmptyIdentifier, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_phase_bounds() -> TestResult {
    let mut rec = sample_record();

    // At bound
    rec.phase = Some("p".repeat(MAX_TEST_PHASE_LEN));
    assert!(rec.validate().is_ok());

    // At bound + 1
    rec.phase = Some("p".repeat(MAX_TEST_PHASE_LEN + 1));
    match rec.validate() {
        Err(TestEventError::PhaseTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_PHASE_LEN);
            assert_eq!(actual, MAX_TEST_PHASE_LEN + 1);
        }
        other => return Err(format!("expected PhaseTooLong, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_detail_bounds() -> TestResult {
    let mut rec = sample_record();

    // At bound
    rec.detail = Some("d".repeat(MAX_TEST_DETAIL_LEN));
    assert!(rec.validate().is_ok());

    // At bound + 1
    rec.detail = Some("d".repeat(MAX_TEST_DETAIL_LEN + 1));
    match rec.validate() {
        Err(TestEventError::DetailTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_DETAIL_LEN);
            assert_eq!(actual, MAX_TEST_DETAIL_LEN + 1);
        }
        other => return Err(format!("expected DetailTooLong, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_tag_and_tags_count_bounds() -> TestResult {
    let mut rec = sample_record();

    // Tag at bound
    rec.tags = vec!["t".repeat(MAX_TEST_TAG_LEN)];
    assert!(rec.validate().is_ok());

    // Tag at bound + 1
    rec.tags = vec!["t".repeat(MAX_TEST_TAG_LEN + 1)];
    match rec.validate() {
        Err(TestEventError::TagTooLong { max, actual }) => {
            assert_eq!(max, MAX_TEST_TAG_LEN);
            assert_eq!(actual, MAX_TEST_TAG_LEN + 1);
        }
        other => return Err(format!("expected TagTooLong, got {other:?}").into()),
    }

    // Tags count at bound
    rec.tags = (0..MAX_TEST_TAGS_COUNT)
        .map(|i| format!("tag_{i}"))
        .collect();
    assert!(rec.validate().is_ok());

    // Tags count at bound + 1
    rec.tags = (0..MAX_TEST_TAGS_COUNT + 1)
        .map(|i| format!("tag_{i}"))
        .collect();
    match rec.validate() {
        Err(TestEventError::TagsCountExceeded { max, actual }) => {
            assert_eq!(max, MAX_TEST_TAGS_COUNT);
            assert_eq!(actual, MAX_TEST_TAGS_COUNT + 1);
        }
        other => return Err(format!("expected TagsCountExceeded, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_secret_detection() -> TestResult {
    let sensitive_patterns = [
        "Bearer eyJhbGciOi...",
        "auth_token: xyz123",
        "access_token=secret",
        "private_key: -----BEGIN...",
        "password=supersecret",
    ];

    for secret in sensitive_patterns {
        let mut rec = sample_record();
        rec.detail = Some(format!("failed with error: {secret}"));
        match rec.validate() {
            Err(TestEventError::SecretDetected { field }) => {
                assert_eq!(field, "detail");
            }
            other => return Err(format!("expected SecretDetected, got {other:?}").into()),
        }

        let mut rec2 = sample_record();
        rec2.phase = Some(secret.to_string());
        match rec2.validate() {
            Err(TestEventError::SecretDetected { field }) => {
                assert_eq!(field, "phase");
            }
            other => return Err(format!("expected SecretDetected, got {other:?}").into()),
        }

        let mut rec3 = sample_record();
        rec3.tags = vec![secret.to_string()];
        match rec3.validate() {
            Err(TestEventError::SecretDetected { field }) => {
                assert_eq!(field, "tags");
            }
            other => return Err(format!("expected SecretDetected, got {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn test_collector_monotone_sequence() -> TestResult {
    let mut collector = TestEventCollector::new();
    assert_eq!(collector.records().len(), 0);

    let mut r1 = sample_record();
    r1.sequence = 10;
    collector.push(r1)?;
    assert_eq!(collector.records().len(), 1);

    // Monotone forward
    let mut r2 = sample_record();
    r2.sequence = 11;
    collector.push(r2)?;
    assert_eq!(collector.records().len(), 2);

    // Regression fails
    let mut r_regress = sample_record();
    r_regress.sequence = 11;
    match collector.push(r_regress) {
        Err(TestEventError::SequenceRegression {
            expected_at_least,
            actual,
        }) => {
            assert_eq!(expected_at_least, 12);
            assert_eq!(actual, 11);
        }
        other => return Err(format!("expected SequenceRegression, got {other:?}").into()),
    }

    // Write to buffer
    let mut buf = Vec::new();
    collector.write_jsonl(&mut buf)?;
    assert!(!buf.is_empty());

    let lines: Vec<&str> = std::str::from_utf8(&buf)?.lines().collect();
    assert_eq!(lines.len(), 2);
    Ok(())
}

#[test]
fn test_json_size_bound() -> TestResult {
    let rec = sample_record();
    // Normal size well under MAX_TEST_EVENT_JSON_BYTES
    let jsonl = rec.to_jsonl()?;
    assert!(jsonl.len() < MAX_TEST_EVENT_JSON_BYTES);

    // Test from_json_str with oversized string
    let huge_input = format!(
        "{{\"schema\":\"test_event.v1\", \"padding\":\"{}\"}}",
        "x".repeat(MAX_TEST_EVENT_JSON_BYTES + 1)
    );
    match TestEventRecord::from_json_str(&huge_input) {
        Err(TestEventError::JsonSizeExceeded { max, actual }) => {
            assert_eq!(max, MAX_TEST_EVENT_JSON_BYTES);
            assert!(actual > max);
        }
        other => return Err(format!("expected JsonSizeExceeded, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_malformed_json_rejections() -> TestResult {
    // Missing required field
    let missing_field = "{\"schema\":\"test_event.v1\",\"version\":1}";
    match TestEventRecord::from_json_str(missing_field) {
        Err(TestEventError::MissingField(_)) => {}
        other => return Err(format!("expected MissingField, got {other:?}").into()),
    }

    // Schema mismatch
    let bad_schema = "{\"schema\":\"fss.unknown.v1\",\"version\":1}";
    match TestEventRecord::from_json_str(bad_schema) {
        Err(TestEventError::SchemaMismatch { .. }) => {}
        other => return Err(format!("expected SchemaMismatch, got {other:?}").into()),
    }

    // Not an object
    let not_obj = "\"just a string\"";
    match TestEventRecord::from_json_str(not_obj) {
        Err(TestEventError::MalformedJson(_)) => {}
        other => return Err(format!("expected MalformedJson, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_json_utf8_unescaping_corruption() -> TestResult {
    let mut rec = sample_record();
    rec.detail = Some("Measurement: 42 µm at café sensor".to_string());
    let jsonl = rec.to_jsonl()?;
    let parsed = TestEventRecord::from_json_str(&jsonl)?;
    assert_eq!(
        parsed.detail.as_deref(),
        Some("Measurement: 42 µm at café sensor"),
        "UTF-8 characters must not be corrupted into Mojibake upon unescaping"
    );
    Ok(())
}

#[test]
fn test_pem_private_key_leak_rejected() {
    let mut rec = sample_record();
    rec.detail = Some(
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ..."
            .to_string(),
    );
    assert!(matches!(
        rec.validate(),
        Err(TestEventError::SecretDetected { field: "detail" })
    ));
}

#[test]
fn test_unredacted_media_leak_rejected() {
    let mut rec = sample_record();
    rec.detail = Some("captured: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...".to_string());
    assert!(matches!(
        rec.validate(),
        Err(TestEventError::SecretDetected { field: "detail" })
    ));
}

#[test]
fn test_collector_rejects_duplicate_u64_max_sequence() -> TestResult {
    let mut collector = TestEventCollector::new();
    let mut r1 = sample_record();
    r1.sequence = u64::MAX;
    collector.push(r1.clone())?;
    let r2 = r1;
    let err = collector.push(r2);
    assert!(
        matches!(err, Err(TestEventError::SequenceRegression { .. })),
        "pushing record with sequence u64::MAX twice must fail with SequenceRegression"
    );
    Ok(())
}

#[test]
fn test_collector_capacity_bound() -> TestResult {
    let mut collector = TestEventCollector::new();
    for seq in 0..MAX_TEST_EVENTS_COUNT as u64 {
        let mut rec = sample_record();
        rec.sequence = seq;
        collector.push(rec)?;
    }
    assert_eq!(collector.records().len(), MAX_TEST_EVENTS_COUNT);

    let mut over_bound = sample_record();
    over_bound.sequence = MAX_TEST_EVENTS_COUNT as u64;
    let err = collector.push(over_bound);
    assert!(
        matches!(err, Err(TestEventError::CollectorCapacityExceeded { max, actual }) if max == MAX_TEST_EVENTS_COUNT && actual == MAX_TEST_EVENTS_COUNT + 1),
        "pushing past MAX_TEST_EVENTS_COUNT must return CollectorCapacityExceeded"
    );
    Ok(())
}
