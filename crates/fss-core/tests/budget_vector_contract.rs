//! Contract tests for BudgetVector finite nonnegative validation, checked arithmetic,
//! canonical encoding, schema decode boundaries, and redacted structured logging.
//!
//! Ref: fss-x4a.8.13 / BUDGET-FLOAT-VALIDATION-001

#![forbid(unsafe_code)]

use fss_core::{
    BudgetDimension, BudgetError, BudgetLogRecord, BudgetQuantity, BudgetVector,
    BudgetVectorBuilder, CanonicalDecode, CanonicalEncode, ContractError,
};

// ---------------------------------------------------------------------------
// 1. Unit Tests: Construction and Boundary Values
// ---------------------------------------------------------------------------

#[test]
fn zero_budget_is_valid_and_fits_within_itself() {
    let zero = BudgetVector::ZERO;
    assert!(zero.is_valid());
    assert!(zero.validate().is_ok());
    assert_eq!(zero, BudgetVector::default());
    assert!(zero.fits_within(zero));
    assert_eq!(zero.checked_fits_within(&zero), Ok(true));
    assert_eq!(zero.latency_ms, 0);
    assert_eq!(zero.tokens, 0);
    assert_eq!(zero.privacy_exposure, 0.0);
    assert_eq!(zero.operator_attention_seconds, 0.0);
}

#[test]
fn ordinary_valid_budget_construction_via_new_and_builder() -> Result<(), BudgetError> {
    let budget = BudgetVector::new(100, 200, 1024, 2, 50, 10, 15, 512, 5, 0.5, 1.25)?;
    assert!(budget.is_valid());
    assert_eq!(budget.latency_ms, 100);
    assert_eq!(budget.tokens, 200);
    assert_eq!(budget.bytes, 1024);
    assert_eq!(budget.model_calls, 2);
    assert_eq!(budget.cpu_millis, 50);
    assert_eq!(budget.accelerator_millis, 10);
    assert_eq!(budget.energy_millijoules, 15);
    assert_eq!(budget.network_bytes, 512);
    assert_eq!(budget.storage_operations, 5);
    assert_eq!(budget.privacy_exposure, 0.5);
    assert_eq!(budget.operator_attention_seconds, 1.25);

    // Same via builder
    let built = BudgetVectorBuilder::default()
        .latency_ms(100)
        .tokens(200)
        .bytes(1024)
        .model_calls(2)
        .cpu_millis(50)
        .accelerator_millis(10)
        .energy_millijoules(15)
        .network_bytes(512)
        .storage_operations(5)
        .privacy_exposure(0.5)
        .operator_attention_seconds(1.25)
        .build()?;
    assert_eq!(budget, built);
    Ok(())
}

#[test]
fn rejects_negative_floating_quantities_with_typed_error() {
    // Negative privacy_exposure
    let res = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, -0.001, 1.0);
    match res {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected NegativeQuantity for negative privacy_exposure"),
    }

    // Negative operator_attention_seconds
    let res2 = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 1.0, -100.0);
    match res2 {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::OperatorAttentionSeconds);
        }
        _ => panic!("expected NegativeQuantity for negative operator_attention_seconds"),
    }
}

#[test]
fn rejects_nan_floating_quantities_with_typed_error() {
    // Standard NaN
    let res = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, f64::NAN, 1.0);
    assert_eq!(
        res,
        Err(BudgetError::NaNQuantity {
            dimension: BudgetDimension::PrivacyExposure,
        })
    );

    // NaN payload variant
    let nan_payload = f64::from_bits(0x7ff8_0000_0000_0001);
    let res2 = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 1.0, nan_payload);
    assert_eq!(
        res2,
        Err(BudgetError::NaNQuantity {
            dimension: BudgetDimension::OperatorAttentionSeconds,
        })
    );
}

#[test]
fn rejects_both_infinities_with_typed_error() {
    // Positive infinity
    let res_pos = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, f64::INFINITY, 0.0);
    assert_eq!(
        res_pos,
        Err(BudgetError::InfiniteQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            is_negative: false,
        })
    );

    // Negative infinity
    let res_neg = BudgetVector::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, f64::NEG_INFINITY);
    assert_eq!(
        res_neg,
        Err(BudgetError::InfiniteQuantity {
            dimension: BudgetDimension::OperatorAttentionSeconds,
            is_negative: true,
        })
    );
}

#[test]
fn normalizes_negative_zero_deterministically() -> Result<(), BudgetError> {
    let neg_zero = -0.0f64;
    let pos_zero = 0.0f64;

    let v_neg = BudgetVector::new(10, 0, 0, 0, 0, 0, 0, 0, 0, neg_zero, neg_zero)?;
    let v_pos = BudgetVector::new(10, 0, 0, 0, 0, 0, 0, 0, 0, pos_zero, pos_zero)?;

    // Both normalize to +0.0 bits
    assert_eq!(v_neg.privacy_exposure.to_bits(), 0);
    assert_eq!(v_neg.operator_attention_seconds.to_bits(), 0);
    assert_eq!(v_pos.privacy_exposure.to_bits(), 0);
    assert_eq!(v_pos.operator_attention_seconds.to_bits(), 0);

    // Canonical bytes and digests are bit-for-bit identical
    let bytes_neg = v_neg.canonical_bytes();
    let bytes_pos = v_pos.canonical_bytes();
    assert_eq!(bytes_neg, bytes_pos);

    let digest_neg = v_neg.canonical_digest("test.budget");
    let digest_pos = v_pos.canonical_digest("test.budget");
    assert_eq!(digest_neg, digest_pos);
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Checked Arithmetic: Addition, Subtraction, Consumption, Reservation
// ---------------------------------------------------------------------------

#[test]
fn checked_add_succeeds_and_detects_overflow() -> Result<(), BudgetError> {
    let v1 = BudgetVector::builder()
        .latency_ms(100)
        .tokens(50)
        .privacy_exposure(1.5)
        .build()?;
    let v2 = BudgetVector::builder()
        .latency_ms(200)
        .tokens(150)
        .privacy_exposure(2.5)
        .build()?;

    let s = v1.checked_add(&v2)?;
    assert_eq!(s.latency_ms, 300);
    assert_eq!(s.tokens, 200);
    assert_eq!(s.privacy_exposure, 4.0);

    // Integer overflow detection
    let v_max = BudgetVector::builder().latency_ms(u64::MAX).build()?;
    let v_one = BudgetVector::builder().latency_ms(1).build()?;
    let overflow = v_max.checked_add(&v_one);
    assert_eq!(
        overflow,
        Err(BudgetError::Overflow {
            dimension: BudgetDimension::LatencyMs,
            operation: "add",
        })
    );

    // Float overflow detection
    let v_huge = BudgetVector::builder().privacy_exposure(f64::MAX).build()?;
    let float_overflow = v_huge.checked_add(&v_huge);
    assert_eq!(
        float_overflow,
        Err(BudgetError::Overflow {
            dimension: BudgetDimension::PrivacyExposure,
            operation: "add",
        })
    );
    Ok(())
}

#[test]
fn checked_sub_succeeds_and_detects_underflow() -> Result<(), BudgetError> {
    let v1 = BudgetVector::builder()
        .latency_ms(300)
        .tokens(200)
        .privacy_exposure(5.0)
        .build()?;
    let v2 = BudgetVector::builder()
        .latency_ms(100)
        .tokens(50)
        .privacy_exposure(2.0)
        .build()?;

    let d = v1.checked_sub(&v2)?;
    assert_eq!(d.latency_ms, 200);
    assert_eq!(d.tokens, 150);
    assert_eq!(d.privacy_exposure, 3.0);

    // Underflow on latency
    let underflow = v2.checked_sub(&v1);
    match underflow {
        Err(BudgetError::Underflow { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::LatencyMs);
        }
        _ => panic!("expected Underflow error on LatencyMs"),
    }

    // Underflow on privacy exposure
    let v_priv1 = BudgetVector::builder().privacy_exposure(1.0).build()?;
    let v_priv2 = BudgetVector::builder().privacy_exposure(2.0).build()?;
    match v_priv1.checked_sub(&v_priv2) {
        Err(BudgetError::Underflow { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected Underflow error on PrivacyExposure"),
    }
    Ok(())
}

#[test]
fn monotone_consumption_cannot_increase_remaining_authority() -> Result<(), BudgetError> {
    let avail = BudgetVector::builder()
        .latency_ms(1000)
        .tokens(500)
        .bytes(64 * 1024)
        .privacy_exposure(2.0)
        .operator_attention_seconds(10.0)
        .build()?;

    let c = BudgetVector::builder()
        .latency_ms(200)
        .tokens(100)
        .privacy_exposure(0.5)
        .build()?;

    let rem = avail.checked_consume(&c)?;

    // Invariant: remaining fits within available
    assert!(rem.fits_within(avail));
    assert_eq!(rem.latency_ms, 800);
    assert_eq!(rem.tokens, 400);
    assert_eq!(rem.privacy_exposure, 1.5);

    // Overconsumption fails
    let ec = BudgetVector::builder().latency_ms(2000).build()?;
    assert!(avail.checked_consume(&ec).is_err());
    Ok(())
}

#[test]
fn checked_reservation_and_release_cycle() -> Result<(), BudgetError> {
    let avail = BudgetVector::builder()
        .latency_ms(1000)
        .tokens(500)
        .build()?;

    let req = BudgetVector::builder()
        .latency_ms(300)
        .tokens(100)
        .build()?;

    let (rem_avail, reserved) = avail.checked_reserve(&req)?;
    assert_eq!(rem_avail.latency_ms, 700);
    assert_eq!(rem_avail.tokens, 400);
    assert_eq!(reserved.latency_ms, 300);
    assert_eq!(reserved.tokens, 100);

    // Release 100 ms and 50 tokens
    let rel = BudgetVector::builder().latency_ms(100).tokens(50).build()?;

    let (new_avail, new_res) = rem_avail.checked_release(&reserved, &rel)?;
    assert_eq!(new_avail.latency_ms, 800);
    assert_eq!(new_avail.tokens, 450);
    assert_eq!(new_res.latency_ms, 200);
    assert_eq!(new_res.tokens, 50);
    Ok(())
}

#[test]
fn authority_enlargement_is_forbidden() -> Result<(), BudgetError> {
    let prior = BudgetVector::builder()
        .latency_ms(500)
        .tokens(250)
        .privacy_exposure(1.0)
        .build()?;

    // Equal or smaller budget passes authority check
    let sub = BudgetVector::builder()
        .latency_ms(400)
        .tokens(200)
        .privacy_exposure(0.8)
        .build()?;
    assert_eq!(sub.assert_authority_unmodified(&prior), Ok(()));

    // Enlarged budget fails authority check on LatencyMs
    let enl_latency = BudgetVector::builder()
        .latency_ms(600)
        .tokens(200)
        .privacy_exposure(0.8)
        .build()?;
    assert_eq!(
        enl_latency.assert_authority_unmodified(&prior),
        Err(BudgetError::AuthorityEnlargementForbidden {
            dimension: BudgetDimension::LatencyMs,
        })
    );

    // Enlarged budget fails authority check on Tokens
    let enl_tokens = BudgetVector::builder()
        .latency_ms(500)
        .tokens(300)
        .privacy_exposure(0.8)
        .build()?;
    assert_eq!(
        enl_tokens.assert_authority_unmodified(&prior),
        Err(BudgetError::AuthorityEnlargementForbidden {
            dimension: BudgetDimension::Tokens,
        })
    );

    // Enlarged budget fails authority check on PrivacyExposure
    let enl_privacy = BudgetVector::builder()
        .latency_ms(500)
        .tokens(250)
        .privacy_exposure(1.5)
        .build()?;
    assert_eq!(
        enl_privacy.assert_authority_unmodified(&prior),
        Err(BudgetError::AuthorityEnlargementForbidden {
            dimension: BudgetDimension::PrivacyExposure,
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Encapsulated BudgetQuantity Invariants and Total Ordering
// ---------------------------------------------------------------------------

#[test]
fn budget_quantity_invariants_and_ordering() -> Result<(), BudgetError> {
    let v0 = BudgetQuantity::new(0.0, BudgetDimension::PrivacyExposure)?;
    let v1 = BudgetQuantity::new(1.0, BudgetDimension::PrivacyExposure)?;
    let v2 = BudgetQuantity::new(2.5, BudgetDimension::PrivacyExposure)?;

    // Total order
    assert!(v0 < v1);
    assert!(v1 < v2);
    assert!(v0 < v2);
    assert_eq!(v0, BudgetQuantity::ZERO);
    assert_eq!(Ord::cmp(&v1, &v2), core::cmp::Ordering::Less);
    assert_eq!(Ord::cmp(&v2, &v1), core::cmp::Ordering::Greater);
    assert_eq!(Ord::cmp(&v1, &v1), core::cmp::Ordering::Equal);

    // Rejects invalid
    assert!(BudgetQuantity::new(-0.1, BudgetDimension::PrivacyExposure).is_err());
    assert!(BudgetQuantity::new(f64::NAN, BudgetDimension::PrivacyExposure).is_err());
    assert!(BudgetQuantity::new(f64::INFINITY, BudgetDimension::PrivacyExposure).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Canonical Binary Encode / Decode Round-Trip and Quarantine
// ---------------------------------------------------------------------------

#[test]
fn canonical_encode_decode_round_trip() -> Result<(), BudgetError> {
    let orig = BudgetVector::new(1234, 5678, 9012, 42, 100, 200, 300, 400, 500, 1.75, 4.5)?;

    let canonical_bytes = orig.canonical_bytes();
    assert_eq!(canonical_bytes.len(), 84);

    let decoded = BudgetVector::decode_canonical(&canonical_bytes)?;
    assert_eq!(decoded, orig);

    // Trait decode round-trip via ContractError
    let trait_decoded = BudgetVector::from_canonical_bytes(&canonical_bytes);
    assert_eq!(trait_decoded, Ok(orig));
    Ok(())
}

#[test]
fn canonical_decode_rejects_malformed_and_faulty_bytes() {
    // Truncated buffer (< 84 bytes)
    let short = [0u8; 80];
    assert_eq!(
        BudgetVector::decode_canonical(&short),
        Err(BudgetError::InvalidEncoding {
            reason: "canonical budget encoding must be exactly 84 bytes",
        })
    );

    // Corrupt NaN float injected at privacy_exposure slot (offset 68..76)
    let mut corrupt_nan = [0u8; 84];
    corrupt_nan[68..76].copy_from_slice(&0x7ff8_0000_0000_0000u64.to_be_bytes());
    assert_eq!(
        BudgetVector::decode_canonical(&corrupt_nan),
        Err(BudgetError::NaNQuantity {
            dimension: BudgetDimension::PrivacyExposure,
        })
    );

    // Corrupt negative float injected at operator_attention slot (offset 76..84)
    let mut corrupt_neg = [0u8; 84];
    corrupt_neg[76..84].copy_from_slice(&(-5.0f64).to_bits().to_be_bytes());
    match BudgetVector::decode_canonical(&corrupt_neg) {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::OperatorAttentionSeconds);
        }
        _ => panic!("expected NegativeQuantity for negative operator attention"),
    }
}

#[test]
fn historical_quarantine_produces_explicit_quarantine_record() {
    let corrupt_bytes = [0xFFu8; 84]; // Invariant violation: bits represent negative NaN
    let res = BudgetVector::quarantine_historical(&corrupt_bytes, "rec-hist-0042");
    match res {
        Err(
            ref err @ BudgetError::QuarantinedRecord {
                ref record_id,
                ref reason,
            },
        ) => {
            assert_eq!(record_id, "rec-hist-0042");
            assert!(reason.contains("historical budget validation failed"));
            assert_eq!(err.code(), "quarantined_budget_record");
        }
        _ => panic!("expected QuarantinedRecord error"),
    }
}

// ---------------------------------------------------------------------------
// 5. Untrusted JSON Decode Boundary Validation
// ---------------------------------------------------------------------------

#[test]
fn json_decode_valid_camel_case_and_snake_case() -> Result<(), BudgetError> {
    let json_camel = br#"{
        "latencyMs": 150,
        "tokens": 300,
        "bytes": 2048,
        "modelCalls": 4,
        "cpuMillis": 80,
        "acceleratorMillis": 20,
        "energyMillijoules": 40,
        "networkBytes": 1024,
        "storageOperations": 8,
        "privacyExposure": 0.25,
        "operatorAttentionSeconds": 2.5
    }"#;

    let budget = BudgetVector::decode_json_slice(json_camel)?;
    assert_eq!(budget.latency_ms, 150);
    assert_eq!(budget.tokens, 300);
    assert_eq!(budget.privacy_exposure, 0.25);
    assert_eq!(budget.operator_attention_seconds, 2.5);

    let json_snake = br#"{
        "latency_ms": 100,
        "tokens": 50,
        "privacy_exposure": 0.1
    }"#;
    let s = BudgetVector::decode_json_slice(json_snake)?;
    assert_eq!(s.latency_ms, 100);
    assert_eq!(s.tokens, 50);
    assert_eq!(s.privacy_exposure, 0.1);
    Ok(())
}

#[test]
fn json_decode_rejects_negative_nan_and_infinities() {
    // Negative integer in JSON
    let json_neg_int = br#"{"latencyMs": -50}"#;
    match BudgetVector::decode_json_slice(json_neg_int) {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::LatencyMs);
        }
        _ => panic!("expected NegativeQuantity for negative integer in JSON"),
    }

    // Negative float in JSON
    let json_neg_float = br#"{"privacyExposure": -1.5}"#;
    match BudgetVector::decode_json_slice(json_neg_float) {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected NegativeQuantity for negative float in JSON"),
    }

    // NaN string in JSON
    let json_nan = br#"{"operatorAttentionSeconds": "NaN"}"#;
    match BudgetVector::decode_json_slice(json_nan) {
        Err(BudgetError::NaNQuantity { dimension }) => {
            assert_eq!(dimension, BudgetDimension::OperatorAttentionSeconds);
        }
        _ => panic!("expected NaNQuantity for NaN in JSON"),
    }

    // Infinity in JSON
    let json_inf = br#"{"privacyExposure": "Infinity"}"#;
    match BudgetVector::decode_json_slice(json_inf) {
        Err(BudgetError::InfiniteQuantity {
            dimension,
            is_negative,
        }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
            assert!(!is_negative);
        }
        _ => panic!("expected InfiniteQuantity for Infinity in JSON"),
    }

    // Negative Infinity in JSON
    let json_neg_inf = br#"{"privacyExposure": "-Infinity"}"#;
    match BudgetVector::decode_json_slice(json_neg_inf) {
        Err(BudgetError::InfiniteQuantity {
            dimension,
            is_negative,
        }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
            assert!(is_negative);
        }
        _ => panic!("expected InfiniteQuantity (negative) in JSON"),
    }

    // Exponential overflow to infinity (1e999)
    let json_overflow = br#"{"privacyExposure": 1e999}"#;
    match BudgetVector::decode_json_slice(json_overflow) {
        Err(BudgetError::InfiniteQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected InfiniteQuantity for exponential overflow in JSON"),
    }

    // Malformed JSON not an object
    let json_array = br#"[100, 200]"#;
    assert_eq!(
        BudgetVector::decode_json_slice(json_array),
        Err(BudgetError::InvalidEncoding {
            reason: "JSON budget must be an object enclosed in braces",
        })
    );

    // Unknown dimension in JSON
    let json_unknown = br#"{"unknownBudgetDimension": 100}"#;
    assert_eq!(
        BudgetVector::decode_json_slice(json_unknown),
        Err(BudgetError::InvalidEncoding {
            reason: "unknown budget dimension in JSON",
        })
    );
}

#[test]
fn checked_fits_within_rejects_invalid_operands() {
    let valid = BudgetVector::ZERO;
    let mut invalid = BudgetVector::ZERO;
    invalid.privacy_exposure = -1.0;

    // Invalid self
    match invalid.checked_fits_within(&valid) {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected NegativeQuantity for invalid self in checked_fits_within"),
    }

    // Invalid limit
    match valid.checked_fits_within(&invalid) {
        Err(BudgetError::NegativeQuantity { dimension, .. }) => {
            assert_eq!(dimension, BudgetDimension::PrivacyExposure);
        }
        _ => panic!("expected NegativeQuantity for invalid limit in checked_fits_within"),
    }
}

#[test]
fn project_dimensions_preserves_selected_and_zeroes_others() -> Result<(), BudgetError> {
    let b = BudgetVector::builder()
        .latency_ms(100)
        .tokens(200)
        .privacy_exposure(1.5)
        .build()?;

    let proj = b.project_dimensions(|d| d == BudgetDimension::PrivacyExposure)?;
    assert_eq!(proj.latency_ms, 0);
    assert_eq!(proj.tokens, 0);
    assert_eq!(proj.privacy_exposure, 1.5);
    assert!(proj.fits_within(b));
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Differential / Reference Model Comparison Tests
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
struct ReferenceBudget {
    latency_ms: u64,
    tokens: u64,
    bytes: u64,
    model_calls: u32,
    cpu_millis: u64,
    accelerator_millis: u64,
    energy_millijoules: u64,
    network_bytes: u64,
    storage_operations: u64,
    privacy_exposure: f64,
    operator_attention_seconds: f64,
}

impl ReferenceBudget {
    fn is_valid(&self) -> bool {
        self.privacy_exposure.is_finite()
            && self.privacy_exposure >= 0.0
            && self.operator_attention_seconds.is_finite()
            && self.operator_attention_seconds >= 0.0
    }

    fn fits_within(&self, limit: &Self) -> bool {
        self.is_valid()
            && limit.is_valid()
            && self.latency_ms <= limit.latency_ms
            && self.tokens <= limit.tokens
            && self.bytes <= limit.bytes
            && self.model_calls <= limit.model_calls
            && self.cpu_millis <= limit.cpu_millis
            && self.accelerator_millis <= limit.accelerator_millis
            && self.energy_millijoules <= limit.energy_millijoules
            && self.network_bytes <= limit.network_bytes
            && self.storage_operations <= limit.storage_operations
            && self.privacy_exposure <= limit.privacy_exposure
            && self.operator_attention_seconds <= limit.operator_attention_seconds
    }
}

#[test]
fn differential_conformance_with_reference_model() -> Result<(), BudgetError> {
    let test_matrix = [
        (0u64, 0.0f64, 0.0f64, true),
        (100, 1.0, 1.0, true),
        (500, 0.0001, 100.0, true),
        (1000, -0.0, 0.0, true),
        (100, -0.1, 1.0, false),
        (100, 1.0, -1.0, false),
        (100, f64::NAN, 1.0, false),
        (100, 1.0, f64::INFINITY, false),
        (100, f64::NEG_INFINITY, 1.0, false),
    ];

    for (lat, priv_exp, att_sec, should_be_valid) in test_matrix {
        let ref_model = ReferenceBudget {
            latency_ms: lat,
            tokens: 100,
            bytes: 1024,
            model_calls: 1,
            cpu_millis: 10,
            accelerator_millis: 5,
            energy_millijoules: 10,
            network_bytes: 512,
            storage_operations: 1,
            privacy_exposure: priv_exp,
            operator_attention_seconds: att_sec,
        };
        assert_eq!(ref_model.is_valid(), should_be_valid);

        let opt_vec = BudgetVector {
            latency_ms: lat,
            tokens: 100,
            bytes: 1024,
            model_calls: 1,
            cpu_millis: 10,
            accelerator_millis: 5,
            energy_millijoules: 10,
            network_bytes: 512,
            storage_operations: 1,
            privacy_exposure: priv_exp,
            operator_attention_seconds: att_sec,
        };
        assert_eq!(opt_vec.is_valid(), should_be_valid);
        assert_eq!(opt_vec.validate().is_ok(), should_be_valid);

        if should_be_valid {
            let constructor_result =
                BudgetVector::new(lat, 100, 1024, 1, 10, 5, 10, 512, 1, priv_exp, att_sec);
            assert!(constructor_result.is_ok());

            let lim = BudgetVector::builder()
                .latency_ms(2000)
                .tokens(200)
                .bytes(2048)
                .model_calls(2)
                .cpu_millis(20)
                .accelerator_millis(10)
                .energy_millijoules(20)
                .network_bytes(1024)
                .storage_operations(2)
                .privacy_exposure(100.0)
                .operator_attention_seconds(200.0)
                .build()?;

            let ref_limit = ReferenceBudget {
                latency_ms: 2000,
                tokens: 200,
                bytes: 2048,
                model_calls: 2,
                cpu_millis: 20,
                accelerator_millis: 10,
                energy_millijoules: 20,
                network_bytes: 1024,
                storage_operations: 2,
                privacy_exposure: 100.0,
                operator_attention_seconds: 200.0,
            };

            assert_eq!(opt_vec.fits_within(lim), ref_model.fits_within(&ref_limit));
        } else {
            let constructor_result =
                BudgetVector::new(lat, 100, 1024, 1, 10, 5, 10, 512, 1, priv_exp, att_sec);
            assert!(constructor_result.is_err());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Structured Redacted Logging & Proof Verification
// ---------------------------------------------------------------------------

#[test]
fn structured_redacted_logging_does_not_leak_secrets() {
    let err = BudgetError::negative_quantity(BudgetDimension::PrivacyExposure, -0.75);
    let log_record = BudgetLogRecord::validation_failure("req-corr-12345", "decode", &err);
    let jsonl = log_record.to_jsonl();

    assert!(jsonl.contains("\"schema\":\"budget_log_record.v1\""));
    assert!(jsonl.contains("\"eventId\":\"budget.validation_failure\""));
    assert!(jsonl.contains("\"stage\":\"decode\""));
    assert!(jsonl.contains("\"correlationId\":\"req-corr-12345\""));
    assert!(jsonl.contains("\"dimension\":\"privacy_exposure\""));
    assert!(jsonl.contains("\"errorCode\":\"negative_budget_quantity\""));

    // Ensure forbidden sensitive substrings NEVER appear
    let forbidden = [
        "password",
        "secret",
        "bearer",
        "prompt",
        "token_secret",
        "raw_payload",
    ];
    for keyword in forbidden {
        assert!(!jsonl.to_lowercase().contains(keyword));
    }

    // Success transition logging
    let success_record = BudgetLogRecord::transition_success(
        "req-corr-12345",
        "consumption",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
    );
    let success_jsonl = success_record.to_jsonl();
    assert!(success_jsonl.contains("\"eventId\":\"budget.transition\""));
    assert!(success_jsonl.contains("\"beforeDigest\":\"sha256:1111"));
    assert!(success_jsonl.contains("\"afterDigest\":\"sha256:2222"));
}

// ---------------------------------------------------------------------------
// 8. ContractError Interoperability
// ---------------------------------------------------------------------------

#[test]
fn budget_error_converts_to_contract_error_with_stable_code() {
    let b_err = BudgetError::NaNQuantity {
        dimension: BudgetDimension::PrivacyExposure,
    };
    let c_err: ContractError = b_err.into();
    assert_eq!(c_err.code(), "nan_budget_quantity");
    assert_eq!(format!("{c_err}"), "nan_budget_quantity");
}
