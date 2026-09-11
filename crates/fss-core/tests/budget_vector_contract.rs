//! Contract tests for BudgetVector finite nonnegative validation, checked arithmetic,
//! canonical encoding, schema decode boundaries, and redacted structured logging.
//!
//! Ref: fss-x4a.8.13 / BUDGET-FLOAT-VALIDATION-001

#![forbid(unsafe_code)]

use fss_core::{
    BudgetDimension, BudgetError, BudgetLogRecord, BudgetQuantitiesSpec, BudgetQuantity,
    BudgetVector, BudgetVectorBuilder, BudgetVectorSpec, CanonicalDecode, CanonicalEncode,
    CanonicalEncoder, ContractError,
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
    assert_eq!(zero.privacy_exposure(), 0.0);
    assert_eq!(zero.operator_attention_seconds(), 0.0);
}

#[test]
fn ordinary_valid_budget_construction_via_new_and_builder() -> Result<(), BudgetError> {
    let budget = BudgetVector::new(BudgetVectorSpec {
        latency_ms: 100,
        tokens: 200,
        bytes: 1024,
        model_calls: 2,
        cpu_millis: 50,
        accelerator_millis: 10,
        energy_millijoules: 15,
        network_bytes: 512,
        storage_operations: 5,
        privacy_exposure: 0.5,
        operator_attention_seconds: 1.25,
    })?;
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
    assert_eq!(budget.privacy_exposure(), 0.5);
    assert_eq!(budget.operator_attention_seconds(), 1.25);

    // Same via from_quantities
    let quantities_budget = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 100,
        tokens: 200,
        bytes: 1024,
        model_calls: 2,
        cpu_millis: 50,
        accelerator_millis: 10,
        energy_millijoules: 15,
        network_bytes: 512,
        storage_operations: 5,
        privacy_exposure: budget.privacy_quantity()?,
        operator_attention_seconds: budget.operator_attention_quantity()?,
    });
    assert_eq!(budget, quantities_budget);

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
    let res = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: -0.001,
        operator_attention_seconds: 1.0,
        ..Default::default()
    });
    assert!(matches!(
        res,
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            ..
        })
    ));

    // Negative operator_attention_seconds
    let res2 = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: 1.0,
        operator_attention_seconds: -100.0,
        ..Default::default()
    });
    assert!(matches!(
        res2,
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::OperatorAttentionSeconds,
            ..
        })
    ));
}

#[test]
fn rejects_nan_floating_quantities_with_typed_error() {
    // Standard NaN
    let res = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: f64::NAN,
        operator_attention_seconds: 1.0,
        ..Default::default()
    });
    assert_eq!(
        res,
        Err(BudgetError::NaNQuantity {
            dimension: BudgetDimension::PrivacyExposure,
        })
    );

    // NaN payload variant
    let nan_payload = f64::from_bits(0x7ff8_0000_0000_0001);
    let res2 = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: 1.0,
        operator_attention_seconds: nan_payload,
        ..Default::default()
    });
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
    let res_pos = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: f64::INFINITY,
        operator_attention_seconds: 0.0,
        ..Default::default()
    });
    assert_eq!(
        res_pos,
        Err(BudgetError::InfiniteQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            is_negative: false,
        })
    );

    // Negative infinity
    let res_neg = BudgetVector::new(BudgetVectorSpec {
        privacy_exposure: 0.0,
        operator_attention_seconds: f64::NEG_INFINITY,
        ..Default::default()
    });
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

    let v_neg = BudgetVector::new(BudgetVectorSpec {
        latency_ms: 10,
        privacy_exposure: neg_zero,
        operator_attention_seconds: neg_zero,
        ..Default::default()
    })?;
    let v_pos = BudgetVector::new(BudgetVectorSpec {
        latency_ms: 10,
        privacy_exposure: pos_zero,
        operator_attention_seconds: pos_zero,
        ..Default::default()
    })?;

    // Both normalize to +0.0 bits
    assert_eq!(v_neg.privacy_exposure().to_bits(), 0);
    assert_eq!(v_neg.operator_attention_seconds().to_bits(), 0);
    assert_eq!(v_pos.privacy_exposure().to_bits(), 0);
    assert_eq!(v_pos.operator_attention_seconds().to_bits(), 0);

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
    assert_eq!(s.privacy_exposure(), 4.0);

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
    assert_eq!(d.privacy_exposure(), 3.0);

    // Underflow on latency
    let underflow = v2.checked_sub(&v1);
    assert!(matches!(
        underflow,
        Err(BudgetError::Underflow {
            dimension: BudgetDimension::LatencyMs,
            ..
        })
    ));

    // Underflow on privacy exposure
    let v_priv1 = BudgetVector::builder().privacy_exposure(1.0).build()?;
    let v_priv2 = BudgetVector::builder().privacy_exposure(2.0).build()?;
    assert!(matches!(
        v_priv1.checked_sub(&v_priv2),
        Err(BudgetError::Underflow {
            dimension: BudgetDimension::PrivacyExposure,
            ..
        })
    ));
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
    assert_eq!(rem.privacy_exposure(), 1.5);

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
    let orig = BudgetVector::new(BudgetVectorSpec {
        latency_ms: 1234,
        tokens: 5678,
        bytes: 9012,
        model_calls: 42,
        cpu_millis: 100,
        accelerator_millis: 200,
        energy_millijoules: 300,
        network_bytes: 400,
        storage_operations: 500,
        privacy_exposure: 1.75,
        operator_attention_seconds: 4.5,
    })?;

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
    assert!(matches!(
        BudgetVector::decode_canonical(&corrupt_neg),
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::OperatorAttentionSeconds,
            ..
        })
    ));
}

#[test]
fn historical_quarantine_produces_explicit_quarantine_record() {
    let corrupt_bytes = [0xFFu8; 84]; // Invariant violation: bits represent negative NaN
    let res = BudgetVector::quarantine_historical(&corrupt_bytes, "rec-hist-0042");
    if let Err(
        ref err @ BudgetError::QuarantinedRecord {
            ref record_id,
            ref reason,
        },
    ) = res
    {
        assert_eq!(record_id, "rec-hist-0042");
        assert!(reason.contains("historical budget validation failed"));
        assert_eq!(err.code(), "quarantined_budget_record");
    } else {
        assert!(matches!(res, Err(BudgetError::QuarantinedRecord { .. })));
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
    assert_eq!(budget.privacy_exposure(), 0.25);
    assert_eq!(budget.operator_attention_seconds(), 2.5);

    let json_snake = br#"{
        "latency_ms": 100,
        "tokens": 50,
        "privacy_exposure": 0.1
    }"#;
    let s = BudgetVector::decode_json_slice(json_snake)?;
    assert_eq!(s.latency_ms, 100);
    assert_eq!(s.tokens, 50);
    assert_eq!(s.privacy_exposure(), 0.1);
    Ok(())
}

#[test]
fn json_decode_rejects_negative_nan_and_infinities() {
    // Negative integer in JSON
    let json_neg_int = br#"{"latencyMs": -50}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_neg_int),
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::LatencyMs,
            ..
        })
    ));

    // Negative float in JSON
    let json_neg_float = br#"{"privacyExposure": -1.5}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_neg_float),
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            ..
        })
    ));

    // NaN string in JSON
    let json_nan = br#"{"operatorAttentionSeconds": "NaN"}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_nan),
        Err(BudgetError::NaNQuantity {
            dimension: BudgetDimension::OperatorAttentionSeconds,
        })
    ));

    // Infinity in JSON
    let json_inf = br#"{"privacyExposure": "Infinity"}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_inf),
        Err(BudgetError::InfiniteQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            is_negative: false,
        })
    ));

    // Negative Infinity in JSON
    let json_neg_inf = br#"{"privacyExposure": "-Infinity"}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_neg_inf),
        Err(BudgetError::InfiniteQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            is_negative: true,
        })
    ));

    // Exponential overflow to infinity (1e999)
    let json_overflow = br#"{"privacyExposure": 1e999}"#;
    assert!(matches!(
        BudgetVector::decode_json_slice(json_overflow),
        Err(BudgetError::InvalidEncoding { .. })
    ));

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
fn checked_fits_within_contract() -> Result<(), BudgetError> {
    let valid_zero = BudgetVector::ZERO;
    let valid_some = BudgetVector::builder()
        .latency_ms(100)
        .privacy_exposure(1.0)
        .build()?;

    assert_eq!(valid_zero.checked_fits_within(&valid_some), Ok(true));
    assert_eq!(valid_some.checked_fits_within(&valid_zero), Ok(false));

    // Construction of invalid vector fails closed at the boundary
    let invalid_spec = BudgetVectorSpec {
        privacy_exposure: -1.0,
        ..Default::default()
    };
    assert!(matches!(
        BudgetVector::new(invalid_spec),
        Err(BudgetError::NegativeQuantity {
            dimension: BudgetDimension::PrivacyExposure,
            ..
        })
    ));

    Ok(())
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
    assert_eq!(proj.privacy_exposure(), 1.5);
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

        let constructor_result = BudgetVector::new(BudgetVectorSpec {
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
        });
        assert_eq!(constructor_result.is_ok(), should_be_valid);

        if should_be_valid {
            let vec = constructor_result?;
            assert!(vec.is_valid());
            assert!(vec.validate().is_ok());

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

            assert_eq!(vec.fits_within(lim), ref_model.fits_within(&ref_limit));
        } else {
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

// ---------------------------------------------------------------------------
// 9. Cross-Review Findings Regression Tests (DustyChapel Review)
// ---------------------------------------------------------------------------

#[test]
fn json_decoding_rejects_duplicate_keys() {
    let json = br#"{"tokens": 100, "tokens": 200}"#;
    let result = BudgetVector::decode_json_slice(json);
    assert!(matches!(
        result,
        Err(BudgetError::InvalidEncoding { reason }) if reason.contains("duplicate")
    ));
}

#[test]
fn json_decoding_rejects_quoted_numerals_for_both_integer_and_float() -> Result<(), BudgetError> {
    // Quoted integer must be rejected with IncompatibleUnit
    let json_quoted_int = br#"{"tokens": "200"}"#;
    let err_int = BudgetVector::decode_json_slice(json_quoted_int);
    assert!(
        matches!(
            err_int,
            Err(BudgetError::IncompatibleUnit {
                dimension: BudgetDimension::Tokens,
                ..
            })
        ),
        "expected IncompatibleUnit for quoted integer, got {err_int:?}"
    );

    // Quoted float must be rejected with IncompatibleUnit (strict: neither accepts quoted numerals)
    let json_quoted_float = br#"{"privacy_exposure": "0.5"}"#;
    let err_float = BudgetVector::decode_json_slice(json_quoted_float);
    assert!(
        matches!(
            err_float,
            Err(BudgetError::IncompatibleUnit {
                dimension: BudgetDimension::PrivacyExposure,
                ..
            })
        ),
        "expected IncompatibleUnit for quoted float, got {err_float:?}"
    );

    // Valid unquoted numbers must be accepted
    let json_unquoted = br#"{"tokens": 200, "privacy_exposure": 0.5}"#;
    let ok = BudgetVector::decode_json_slice(json_unquoted)?;
    assert_eq!(ok.tokens, 200);
    assert_eq!(ok.privacy_exposure(), 0.5);
    Ok(())
}

#[test]
fn checked_scale_multiplies_budget_dimensions_and_detects_overflow() -> Result<(), BudgetError> {
    let budget = BudgetVector::builder()
        .tokens(100)
        .latency_ms(200)
        .privacy_exposure(1.5)
        .operator_attention_seconds(2.0)
        .build()?;

    let scaled = budget.checked_scale(2.5)?;
    assert_eq!(scaled.tokens, 250);
    assert_eq!(scaled.latency_ms, 500);
    assert_eq!(scaled.privacy_exposure(), 3.75);
    assert_eq!(scaled.operator_attention_seconds(), 5.0);

    // Scaling by negative must fail
    assert!(matches!(
        budget.checked_scale(-1.0),
        Err(BudgetError::NegativeQuantity { .. })
    ));

    // Scaling by NaN must fail
    assert!(matches!(
        budget.checked_scale(f64::NAN),
        Err(BudgetError::NaNQuantity { .. })
    ));

    // Scaling by infinity must fail
    assert!(matches!(
        budget.checked_scale(f64::INFINITY),
        Err(BudgetError::InfiniteQuantity { .. })
    ));

    // Scaling that overflows u64 must return BudgetError::Overflow with operation "scale"
    let huge_budget = BudgetVector::builder().tokens(u64::MAX).build()?;
    assert!(matches!(
        huge_budget.checked_scale(2.0),
        Err(BudgetError::Overflow {
            dimension: BudgetDimension::Tokens,
            operation: "scale",
        })
    ));

    // BudgetQuantity::checked_scale
    let qty = BudgetQuantity::new(2.0, BudgetDimension::PrivacyExposure)?;
    let scaled_qty = qty.checked_scale(3.0, BudgetDimension::PrivacyExposure)?;
    assert_eq!(scaled_qty.get(), 6.0);

    let huge_qty = BudgetQuantity::new(f64::MAX, BudgetDimension::PrivacyExposure)?;
    assert!(matches!(
        huge_qty.checked_scale(2.0, BudgetDimension::PrivacyExposure),
        Err(BudgetError::Overflow {
            dimension: BudgetDimension::PrivacyExposure,
            operation: "scale",
        })
    ));

    Ok(())
}

#[test]
fn validated_by_construction_prevents_invalid_values_reaching_canonical_encoding()
-> Result<(), BudgetError> {
    // Attempting to construct with NaN or negative float fails closed at construction time
    let bad_spec = BudgetVectorSpec {
        privacy_exposure: f64::NAN,
        operator_attention_seconds: -10.0,
        ..Default::default()
    };
    assert!(matches!(
        BudgetVector::new(bad_spec),
        Err(BudgetError::NaNQuantity { .. } | BudgetError::NegativeQuantity { .. })
    ));

    let bad_builder_result = BudgetVector::builder().privacy_exposure(f64::NAN).build();
    assert!(matches!(
        bad_builder_result,
        Err(BudgetError::NaNQuantity { .. })
    ));

    // Valid vector encodes deterministically to exactly 84 canonical bytes
    let valid = BudgetVector::builder()
        .latency_ms(100)
        .privacy_exposure(0.5)
        .build()?;
    let mut encoder = CanonicalEncoder::new();
    valid.encode_to_canonical(&mut encoder);
    let bytes = encoder.finish();
    assert_eq!(bytes.len(), 84);
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-Review Defect Hunt Tests (F1 - F6)
// ---------------------------------------------------------------------------

#[test]
fn test_f1_canonical_decode_rejects_negative_zero_bits() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 84];
    bytes[68] = 0x80; // privacy_exposure set to -0.0 bits (0x8000_0000_0000_0000)
    let res = BudgetVector::decode_canonical(&bytes);
    assert!(
        res.is_err(),
        "canonical decode must reject non-canonical -0.0 bits"
    );

    let quarantine_res = BudgetVector::quarantine_historical(&bytes, "hist-neg-zero");
    assert!(
        quarantine_res.is_err(),
        "quarantine_historical must quarantine non-canonical -0.0 bits"
    );
    Ok(())
}

#[test]
fn test_f2_json_decode_rejects_leading_plus_in_float_dimensions()
-> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{"privacyExposure": +1.5}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        res.is_err(),
        "JSON specification forbids leading +, but decode_json_slice accepted it"
    );
    Ok(())
}

#[test]
fn test_f3_json_decode_rejects_unquoted_keys() -> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{tokens: 100}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(res.is_err(), "JSON keys must be double-quoted strings");
    Ok(())
}

#[test]
fn test_f4_json_decode_rejects_trailing_and_empty_commas() -> Result<(), Box<dyn std::error::Error>>
{
    let json_trailing = br#"{"tokens": 100,}"#;
    assert!(
        BudgetVector::decode_json_slice(json_trailing).is_err(),
        "trailing comma in JSON must be rejected"
    );

    let json_empty = br#"{,}"#;
    assert!(
        BudgetVector::decode_json_slice(json_empty).is_err(),
        "{{,}} in JSON must be rejected"
    );

    let json_consecutive = br#"{"tokens": 100,, "bytes": 200}"#;
    assert!(
        BudgetVector::decode_json_slice(json_consecutive).is_err(),
        "consecutive commas in JSON must be rejected"
    );
    Ok(())
}

#[test]
fn test_f5_json_decode_nested_object_reports_structural_error()
-> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{"tokens": {"a": 1, "b": 2}}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { reason }) if reason.contains("nested")),
        "nested values must produce structural InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn test_f6_checked_scale_does_not_blame_latency_when_vector_has_no_latency()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = BudgetVector::builder().privacy_exposure(1.0).build()?;
    let res = budget.checked_scale(-1.0);
    let is_neg_non_latency = matches!(
        res,
        Err(BudgetError::NegativeQuantity { dimension, .. }) if dimension != BudgetDimension::LatencyMs
    );
    assert!(
        is_neg_non_latency,
        "scaling factor error should not blame LatencyMs on a pure privacy budget"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Defects found by PinkCoast adversarial review (fss-x4a.8.13 v3)
// ---------------------------------------------------------------------------

#[test]
fn defect_empty_object_silently_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { .. })),
        "empty object {{}} must be rejected with InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn defect_whitespace_only_object_silently_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let json = b"{   \t\n\r  }";
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { .. })),
        "whitespace-only object must be rejected with InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn defect_malformed_numbers_float_dims_silently_accepted() -> Result<(), Box<dyn std::error::Error>>
{
    let invalid_floats = [
        ("1.", br#"{"privacyExposure": 1.}"# as &[u8]),
        (".5", br#"{"privacyExposure": .5}"#),
        ("01", br#"{"privacyExposure": 01}"#),
    ];
    for (label, json) in invalid_floats {
        let res = BudgetVector::decode_json_slice(json);
        assert!(
            matches!(res, Err(BudgetError::InvalidEncoding { .. })),
            "malformed float number '{label}' must be rejected with InvalidEncoding, got: {res:?}"
        );
    }
    Ok(())
}

#[test]
fn defect_malformed_numbers_integer_dims_silently_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{"tokens": 01}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { .. })),
        "leading zero '01' must be rejected with InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn defect_illegal_whitespace_formfeed_and_vtab_silently_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let json_formfeed = b"{\"tokens\": 100\x0c, \"bytes\": 200}";
    let res_ff = BudgetVector::decode_json_slice(json_formfeed);
    assert!(
        matches!(res_ff, Err(BudgetError::InvalidEncoding { .. })),
        "form feed \\f whitespace must be rejected with InvalidEncoding, got: {res_ff:?}"
    );

    let json_vtab = b"{\"tokens\": 100\x0b, \"bytes\": 200}";
    let res_vt = BudgetVector::decode_json_slice(json_vtab);
    assert!(
        matches!(res_vt, Err(BudgetError::InvalidEncoding { .. })),
        "vertical tab \\v whitespace must be rejected with InvalidEncoding, got: {res_vt:?}"
    );
    Ok(())
}

#[test]
fn defect_malformed_numbers_misclassified_as_incompatible_unit()
-> Result<(), Box<dyn std::error::Error>> {
    let malformed_numbers = [
        ("1e", br#"{"tokens": 1e}"# as &[u8]),
        ("1e+", br#"{"tokens": 1e+}"#),
        ("1_000", br#"{"tokens": 1_000}"#),
        ("0x10", br#"{"tokens": 0x10}"#),
    ];
    for (label, json) in malformed_numbers {
        let res = BudgetVector::decode_json_slice(json);
        assert!(
            matches!(res, Err(BudgetError::InvalidEncoding { .. })),
            "malformed number '{label}' must be InvalidEncoding, got: {res:?}"
        );
    }
    Ok(())
}

#[test]
fn defect_bare_minus_misclassified_as_negative_quantity() -> Result<(), Box<dyn std::error::Error>>
{
    let json = br#"{"tokens": -}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { .. })),
        "bare minus '-' must be InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn defect_overflowing_exponent_misclassified_for_float_and_int()
-> Result<(), Box<dyn std::error::Error>> {
    let json_float = br#"{"privacyExposure": 1e400}"#;
    let res_float = BudgetVector::decode_json_slice(json_float);
    assert!(
        matches!(res_float, Err(BudgetError::InvalidEncoding { .. })),
        "1e400 for float dim must be InvalidEncoding, got: {res_float:?}"
    );

    let json_int = br#"{"tokens": 1e400}"#;
    let res_int = BudgetVector::decode_json_slice(json_int);
    assert!(
        matches!(res_int, Err(BudgetError::InvalidEncoding { .. })),
        "1e400 for integer dim must be InvalidEncoding, got: {res_int:?}"
    );
    Ok(())
}

#[test]
fn defect_boolean_and_null_values_misclassified() -> Result<(), Box<dyn std::error::Error>> {
    let non_numbers = [
        ("true int", br#"{"tokens": true}"# as &[u8]),
        ("null int", br#"{"tokens": null}"#),
        ("true float", br#"{"privacyExposure": true}"#),
        ("null float", br#"{"privacyExposure": null}"#),
    ];
    for (label, json) in non_numbers {
        let res = BudgetVector::decode_json_slice(json);
        assert!(
            matches!(res, Err(BudgetError::InvalidEncoding { .. })),
            "value '{label}' must be InvalidEncoding, got: {res:?}"
        );
    }
    Ok(())
}

#[test]
fn defect_trailing_garbage_after_brace_misclassified() -> Result<(), Box<dyn std::error::Error>> {
    let json = br#"{"tokens": 100} ;}"#;
    let res = BudgetVector::decode_json_slice(json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { .. })),
        "trailing garbage after closing brace must be InvalidEncoding, got: {res:?}"
    );
    Ok(())
}

#[test]
fn defect_unescaped_control_chars_and_invalid_unicode_escape()
-> Result<(), Box<dyn std::error::Error>> {
    // Unescaped control character in key
    let json_ctrl_in_key = b"{\"tok\x00ens\": 100}";
    let res_key = BudgetVector::decode_json_slice(json_ctrl_in_key);
    assert!(
        matches!(res_key, Err(BudgetError::InvalidEncoding { .. })),
        "unescaped control char in key must be InvalidEncoding, got: {res_key:?}"
    );

    // Unescaped control character in string value
    let json_ctrl_in_val = b"{\"tokens\": \"val\x1f\"}";
    let res_val = BudgetVector::decode_json_slice(json_ctrl_in_val);
    assert!(
        matches!(res_val, Err(BudgetError::InvalidEncoding { .. })),
        "unescaped control char in value must be InvalidEncoding, got: {res_val:?}"
    );

    // Invalid \u escape (not 4 hex digits)
    let json_bad_u = br#"{"tokens\u002g": 100}"#;
    let res_u = BudgetVector::decode_json_slice(json_bad_u);
    assert!(
        matches!(res_u, Err(BudgetError::InvalidEncoding { .. })),
        "invalid \\u escape must be InvalidEncoding, got: {res_u:?}"
    );

    // Incomplete \u escape
    let json_short_u = br#"{"tokens\u00": 100}"#;
    let res_short = BudgetVector::decode_json_slice(json_short_u);
    assert!(
        matches!(res_short, Err(BudgetError::InvalidEncoding { .. })),
        "short \\u escape must be InvalidEncoding, got: {res_short:?}"
    );

    Ok(())
}

#[test]
fn defect_input_exceeding_max_json_budget_bytes() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(BudgetVector::MAX_JSON_BUDGET_BYTES, 64 * 1024);
    let max_bytes = BudgetVector::MAX_JSON_BUDGET_BYTES;
    let mut large_json = Vec::with_capacity(max_bytes + 10);
    large_json.extend_from_slice(b"{\"tokens\": 1, ");
    while large_json.len() <= max_bytes {
        large_json.extend_from_slice(b" ");
    }
    large_json.extend_from_slice(b"\"bytes\": 2}");
    assert!(large_json.len() > max_bytes);

    let res = BudgetVector::decode_json_slice(&large_json);
    assert!(
        matches!(res, Err(BudgetError::InvalidEncoding { reason }) if reason.contains("maximum permitted size")),
        "input exceeding MAX_JSON_BUDGET_BYTES must be rejected with InvalidEncoding, got: {res:?}"
    );
    Ok(())
}
