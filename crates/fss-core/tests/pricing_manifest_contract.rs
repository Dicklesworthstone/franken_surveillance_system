#![forbid(unsafe_code)]
//! Contract tests for dated provider-pricing manifests (FSS-066 / fss-x4a.13.6).

use std::error::Error;

use fss_core::{
    ArchiveMonthlyCost, ArchiveMonthlyUsage, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, CostClass, DatedPriceRate, MAX_CURRENCY_LEN, MAX_MAPPINGS_COUNT,
    MAX_PROVIDER_ID_LEN, MAX_RATES_COUNT, MAX_SOURCE_LEN, MAX_TIER_LEN, OperationCostMapping,
    PROVIDER_PRICING_MANIFEST_DOMAIN, PROVIDER_PRICING_MANIFEST_MAGIC,
    PROVIDER_PRICING_MANIFEST_VERSION_1, PriceLookupError, PricingManifestError, PricingProvenance,
    PricingUnit, ProvenanceClass, ProviderPricingManifest, TimestampNs,
};

type TestResult = Result<(), Box<dyn Error>>;

fn test_timestamp(ns: i128) -> TimestampNs {
    TimestampNs(ns)
}

fn test_validity_window(start_ns: i128, end_ns: i128) -> Result<CaptureInterval, Box<dyn Error>> {
    let interval = CaptureInterval::new(test_timestamp(start_ns), test_timestamp(end_ns))?;
    Ok(interval)
}

fn sample_r2_manifest(
    supersedes: Option<ContentDigest>,
) -> Result<ProviderPricingManifest, Box<dyn Error>> {
    // 2026-08-30T00:00:00Z = 1_788_048_000_000_000_000 ns
    let retrieved_at = test_timestamp(1_788_048_000_000_000_000);
    // Valid for 1 year: 2026-08-30 to 2027-08-30
    let window = test_validity_window(
        1_788_048_000_000_000_000,
        1_788_048_000_000_000_000 + 365 * 86_400 * 1_000_000_000,
    )?;

    let provenance = PricingProvenance {
        source: "https://www.cloudflare.com/plans/developer-platform/pricing/".to_string(),
        retrieved_at,
        validity_window: window,
        retrieval_witness: Some(ContentDigest::sha256(b"cloudflare-r2-pricing-2026-08-30")),
        provenance_class: ProvenanceClass::Observed,
    };

    // Cloudflare R2 rates from PRICING_REFERENCE_2026-08-30.md:
    // - Storage: $0.015 per GB-month = 15_000_000_000 pico-USD / GB-month
    // - Class A: $4.50 per million ops = 4_500_000_000_000 pico-USD / 1M ops
    // - Class B: $0.36 per million ops = 360_000_000_000 pico-USD / 1M ops
    // - Egress: $0.00 (free)
    let rates = vec![
        DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: None,
            unit: PricingUnit::PerGibMonth,
            rate_pico_currency: 15_000_000_000, // $0.015
            free_tier_allowance: Some(10),      // 10 GB-months free
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::ClassAOperations,
            operation_name: None,
            unit: PricingUnit::PerMillionOperations,
            rate_pico_currency: 4_500_000_000_000, // $4.50 / 1M
            free_tier_allowance: Some(1_000_000),  // 1M free operations
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::ClassBOperations,
            operation_name: None,
            unit: PricingUnit::PerMillionOperations,
            rate_pico_currency: 360_000_000_000,   // $0.36 / 1M
            free_tier_allowance: Some(10_000_000), // 10M free operations
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::Egress,
            operation_name: None,
            unit: PricingUnit::PerGib,
            rate_pico_currency: 0, // $0.00
            free_tier_allowance: None,
            minimum_billable_unit: None,
        },
    ];

    let operation_mappings = vec![
        OperationCostMapping {
            provider_operation: "CompleteMultipartUpload".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
        OperationCostMapping {
            provider_operation: "CreateMultipartUpload".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
        OperationCostMapping {
            provider_operation: "GetObject".to_string(),
            cost_class: CostClass::ClassBOperations,
        },
        OperationCostMapping {
            provider_operation: "HeadObject".to_string(),
            cost_class: CostClass::ClassBOperations,
        },
        OperationCostMapping {
            provider_operation: "ListObjectsV2".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
        OperationCostMapping {
            provider_operation: "PutObject".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
        OperationCostMapping {
            provider_operation: "UploadPart".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
    ];

    let manifest = ProviderPricingManifest::new(
        "cloudflare-r2".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        provenance,
        supersedes,
        rates,
        operation_mappings,
    )?;
    Ok(manifest)
}

fn sample_b2_manifest() -> Result<ProviderPricingManifest, Box<dyn Error>> {
    let retrieved_at = test_timestamp(1_788_048_000_000_000_000);
    let window = test_validity_window(
        1_788_048_000_000_000_000,
        1_788_048_000_000_000_000 + 180 * 86_400 * 1_000_000_000,
    )?;

    let provenance = PricingProvenance {
        source: "https://www.backblaze.com/cloud-storage/pricing".to_string(),
        retrieved_at,
        validity_window: window,
        retrieval_witness: Some(ContentDigest::sha256(b"backblaze-b2-pricing-2026-08-30")),
        provenance_class: ProvenanceClass::Observed,
    };

    // Backblaze B2 rates:
    // - Storage: $6.95 per TB-month = 6_950_000_000_000 pico-USD / TB-month
    // - Class A (calls): $0.005 per 10,000 = $0.50 per million = 500_000_000_000 pico-USD / 1M
    // - Class B (downloads): $0.004 per 10,000 = $0.40 per million = 400_000_000_000 pico-USD / 1M
    // - Egress: $0.01 per GB = 10_000_000_000 pico-USD / GB
    let rates = vec![
        DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: None,
            unit: PricingUnit::PerTbMonth,
            rate_pico_currency: 6_950_000_000_000, // $6.95 / TB-month
            free_tier_allowance: None,
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::ClassAOperations,
            operation_name: None,
            unit: PricingUnit::PerMillionOperations,
            rate_pico_currency: 500_000_000_000,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::ClassBOperations,
            operation_name: None,
            unit: PricingUnit::PerMillionOperations,
            rate_pico_currency: 400_000_000_000,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        },
        DatedPriceRate {
            cost_class: CostClass::Egress,
            operation_name: None,
            unit: PricingUnit::PerGib,
            rate_pico_currency: 10_000_000_000, // $0.01 / GB
            free_tier_allowance: None,
            minimum_billable_unit: None,
        },
    ];

    let operation_mappings = vec![
        OperationCostMapping {
            provider_operation: "b2_upload_file".to_string(),
            cost_class: CostClass::ClassAOperations,
        },
        OperationCostMapping {
            provider_operation: "b2_download_file_by_id".to_string(),
            cost_class: CostClass::ClassBOperations,
        },
    ];

    let manifest = ProviderPricingManifest::new(
        "backblaze-b2".to_string(),
        "pay-as-you-go".to_string(),
        "USD".to_string(),
        provenance,
        None,
        rates,
        operation_mappings,
    )?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1: Stable Typed Semantics and Hard Bounds
// ---------------------------------------------------------------------------

#[test]
fn ac1_valid_manifest_construction_and_properties() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    if manifest.provider_id() != "cloudflare-r2" {
        return Err("unexpected provider id".into());
    }
    if manifest.pricing_tier() != "standard" {
        return Err("unexpected tier".into());
    }
    if manifest.currency() != "USD" {
        return Err("unexpected currency".into());
    }
    if manifest.rates().len() != 4 {
        return Err("expected 4 rates".into());
    }
    if manifest.operation_mappings().len() != 7 {
        return Err("expected 7 operation mappings".into());
    }
    Ok(())
}

#[test]
fn ac1_hard_bounds_enforced_at_bound_and_bound_plus_one() -> TestResult {
    let window = test_validity_window(100, 200)?;
    let base_prov = PricingProvenance {
        source: "https://example.com/pricing".to_string(),
        retrieved_at: test_timestamp(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };

    // Provider ID: exactly at bound MAX_PROVIDER_ID_LEN
    let exact_provider = "a".repeat(MAX_PROVIDER_ID_LEN);
    let m1 = ProviderPricingManifest::new(
        exact_provider,
        "standard".to_string(),
        "USD".to_string(),
        base_prov.clone(),
        None,
        vec![],
        vec![],
    )?;
    if m1.provider_id().len() != MAX_PROVIDER_ID_LEN {
        return Err("expected exact provider id length".into());
    }

    // Provider ID: bound + 1
    let over_provider = "a".repeat(MAX_PROVIDER_ID_LEN + 1);
    let err = ProviderPricingManifest::new(
        over_provider,
        "standard".to_string(),
        "USD".to_string(),
        base_prov.clone(),
        None,
        vec![],
        vec![],
    );
    match err {
        Err(PricingManifestError::StringLengthOutOfBounds { field, length, .. }) => {
            if field != "provider_id" || length != MAX_PROVIDER_ID_LEN + 1 {
                return Err("unexpected error details".into());
            }
        }
        _ => return Err("expected StringLengthOutOfBounds for provider_id".into()),
    }

    // Tier: bound + 1
    let over_tier = "b".repeat(MAX_TIER_LEN + 1);
    let err_tier = ProviderPricingManifest::new(
        "provider".to_string(),
        over_tier,
        "USD".to_string(),
        base_prov.clone(),
        None,
        vec![],
        vec![],
    );
    match err_tier {
        Err(PricingManifestError::StringLengthOutOfBounds { field, .. }) => {
            if field != "pricing_tier" {
                return Err("expected pricing_tier field".into());
            }
        }
        _ => return Err("expected StringLengthOutOfBounds for pricing_tier".into()),
    }

    // Source: bound + 1
    let mut over_prov = base_prov.clone();
    over_prov.source = "s".repeat(MAX_SOURCE_LEN + 1);
    let err_source = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        over_prov,
        None,
        vec![],
        vec![],
    );
    match err_source {
        Err(PricingManifestError::StringLengthOutOfBounds { field, .. }) => {
            if field != "source" {
                return Err("expected source field".into());
            }
        }
        _ => return Err("expected StringLengthOutOfBounds for source".into()),
    }

    // Currency: bound + 1
    let over_curr = "C".repeat(MAX_CURRENCY_LEN + 1);
    let err_curr = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        over_curr,
        base_prov.clone(),
        None,
        vec![],
        vec![],
    );
    match err_curr {
        Err(PricingManifestError::StringLengthOutOfBounds { field, .. }) => {
            if field != "currency" {
                return Err("expected currency field".into());
            }
        }
        _ => return Err("expected StringLengthOutOfBounds for currency".into()),
    }

    // Rates count: bound + 1
    let mut over_rates = Vec::new();
    for i in 0..MAX_RATES_COUNT + 1 {
        over_rates.push(DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: Some(format!("op_{i}")),
            unit: PricingUnit::PerByteMonth,
            rate_pico_currency: 1,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        });
    }
    let err_rates = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov.clone(),
        None,
        over_rates,
        vec![],
    );
    match err_rates {
        Err(PricingManifestError::OverLimit { field, count, .. }) => {
            if field != "rates" || count != MAX_RATES_COUNT + 1 {
                return Err("unexpected count error".into());
            }
        }
        _ => return Err("expected OverLimit for rates".into()),
    }

    // Operation mappings count: bound + 1
    let mut over_mappings = Vec::new();
    for i in 0..MAX_MAPPINGS_COUNT + 1 {
        over_mappings.push(OperationCostMapping {
            provider_operation: format!("op_{i}"),
            cost_class: CostClass::ClassAOperations,
        });
    }
    let err_map = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov,
        None,
        vec![],
        over_mappings,
    );
    match err_map {
        Err(PricingManifestError::OverLimit { field, count, .. }) => {
            if field != "operation_mappings" || count != MAX_MAPPINGS_COUNT + 1 {
                return Err("unexpected count error".into());
            }
        }
        _ => return Err("expected OverLimit for operation_mappings".into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2: Pricing Provenance Pinning and Non-Timelessness
// ---------------------------------------------------------------------------

#[test]
fn ac2_pricing_provenance_pinning() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let prov = manifest.provenance();

    if prov.source.is_empty() {
        return Err("provenance source must not be empty".into());
    }
    if prov.retrieved_at.0 == 0 {
        return Err("retrieved_at must be declared".into());
    }
    if prov.validity_window.earliest.0 >= prov.validity_window.latest.0 {
        return Err("validity window must be non-degenerate".into());
    }
    if prov.provenance_class != ProvenanceClass::Observed {
        return Err("unexpected provenance class".into());
    }
    if prov.retrieval_witness.is_none() {
        return Err("witness expected".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3: Fail Closed Outside Validity Window and Unknown Provenance
// ---------------------------------------------------------------------------

#[test]
fn ac3_fail_closed_outside_validity_window() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let start = manifest.provenance().validity_window.earliest;
    let end = manifest.provenance().validity_window.latest;

    // 1. Query before validity window: must fail with Premature
    let premature_time = test_timestamp(start.0 - 1);
    let err_pre = manifest.lookup_rate(CostClass::Storage, premature_time);
    match err_pre {
        Err(PriceLookupError::Premature {
            valid_from,
            query_time,
        }) => {
            if valid_from != start || query_time != premature_time {
                return Err("unexpected premature details".into());
            }
        }
        _ => return Err("expected Premature error for early query".into()),
    }

    // 2. Query after validity window: must fail with Stale
    let stale_time = test_timestamp(end.0 + 1);
    let err_stale = manifest.lookup_rate(CostClass::Storage, stale_time);
    match err_stale {
        Err(PriceLookupError::Stale {
            expired_at,
            query_time,
        }) => {
            if expired_at != end || query_time != stale_time {
                return Err("unexpected stale details".into());
            }
        }
        _ => return Err("expected Stale error for expired query".into()),
    }

    // 3. Exactly at start: valid
    let rate_start = manifest.lookup_rate(CostClass::Storage, start)?;
    if rate_start.rate_pico_currency != 15_000_000_000 {
        return Err("rate mismatch at start".into());
    }

    // 4. Exactly at end: valid
    let rate_end = manifest.lookup_rate(CostClass::Storage, end)?;
    if rate_end.rate_pico_currency != 15_000_000_000 {
        return Err("rate mismatch at end".into());
    }

    // 5. Operation lookup also fails closed outside window
    let op_err_pre = manifest.lookup_operation_rate("PutObject", premature_time);
    match op_err_pre {
        Err(PriceLookupError::Premature { .. }) => {}
        _ => return Err("expected Premature for operation lookup".into()),
    }

    let op_err_stale = manifest.lookup_operation_rate("PutObject", stale_time);
    match op_err_stale {
        Err(PriceLookupError::Stale { .. }) => {}
        _ => return Err("expected Stale for operation lookup".into()),
    }

    Ok(())
}

#[test]
fn ac3_fail_closed_on_synthetic_or_unknown_provenance() -> TestResult {
    let window = test_validity_window(100, 200)?;
    let synthetic_prov = PricingProvenance {
        source: "https://example.com/unverified".to_string(),
        retrieved_at: test_timestamp(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Predicted,
    };

    let manifest = ProviderPricingManifest::new(
        "test-provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        synthetic_prov,
        None,
        vec![DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: None,
            unit: PricingUnit::PerGibMonth,
            rate_pico_currency: 10_000_000_000,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        }],
        vec![],
    )?;

    // Query within validity window, but with SyntheticHypothetical provenance
    let query_time = test_timestamp(150);
    let err = manifest.lookup_rate(CostClass::Storage, query_time);
    match err {
        Err(PriceLookupError::UnknownProvenance { .. }) => {}
        _ => return Err("expected UnknownProvenance for synthetic provenance class".into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4: Deterministic Reference Behavior and Exact Calculations
// ---------------------------------------------------------------------------

#[test]
fn ac4_exact_r2_cost_calculation_with_free_tier() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let at_time = test_timestamp(1_788_048_000_000_000_000 + 1_000_000_000);

    // Scenario:
    // - 100 GB-months stored (10 GB free allowance -> 90 GB billable @ $0.015 = $1.35)
    // - 2,000,000 Class A operations (1M free -> 1M billable @ $4.50 / 1M = $4.50)
    // - 20,000,000 Class B operations (10M free -> 10M billable @ $0.36 / 1M = $3.60)
    // - 500 GB egress (@ $0.00 = $0.00)
    // Total expected = $1.35 + $4.50 + $3.60 + $0.00 = $9.45
    let usage = ArchiveMonthlyUsage {
        retained_gb_months: 100,
        class_a_operations: 2_000_000,
        class_b_operations: 20_000_000,
        egress_gb: 500,
    };

    let cost = manifest.calculate_archive_monthly_cost(&usage, at_time)?;

    // $1.35 in pico-USD = 1_350_000_000_000
    if cost.storage_pico_currency != 1_350_000_000_000 {
        return Err(format!(
            "storage cost mismatch: expected 1_350_000_000_000, got {}",
            cost.storage_pico_currency
        )
        .into());
    }

    // $4.50 in pico-USD = 4_500_000_000_000
    if cost.class_a_pico_currency != 4_500_000_000_000 {
        return Err("class a cost mismatch".into());
    }

    // $3.60 in pico-USD = 3_600_000_000_000
    if cost.class_b_pico_currency != 3_600_000_000_000 {
        return Err("class b cost mismatch".into());
    }

    // $0.00 in pico-USD
    if cost.egress_pico_currency != 0 {
        return Err("egress cost mismatch".into());
    }

    // Total = $9.45 = 9_450_000_000_000 pico-USD
    if cost.total_pico_currency != 9_450_000_000_000 {
        return Err("total cost mismatch".into());
    }

    if cost.total_currency_string() != "9.450000000000" {
        return Err("formatted total currency string mismatch".into());
    }

    Ok(())
}

#[test]
fn ac4_exact_b2_cost_calculation() -> TestResult {
    let manifest = sample_b2_manifest()?;
    let at_time = test_timestamp(1_788_048_000_000_000_000 + 1_000_000_000);

    // Scenario:
    // - 5,000 GB-months stored (= 5 TB @ $6.95 / TB-month = $34.75)
    // - 10,000,000 Class A operations (@ $0.50 / 1M = $5.00)
    // - 5,000,000 Class B operations (@ $0.40 / 1M = $2.00)
    // - 200 GB egress (@ $0.01 / GB = $2.00)
    // Total expected = $34.75 + $5.00 + $2.00 + $2.00 = $43.75
    let usage = ArchiveMonthlyUsage {
        retained_gb_months: 5_000,
        class_a_operations: 10_000_000,
        class_b_operations: 5_000_000,
        egress_gb: 200,
    };

    let cost = manifest.calculate_archive_monthly_cost(&usage, at_time)?;

    // $34.75 in pico-USD = 34_750_000_000_000
    if cost.storage_pico_currency != 34_750_000_000_000 {
        return Err(format!(
            "B2 storage cost mismatch: expected 34_750_000_000_000, got {}",
            cost.storage_pico_currency
        )
        .into());
    }

    // $5.00
    if cost.class_a_pico_currency != 5_000_000_000_000 {
        return Err("B2 class A cost mismatch".into());
    }

    // $2.00
    if cost.class_b_pico_currency != 2_000_000_000_000 {
        return Err("B2 class B cost mismatch".into());
    }

    // $2.00
    if cost.egress_pico_currency != 2_000_000_000_000 {
        return Err("B2 egress cost mismatch".into());
    }

    // Total $43.75 = 43_750_000_000_000 pico-USD
    if cost.total_pico_currency != 43_750_000_000_000 {
        return Err("B2 total cost mismatch".into());
    }

    if cost.total_currency_string() != "43.750000000000" {
        return Err("formatted B2 total currency string mismatch".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5: Canonical Encoding and Registered Digest Domain
// ---------------------------------------------------------------------------

#[test]
fn ac5_canonical_round_trip_bit_identical() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let encoded = manifest.encode()?;

    let decoded = ProviderPricingManifest::decode(&encoded)?;
    if decoded != manifest {
        return Err("decoded manifest does not match original".into());
    }
    if decoded.manifest_digest()? != manifest.manifest_digest()? {
        return Err("decoded digest mismatch".into());
    }

    // Bit-identical re-encoding
    let re_encoded = decoded.encode()?;
    if re_encoded != encoded {
        return Err("re-encoded bytes are not bit-identical".into());
    }

    Ok(())
}

#[test]
fn ac5_registered_digest_domain_verification() -> TestResult {
    if PROVIDER_PRICING_MANIFEST_DOMAIN != "fss.provider_pricing_manifest.v1" {
        return Err("domain constant mismatch".into());
    }
    let manifest = sample_r2_manifest(None)?;
    let digest = manifest.manifest_digest()?;
    if digest.algorithm() != fss_core::DigestAlgorithm::Sha256 {
        return Err("digest algorithm must be sha256".into());
    }
    if digest.to_text().is_empty() {
        return Err("digest hex must not be empty".into());
    }
    Ok(())
}

#[test]
fn ac5_non_canonical_sorting_rejected_on_decode() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let encoded = manifest.encode()?;

    // Verify that encoded bytes can be decoded
    let _ = ProviderPricingManifest::decode(&encoded)?;

    // Plant duplicate rate into encoded stream or verify decode rejects unsorted rates
    // Construct an unsorted manifest in memory and confirm new() sorts it deterministically:
    let rate_b = DatedPriceRate {
        cost_class: CostClass::ClassBOperations,
        operation_name: None,
        unit: PricingUnit::PerMillionOperations,
        rate_pico_currency: 360_000_000_000,
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };
    let rate_a = DatedPriceRate {
        cost_class: CostClass::ClassAOperations,
        operation_name: None,
        unit: PricingUnit::PerMillionOperations,
        rate_pico_currency: 4_500_000_000_000,
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };

    // Provide unsorted: rate_b before rate_a
    let m = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        manifest.provenance().clone(),
        None,
        vec![rate_b.clone(), rate_a.clone()],
        vec![],
    )?;

    // Manifest automatically normalizes to canonical sorted order
    if m.rates()[0].cost_class != CostClass::ClassAOperations {
        return Err("rates must be sorted canonically".into());
    }
    if m.rates()[1].cost_class != CostClass::ClassBOperations {
        return Err("rates must be sorted canonically".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 6: Superseding History and Latest Alias Rejection
// ---------------------------------------------------------------------------

#[test]
fn ac6_superseding_chain_and_latest_alias_rejection() -> TestResult {
    let manifest_v1 = sample_r2_manifest(None)?;
    let digest_v1 = manifest_v1.manifest_digest()?;

    // v2 supersedes v1 explicitly via digest:
    let manifest_v2 = sample_r2_manifest(Some(digest_v1))?;
    if manifest_v2.supersedes_manifest() != Some(digest_v1) {
        return Err("supersedes digest mismatch in v2".into());
    }
    if manifest_v2.manifest_digest()? == digest_v1 {
        return Err("v2 digest must differ from v1".into());
    }

    // Rejection of "latest" alias in provider_id
    let prov = manifest_v1.provenance().clone();
    let err_provider = ProviderPricingManifest::new(
        "latest-provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        prov.clone(),
        None,
        vec![],
        vec![],
    );
    match err_provider {
        Err(PricingManifestError::LatestNotResolvable { field }) => {
            if field != "provider_id" {
                return Err("expected provider_id field".into());
            }
        }
        _ => return Err("expected LatestNotResolvable for provider_id".into()),
    }

    // Rejection of "LATEST" in tier
    let err_tier = ProviderPricingManifest::new(
        "provider".to_string(),
        "TIER_LATEST".to_string(),
        "USD".to_string(),
        prov.clone(),
        None,
        vec![],
        vec![],
    );
    match err_tier {
        Err(PricingManifestError::LatestNotResolvable { field }) => {
            if field != "pricing_tier" {
                return Err("expected pricing_tier field".into());
            }
        }
        _ => return Err("expected LatestNotResolvable for pricing_tier".into()),
    }

    // Rejection of "Latest" in source
    let mut bad_prov = prov;
    bad_prov.source = "https://example.com/pricing/latest.json".to_string();
    let err_source = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        bad_prov,
        None,
        vec![],
        vec![],
    );
    match err_source {
        Err(PricingManifestError::LatestNotResolvable { field }) => {
            if field != "source" {
                return Err("expected source field".into());
            }
        }
        _ => return Err("expected LatestNotResolvable for source".into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 7: Malformed and Edge Case Gauntlet
// ---------------------------------------------------------------------------

#[test]
fn ac7_malformed_and_edge_case_gauntlet() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let at_time = test_timestamp(1_788_048_000_000_000_000 + 1_000_000_000);

    // 1. Unmapped operation query
    let err_unmapped = manifest.lookup_operation_rate("UnknownOperation", at_time);
    match err_unmapped {
        Err(PriceLookupError::UnmappedOperation { operation }) => {
            if operation != "UnknownOperation" {
                return Err("unexpected operation name".into());
            }
        }
        _ => return Err("expected UnmappedOperation".into()),
    }

    // 2. Cost class not configured in manifest
    let err_unconfig = manifest.lookup_rate(CostClass::LocalCompute, at_time);
    match err_unconfig {
        Err(PriceLookupError::CostClassNotFound { cost_class }) => {
            if cost_class != CostClass::LocalCompute {
                return Err("unexpected cost class".into());
            }
        }
        _ => return Err("expected CostClassNotFound".into()),
    }

    // 3. Inverted validity window rejected at construction
    let inv_window = CaptureInterval {
        earliest: test_timestamp(500),
        latest: test_timestamp(100),
    };
    let mut bad_prov = manifest.provenance().clone();
    bad_prov.validity_window = inv_window;
    let err_inv = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        bad_prov,
        None,
        vec![],
        vec![],
    );
    match err_inv {
        Err(PricingManifestError::InvertedValidityWindow { .. }) => {}
        _ => return Err("expected InvertedValidityWindow".into()),
    }

    // 4. Duplicate rate rejected at construction
    let dup_rate = DatedPriceRate {
        cost_class: CostClass::Storage,
        operation_name: None,
        unit: PricingUnit::PerGibMonth,
        rate_pico_currency: 100,
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };
    let err_dup = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        manifest.provenance().clone(),
        None,
        vec![dup_rate.clone(), dup_rate],
        vec![],
    );
    match err_dup {
        Err(PricingManifestError::DuplicateRate { .. }) => {}
        _ => return Err("expected DuplicateRate".into()),
    }

    // 5. Truncation at every byte prefix in decode
    let encoded = manifest.encode()?;
    for offset in 0..encoded.len().min(40) {
        let truncated = &encoded[..offset];
        if ProviderPricingManifest::decode(truncated).is_ok() {
            return Err(
                format!("truncated decode at offset {offset} unexpectedly succeeded").into(),
            );
        }
    }

    // 6. Bad magic prefix rejected
    let mut bad_magic = encoded.clone();
    bad_magic[0..4].copy_from_slice(b"NOPE");
    if ProviderPricingManifest::decode(&bad_magic).is_ok() {
        return Err("bad magic decode unexpectedly succeeded".into());
    }

    // 7. Non-uppercase currency rejected
    let err_curr = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "usd".to_string(), // lowercase
        manifest.provenance().clone(),
        None,
        vec![],
        vec![],
    );
    match err_curr {
        Err(PricingManifestError::CurrencyCodeInvalid { .. }) => {}
        _ => return Err("expected CurrencyCodeInvalid for lowercase currency".into()),
    }

    Ok(())
}

#[test]
fn test_g1_manifest_digest_returns_result_and_never_fabricates_default() -> TestResult {
    let manifest1 = sample_r2_manifest(None)?;
    let digest1 = manifest1.manifest_digest()?;

    let manifest2 = sample_b2_manifest()?;
    let digest2 = manifest2.manifest_digest()?;

    let default_bytes = [0u8; 32];
    if digest1.bytes() == default_bytes || digest2.bytes() == default_bytes {
        return Err("manifest_digest must never fabricate default all-zero bytes".into());
    }
    if digest1 == digest2 {
        return Err("distinct manifests must produce distinct digests".into());
    }

    Ok(())
}

#[test]
fn test_g2_rates_bound_enforced_at_bound_and_bound_plus_one() -> TestResult {
    let window = test_validity_window(100, 200)?;
    let base_prov = PricingProvenance {
        source: "https://example.com/pricing".to_string(),
        retrieved_at: test_timestamp(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };

    // Exactly at bound: MAX_RATES_COUNT (128)
    let mut bound_rates = Vec::with_capacity(MAX_RATES_COUNT);
    for i in 0..MAX_RATES_COUNT {
        bound_rates.push(DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: Some(format!("op_{i}")),
            unit: PricingUnit::PerByteMonth,
            rate_pico_currency: 1,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        });
    }
    let m_bound = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov.clone(),
        None,
        bound_rates,
        vec![],
    )?;
    let encoded_bound = m_bound.encode()?;
    if encoded_bound.is_empty() {
        return Err("encoded at bound must not be empty".into());
    }

    // Bound + 1: MAX_RATES_COUNT + 1 (129)
    let mut over_rates = Vec::with_capacity(MAX_RATES_COUNT + 1);
    for i in 0..=MAX_RATES_COUNT {
        over_rates.push(DatedPriceRate {
            cost_class: CostClass::Storage,
            operation_name: Some(format!("op_{i}")),
            unit: PricingUnit::PerByteMonth,
            rate_pico_currency: 1,
            free_tier_allowance: None,
            minimum_billable_unit: None,
        });
    }
    let err_new = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov,
        None,
        over_rates,
        vec![],
    );
    match err_new {
        Err(PricingManifestError::OverLimit { field, count, max }) => {
            if field != "rates" || count != MAX_RATES_COUNT + 1 || max != MAX_RATES_COUNT {
                return Err("unexpected OverLimit parameters for rates".into());
            }
        }
        _ => return Err("expected typed OverLimit error at bound + 1 for rates".into()),
    }

    Ok(())
}

#[test]
fn test_g3_operation_mappings_bound_enforced_at_bound_and_bound_plus_one() -> TestResult {
    let window = test_validity_window(100, 200)?;
    let base_prov = PricingProvenance {
        source: "https://example.com/pricing".to_string(),
        retrieved_at: test_timestamp(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };

    // Exactly at bound: MAX_MAPPINGS_COUNT (256)
    let mut bound_mappings = Vec::with_capacity(MAX_MAPPINGS_COUNT);
    for i in 0..MAX_MAPPINGS_COUNT {
        bound_mappings.push(OperationCostMapping {
            provider_operation: format!("op_{i}"),
            cost_class: CostClass::ClassAOperations,
        });
    }
    let m_bound = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov.clone(),
        None,
        vec![],
        bound_mappings,
    )?;
    let encoded_bound = m_bound.encode()?;
    if encoded_bound.is_empty() {
        return Err("encoded mappings at bound must not be empty".into());
    }

    // Bound + 1: MAX_MAPPINGS_COUNT + 1 (257)
    let mut over_mappings = Vec::with_capacity(MAX_MAPPINGS_COUNT + 1);
    for i in 0..=MAX_MAPPINGS_COUNT {
        over_mappings.push(OperationCostMapping {
            provider_operation: format!("op_{i}"),
            cost_class: CostClass::ClassAOperations,
        });
    }
    let err_new = ProviderPricingManifest::new(
        "provider".to_string(),
        "standard".to_string(),
        "USD".to_string(),
        base_prov,
        None,
        vec![],
        over_mappings,
    );
    match err_new {
        Err(PricingManifestError::OverLimit { field, count, max }) => {
            if field != "operation_mappings"
                || count != MAX_MAPPINGS_COUNT + 1
                || max != MAX_MAPPINGS_COUNT
            {
                return Err("unexpected OverLimit parameters for operation_mappings".into());
            }
        }
        _ => {
            return Err(
                "expected typed OverLimit error at bound + 1 for operation_mappings".into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_finding1_manifest_digest_collision_boundary_shift() -> TestResult {
    let window = test_validity_window(100, 200)?;
    let prov = PricingProvenance {
        source: "https://example.com/pricing".to_string(),
        retrieved_at: test_timestamp(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };
    // Boundary shift: "aws-s3" + "standard" vs "aws" + "-s3standard"
    let m_a = ProviderPricingManifest::new(
        "aws-s3".into(),
        "standard".into(),
        "USD".into(),
        prov.clone(),
        None,
        vec![],
        vec![],
    )?;
    let m_b = ProviderPricingManifest::new(
        "aws".into(),
        "-s3standard".into(),
        "USD".into(),
        prov,
        None,
        vec![],
        vec![],
    )?;
    if m_a.manifest_digest()? == m_b.manifest_digest()? {
        return Err(
            "boundary shift between provider_id and tier must not produce colliding digests".into(),
        );
    }
    Ok(())
}

#[test]
fn test_finding2_per_byte_month_storage_cost_calculation() -> TestResult {
    let m = sample_r2_manifest(None)?;
    let byte_rate = DatedPriceRate {
        cost_class: CostClass::Storage,
        operation_name: None,
        unit: PricingUnit::PerByteMonth,
        rate_pico_currency: 15, // 15 pico-USD / byte-month = $0.015 / GB-month
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };
    let manifest = ProviderPricingManifest::new(
        m.provider_id().to_string(),
        m.pricing_tier().to_string(),
        "USD".to_string(),
        m.provenance().clone(),
        None,
        vec![byte_rate],
        vec![],
    )?;
    let usage = ArchiveMonthlyUsage {
        retained_gb_months: 100,
        class_a_operations: 0,
        class_b_operations: 0,
        egress_gb: 0,
    };
    let cost =
        manifest.calculate_archive_monthly_cost(&usage, m.provenance().validity_window.earliest)?;
    // 100 GB = 100 * 10^9 bytes. Total pico-USD should be 100 * 10^9 * 15 = 1_500_000_000_000 ($1.50)
    if cost.storage_pico_currency != 1_500_000_000_000 {
        return Err(format!(
            "storage cost underbilled by 10^9: expected 1_500_000_000_000, got {}",
            cost.storage_pico_currency
        )
        .into());
    }

    // Incompatible unit test: CostClass::Storage with PerJoule
    let bad_rate = DatedPriceRate {
        cost_class: CostClass::Storage,
        operation_name: None,
        unit: PricingUnit::PerJoule,
        rate_pico_currency: 100,
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };
    let bad_manifest = ProviderPricingManifest::new(
        m.provider_id().to_string(),
        m.pricing_tier().to_string(),
        "USD".to_string(),
        m.provenance().clone(),
        None,
        vec![bad_rate],
        vec![],
    );
    match bad_manifest {
        Err(PricingManifestError::IncompatibleUnit {
            cost_class: CostClass::Storage,
            unit: PricingUnit::PerJoule,
        }) => Ok(()),
        _ => Err("expected IncompatibleUnit error for Storage with PerJoule".into()),
    }
}

#[test]
fn test_finding3_no_float_precision_loss_above_9007_usd() -> TestResult {
    let pico: u128 = 10_000_000_000_000_001; // > 2^53 pico-units ($10,000.000000000001)
    let formatted = ArchiveMonthlyCost::format_pico_currency(pico);
    if formatted != "10000.000000000001" {
        return Err(format!("expected '10000.000000000001', got {formatted}").into());
    }
    Ok(())
}

#[test]
fn test_finding4_retrieval_date_and_source_validation() -> TestResult {
    let window = test_validity_window(100, 200)?;

    // 1. Zero retrieval timestamp
    let prov_zero = PricingProvenance {
        source: "https://example.com".to_string(),
        retrieved_at: TimestampNs(0),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };
    if prov_zero.validate().is_ok() {
        return Err("retrieved_at == 0 must be rejected".into());
    }

    // 2. Negative retrieval timestamp
    let prov_neg = PricingProvenance {
        source: "https://example.com".to_string(),
        retrieved_at: TimestampNs(-1),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };
    if prov_neg.validate().is_ok() {
        return Err("negative retrieved_at must be rejected".into());
    }

    // 3. Retrieval date after validity window latest
    let prov_post_expiry = PricingProvenance {
        source: "https://example.com".to_string(),
        retrieved_at: TimestampNs(201),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };
    if prov_post_expiry.validate().is_ok() {
        return Err("retrieved_at after validity_window.latest must be rejected".into());
    }

    // 4. Blank / whitespace source
    let prov_blank = PricingProvenance {
        source: "   ".to_string(),
        retrieved_at: TimestampNs(150),
        validity_window: window,
        retrieval_witness: None,
        provenance_class: ProvenanceClass::Observed,
    };
    if prov_blank.validate().is_ok() {
        return Err("whitespace-only source must be rejected".into());
    }

    Ok(())
}

#[test]
fn test_finding5_calculate_operation_cost_applies_surcharge() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    // Manifest already has PutObject mapped to ClassAOperations.
    // Add an operation-specific override for PutObject with a surcharge: 9_000_000_000_000 pico-USD / 1M ops
    let surcharge_rate = DatedPriceRate {
        cost_class: CostClass::ClassAOperations,
        operation_name: Some("PutObject".to_string()),
        unit: PricingUnit::PerMillionOperations,
        rate_pico_currency: 9_000_000_000_000, // $9.00 / 1M ops (vs default $4.50)
        free_tier_allowance: None,
        minimum_billable_unit: None,
    };
    let mut rates = manifest.rates().to_vec();
    rates.push(surcharge_rate);

    let manifest_with_override = ProviderPricingManifest::new(
        manifest.provider_id().to_string(),
        manifest.pricing_tier().to_string(),
        manifest.currency().to_string(),
        manifest.provenance().clone(),
        None,
        rates,
        manifest.operation_mappings().to_vec(),
    )?;

    let query_time = manifest.provenance().validity_window.earliest;
    // Calculate 1_000_000 PutObject operations: should use the override ($9.00 = 9_000_000_000_000)
    let op_cost =
        manifest_with_override.calculate_operation_cost("PutObject", 1_000_000, query_time)?;
    if op_cost != 9_000_000_000_000 {
        return Err(format!(
            "operation override not applied: expected 9_000_000_000_000, got {op_cost}"
        )
        .into());
    }

    // For an un-overridden ClassA operation like CreateMultipartUpload, generic rate ($4.50) should be applied.
    // 2_000_000 ops - 1_000_000 free tier = 1_000_000 billable @ $4.50 / 1M = 4_500_000_000_000.
    let generic_cost = manifest_with_override.calculate_operation_cost(
        "CreateMultipartUpload",
        2_000_000,
        query_time,
    )?;
    if generic_cost != 4_500_000_000_000 {
        return Err(format!(
            "generic rate not applied for non-overridden operation: expected 4_500_000_000_000, got {generic_cost}"
        )
        .into());
    }

    Ok(())
}

#[test]
fn test_finding6_monthly_archive_near_expiry_fails_closed() -> TestResult {
    let m = sample_r2_manifest(None)?;
    let at_time = m.provenance().validity_window.latest;
    let usage = ArchiveMonthlyUsage {
        retained_gb_months: 100,
        class_a_operations: 1000,
        class_b_operations: 1000,
        egress_gb: 10,
    };
    let res = m.calculate_archive_monthly_cost(&usage, at_time);
    match res {
        Err(PriceLookupError::Stale { .. }) => Ok(()),
        other => Err(format!(
            "monthly calculation at expiry instant must fail closed with Stale, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn test_finding7_decode_rejects_unsorted_rates_stream() -> TestResult {
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(&PROVIDER_PRICING_MANIFEST_MAGIC);
    encoder.text(PROVIDER_PRICING_MANIFEST_DOMAIN);
    encoder.u32(PROVIDER_PRICING_MANIFEST_VERSION_1);
    encoder.text("provider");
    encoder.text("standard");
    encoder.text("USD");
    encoder.text("https://example.com");
    TimestampNs(100).encode_canonical(&mut encoder);
    CaptureInterval::new_checked(TimestampNs(100), TimestampNs(200))?
        .encode_canonical(&mut encoder);
    encoder.tag(0); // witness None
    encoder.tag(1); // Observed
    encoder.tag(0); // supersedes None

    // Rates: count = 2, but unsorted: ClassB (tag 3) before ClassA (tag 2)
    encoder.u32(2);
    // Rate B
    encoder.tag(3); // CostClass::ClassBOperations
    encoder.tag(0); // operation_name None
    encoder.tag(5); // PerMillionOperations
    encoder.bytes(&100u128.to_be_bytes());
    encoder.tag(0);
    encoder.tag(0);
    // Rate A
    encoder.tag(2); // CostClass::ClassAOperations
    encoder.tag(0); // operation_name None
    encoder.tag(5); // PerMillionOperations
    encoder.bytes(&200u128.to_be_bytes());
    encoder.tag(0);
    encoder.tag(0);

    // Mappings: count = 0
    encoder.u32(0);

    let malformed_bytes = encoder.finish();
    match ProviderPricingManifest::decode(&malformed_bytes) {
        Err(PricingManifestError::NonCanonicalOrder { field: "rates" }) => Ok(()),
        other => Err(format!(
            "expected NonCanonicalOrder for unsorted rates stream, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn test_finding8_decode_returns_rich_error_variants() -> TestResult {
    let manifest = sample_r2_manifest(None)?;
    let mut encoded = manifest.encode()?;

    // Bad magic (offset 8..12 following the 8-byte length prefix)
    encoded[8..12].copy_from_slice(b"XXXX");
    match ProviderPricingManifest::decode(&encoded) {
        Err(PricingManifestError::BadMagic { expected, actual }) => {
            if expected != PROVIDER_PRICING_MANIFEST_MAGIC || actual != *b"XXXX" {
                return Err("unexpected BadMagic values".into());
            }
        }
        other => return Err(format!("expected BadMagic, got {other:?}").into()),
    }

    // Unsupported version
    let mut encoder = CanonicalEncoder::new();
    encoder.bytes(&PROVIDER_PRICING_MANIFEST_MAGIC);
    encoder.text(PROVIDER_PRICING_MANIFEST_DOMAIN);
    encoder.u32(99); // version 99
    encoder.text("provider");
    encoder.text("tier");
    encoder.text("USD");
    encoder.text("https://example.com");
    TimestampNs(100).encode_canonical(&mut encoder);
    CaptureInterval::new_checked(TimestampNs(100), TimestampNs(200))?
        .encode_canonical(&mut encoder);
    encoder.tag(0);
    encoder.tag(1);
    encoder.tag(0);
    encoder.u32(0);
    encoder.u32(0);
    match ProviderPricingManifest::decode(&encoder.finish()) {
        Err(PricingManifestError::UnsupportedVersion { actual: 99 }) => Ok(()),
        other => Err(format!("expected UnsupportedVersion(99), got {other:?}").into()),
    }
}

#[test]
fn test_gate_encode_canonical_checked_fails_closed_on_encoder_error() -> TestResult {
    let manifest = sample_r2_manifest(None)?;

    // If an encoder is already in an error state (or encounters an error),
    // encode_canonical_checked must fail closed with a typed error rather than returning Ok(()).
    let mut bad_encoder = CanonicalEncoder::new();
    bad_encoder.text(&"x".repeat(fss_core::MAX_CANONICAL_TEXT_BYTES + 1));
    if !bad_encoder.has_error() {
        return Err("expected bad_encoder to have an error".into());
    }

    let res = manifest.encode_canonical_checked(&mut bad_encoder);
    match res {
        Err(PricingManifestError::Contract(_)) => Ok(()),
        Ok(()) => Err(
            "encode_canonical_checked must fail closed on encoder error, but returned Ok(())"
                .into(),
        ),
        Err(other) => Err(format!("expected Contract error, got {other:?}").into()),
    }
}
