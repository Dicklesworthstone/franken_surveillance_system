//! Dated provider-pricing manifest v1 (FSS-066 / fss-x4a.13.6).
//!
//! Provides the canonical [`ProviderPricingManifest`] type with:
//! - Content-addressed canonical pricing manifest binding provider identity, pricing tier,
//!   currency, dated rate table, provider operation mappings, and strict provenance.
//! - Provenance pinning: every price carries source documentation, retrieval date,
//!   validity window, currency, unit, and epistemic provenance class.
//! - Strict fail-closed query semantics: any lookup outside the validity window or with
//!   unknown/synthetic provenance fails closed with typed [`PriceLookupError::Premature`],
//!   [`PriceLookupError::Stale`], or [`PriceLookupError::UnknownProvenance`] (never default
//!   or last-known values).
//! - Rejection of floating alias `"latest"` everywhere (provider ID, tier, source).
//! - Bit-identical canonical encoding round-trips under registered digest domain
//!   `fss.provider_pricing_manifest.v1`.
//! - Exact integer pico-currency rate arithmetic (10^-12 currency units, e.g. pico-USD)
//!   for zero-loss storage, operations, and egress cost calculations.

use core::fmt;
use std::error::Error;

use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, ProvenanceClass, Sha256Hasher, TimestampNs,
};

/// Canonical digest domain tag for dated provider-pricing manifests.
pub const PROVIDER_PRICING_MANIFEST_DOMAIN: &str = "fss.provider_pricing_manifest.v1";

/// Format magic header for binary provider-pricing manifest envelope (`FSPM`).
pub const PROVIDER_PRICING_MANIFEST_MAGIC: [u8; 4] = *b"FSPM";

/// Binary format version for provider-pricing manifest v1.
pub const PROVIDER_PRICING_MANIFEST_VERSION_1: u32 = 1;

/// Maximum allowed byte length for a provider identity string.
pub const MAX_PROVIDER_ID_LEN: usize = 64;

/// Minimum allowed byte length for a provider identity string.
pub const MIN_PROVIDER_ID_LEN: usize = 2;

/// Maximum allowed byte length for a pricing tier string.
pub const MAX_TIER_LEN: usize = 64;

/// Minimum allowed byte length for a pricing tier string.
pub const MIN_TIER_LEN: usize = 1;

/// Maximum allowed byte length for a pricing source URI/reference.
pub const MAX_SOURCE_LEN: usize = 512;

/// Minimum allowed byte length for a pricing source URI/reference.
pub const MIN_SOURCE_LEN: usize = 1;

/// Maximum allowed byte length for a currency code (e.g. `USD`).
pub const MAX_CURRENCY_LEN: usize = 8;

/// Minimum allowed byte length for a currency code.
pub const MIN_CURRENCY_LEN: usize = 3;

/// Maximum allowed byte length for an operation name string.
pub const MAX_OPERATION_LEN: usize = 64;

/// Minimum allowed byte length for an operation name string.
pub const MIN_OPERATION_LEN: usize = 1;

/// Maximum number of rate entries permitted in a manifest.
pub const MAX_RATES_COUNT: usize = 128;

/// Maximum number of operation cost mappings permitted in a manifest.
pub const MAX_MAPPINGS_COUNT: usize = 256;

/// 1 currency unit (e.g. 1 USD) = 1,000,000,000,000 pico-currency units (10^12).
pub const PICO_DENOMINATOR: u128 = 1_000_000_000_000;

/// Number of gigabytes per terabyte in decimal storage metrics (1 TB = 1,000 GB).
pub const GB_PER_TB: u64 = 1_000;

/// Floating alias refused wherever a provider, tier, or source is named.
pub const LATEST_ALIAS: &str = "latest";

/// Rejects any identifier that names [`LATEST_ALIAS`] in any letter case and at any position.
pub fn reject_latest_alias(value: &str, field: &'static str) -> Result<(), PricingManifestError> {
    let alias = LATEST_ALIAS.as_bytes();
    if value
        .as_bytes()
        .windows(alias.len())
        .any(|window| window.eq_ignore_ascii_case(alias))
    {
        return Err(PricingManifestError::LatestNotResolvable { field });
    }
    Ok(())
}

/// Standard FSS archive cost classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CostClass {
    /// Object storage volume over time (GB-month, TB-month, Byte-month).
    Storage,
    /// Class A operations: write, list, create multipart, upload part, complete multipart.
    ClassAOperations,
    /// Class B operations: read, head/stat, get metadata.
    ClassBOperations,
    /// Internet / inter-region egress data transfer.
    Egress,
    /// Data retrieval / un-archival fees.
    DataRetrieval,
    /// Local compute / transcode energy.
    LocalCompute,
}

impl CostClass {
    /// Canonical machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::ClassAOperations => "class_a_operations",
            Self::ClassBOperations => "class_b_operations",
            Self::Egress => "egress",
            Self::DataRetrieval => "data_retrieval",
            Self::LocalCompute => "local_compute",
        }
    }

    /// Encodes into canonical single-byte discriminator.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Storage => 1,
            Self::ClassAOperations => 2,
            Self::ClassBOperations => 3,
            Self::Egress => 4,
            Self::DataRetrieval => 5,
            Self::LocalCompute => 6,
        }
    }

    /// Decodes from canonical single-byte discriminator.
    pub fn from_u8(tag: u8) -> Result<Self, PricingManifestError> {
        match tag {
            1 => Ok(Self::Storage),
            2 => Ok(Self::ClassAOperations),
            3 => Ok(Self::ClassBOperations),
            4 => Ok(Self::Egress),
            5 => Ok(Self::DataRetrieval),
            6 => Ok(Self::LocalCompute),
            other => Err(PricingManifestError::InvalidTag {
                field: "cost_class",
                tag: other,
            }),
        }
    }
}

impl fmt::Display for CostClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unit of measure for pricing rates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PricingUnit {
    /// Per byte-month of stored data.
    PerByteMonth,
    /// Per gigabyte-month (decimal 10^9 bytes).
    PerGibMonth,
    /// Per terabyte-month (decimal 10^12 bytes).
    PerTbMonth,
    /// Per single API operation.
    PerOperation,
    /// Per 1,000,000 API operations.
    PerMillionOperations,
    /// Per single byte transferred/retrieved.
    PerByte,
    /// Per gigabyte transferred/retrieved.
    PerGib,
    /// Per joule of energy consumed.
    PerJoule,
}

impl PricingUnit {
    /// Canonical machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerByteMonth => "per_byte_month",
            Self::PerGibMonth => "per_gib_month",
            Self::PerTbMonth => "per_tb_month",
            Self::PerOperation => "per_operation",
            Self::PerMillionOperations => "per_million_operations",
            Self::PerByte => "per_byte",
            Self::PerGib => "per_gib",
            Self::PerJoule => "per_joule",
        }
    }

    /// Encodes into canonical single-byte discriminator.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::PerByteMonth => 1,
            Self::PerGibMonth => 2,
            Self::PerTbMonth => 3,
            Self::PerOperation => 4,
            Self::PerMillionOperations => 5,
            Self::PerByte => 6,
            Self::PerGib => 7,
            Self::PerJoule => 8,
        }
    }

    /// Decodes from canonical single-byte discriminator.
    pub fn from_u8(tag: u8) -> Result<Self, PricingManifestError> {
        match tag {
            1 => Ok(Self::PerByteMonth),
            2 => Ok(Self::PerGibMonth),
            3 => Ok(Self::PerTbMonth),
            4 => Ok(Self::PerOperation),
            5 => Ok(Self::PerMillionOperations),
            6 => Ok(Self::PerByte),
            7 => Ok(Self::PerGib),
            8 => Ok(Self::PerJoule),
            other => Err(PricingManifestError::InvalidTag {
                field: "pricing_unit",
                tag: other,
            }),
        }
    }
}

impl fmt::Display for PricingUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provenance and custody metadata for a dated pricing manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricingProvenance {
    /// Official URL or document reference consulted.
    pub source: String,
    /// Exact timestamp when pricing information was retrieved/observed.
    pub retrieved_at: TimestampNs,
    /// Validity window during which this pricing is guaranteed to apply.
    pub validity_window: CaptureInterval,
    /// Cryptographic digest of the raw source pricing documentation, if retained.
    pub retrieval_witness: Option<ContentDigest>,
    /// Epistemic provenance classification.
    pub provenance_class: ProvenanceClass,
}

impl PricingProvenance {
    /// Validates all constraints and bounds on the provenance record.
    pub fn validate(&self) -> Result<(), PricingManifestError> {
        if self.source.len() < MIN_SOURCE_LEN || self.source.len() > MAX_SOURCE_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "source",
                length: self.source.len(),
                min: MIN_SOURCE_LEN,
                max: MAX_SOURCE_LEN,
            });
        }
        reject_latest_alias(&self.source, "source")?;
        if self.validity_window.earliest > self.validity_window.latest {
            return Err(PricingManifestError::InvertedValidityWindow {
                earliest: self.validity_window.earliest,
                latest: self.validity_window.latest,
            });
        }
        Ok(())
    }
}

/// Converts a [`ProvenanceClass`] to its canonical single-byte tag.
#[must_use]
pub const fn provenance_class_to_u8(p: ProvenanceClass) -> u8 {
    match p {
        ProvenanceClass::Observed => 1,
        ProvenanceClass::Derived => 2,
        ProvenanceClass::Predicted => 3,
        ProvenanceClass::Remembered => 4,
        ProvenanceClass::OperatorAsserted => 5,
        ProvenanceClass::VendorClaimed => 6,
        ProvenanceClass::Policy => 7,
    }
}

/// Decodes a [`ProvenanceClass`] from its canonical single-byte tag.
pub fn provenance_class_from_u8(val: u8) -> Result<ProvenanceClass, ContractError> {
    match val {
        1 => Ok(ProvenanceClass::Observed),
        2 => Ok(ProvenanceClass::Derived),
        3 => Ok(ProvenanceClass::Predicted),
        4 => Ok(ProvenanceClass::Remembered),
        5 => Ok(ProvenanceClass::OperatorAsserted),
        6 => Ok(ProvenanceClass::VendorClaimed),
        7 => Ok(ProvenanceClass::Policy),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

/// One dated rate specification for a cost class or specific provider operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatedPriceRate {
    /// Target FSS cost class.
    pub cost_class: CostClass,
    /// Specific provider operation name if this is an operation override.
    pub operation_name: Option<String>,
    /// Unit of measure for the rate.
    pub unit: PricingUnit,
    /// Price per unit in pico-currency (10^-12 currency units, e.g. pico-USD).
    pub rate_pico_currency: u128,
    /// Free tier allowance in raw units per month, if applicable.
    pub free_tier_allowance: Option<u64>,
    /// Minimum billable unit in raw units, if applicable.
    pub minimum_billable_unit: Option<u64>,
}

impl DatedPriceRate {
    /// Validates rate fields and bounds.
    pub fn validate(&self) -> Result<(), PricingManifestError> {
        if let Some(op) = &self.operation_name {
            if op.len() < MIN_OPERATION_LEN || op.len() > MAX_OPERATION_LEN {
                return Err(PricingManifestError::StringLengthOutOfBounds {
                    field: "operation_name",
                    length: op.len(),
                    min: MIN_OPERATION_LEN,
                    max: MAX_OPERATION_LEN,
                });
            }
            reject_latest_alias(op, "operation_name")?;
        }
        Ok(())
    }

    /// Sort key for canonical deterministic ordering.
    fn canonical_key(&self) -> (u8, Option<&str>) {
        (self.cost_class.as_u8(), self.operation_name.as_deref())
    }
}

/// Mapping from provider-specific operation name to FSS cost class.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OperationCostMapping {
    /// Provider-specific operation or API request name (e.g. `PutObject`).
    pub provider_operation: String,
    /// Mapped FSS cost class.
    pub cost_class: CostClass,
}

impl OperationCostMapping {
    /// Validates operation mapping fields and bounds.
    pub fn validate(&self) -> Result<(), PricingManifestError> {
        if self.provider_operation.len() < MIN_OPERATION_LEN
            || self.provider_operation.len() > MAX_OPERATION_LEN
        {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "provider_operation",
                length: self.provider_operation.len(),
                min: MIN_OPERATION_LEN,
                max: MAX_OPERATION_LEN,
            });
        }
        reject_latest_alias(&self.provider_operation, "provider_operation")?;
        Ok(())
    }
}

/// Monthly resource usage quantities for archive cost estimation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveMonthlyUsage {
    /// Retained volume in gigabyte-months.
    pub retained_gb_months: u64,
    /// Class A operations count.
    pub class_a_operations: u64,
    /// Class B operations count.
    pub class_b_operations: u64,
    /// Data retrieval / egress in gigabytes.
    pub egress_gb: u64,
}

/// Detailed cost breakdown for one monthly archive usage projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveMonthlyCost {
    /// Storage cost in pico-currency.
    pub storage_pico_currency: u128,
    /// Class A operations cost in pico-currency.
    pub class_a_pico_currency: u128,
    /// Class B operations cost in pico-currency.
    pub class_b_pico_currency: u128,
    /// Egress cost in pico-currency.
    pub egress_pico_currency: u128,
    /// Aggregate monthly cost in pico-currency.
    pub total_pico_currency: u128,
    /// Currency code (e.g. `USD`).
    pub currency: String,
    /// Validity window under which this cost projection was computed.
    pub validity_window: CaptureInterval,
}

impl ArchiveMonthlyCost {
    /// Total cost in major currency units as f64 (for logging/display only).
    #[must_use]
    pub fn total_currency_f64(&self) -> f64 {
        (self.total_pico_currency as f64) / (PICO_DENOMINATOR as f64)
    }

    /// Storage cost in major currency units as f64.
    #[must_use]
    pub fn storage_currency_f64(&self) -> f64 {
        (self.storage_pico_currency as f64) / (PICO_DENOMINATOR as f64)
    }

    /// Class A cost in major currency units as f64.
    #[must_use]
    pub fn class_a_currency_f64(&self) -> f64 {
        (self.class_a_pico_currency as f64) / (PICO_DENOMINATOR as f64)
    }

    /// Class B cost in major currency units as f64.
    #[must_use]
    pub fn class_b_currency_f64(&self) -> f64 {
        (self.class_b_pico_currency as f64) / (PICO_DENOMINATOR as f64)
    }

    /// Egress cost in major currency units as f64.
    #[must_use]
    pub fn egress_currency_f64(&self) -> f64 {
        (self.egress_pico_currency as f64) / (PICO_DENOMINATOR as f64)
    }
}

/// Dated, self-verifying provider pricing manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPricingManifest {
    manifest_version: u32,
    provider_id: String,
    pricing_tier: String,
    currency: String,
    provenance: PricingProvenance,
    supersedes_manifest: Option<ContentDigest>,
    rates: Vec<DatedPriceRate>,
    operation_mappings: Vec<OperationCostMapping>,
    manifest_digest: ContentDigest,
}

impl ProviderPricingManifest {
    /// Builds and validates a dated provider pricing manifest.
    ///
    /// Rates and operation mappings are sorted deterministically into canonical order.
    /// Duplicates, inverted validity windows, out-of-bound strings, and `"latest"` aliases
    /// are rejected.
    pub fn new(
        provider_id: String,
        pricing_tier: String,
        currency: String,
        provenance: PricingProvenance,
        supersedes_manifest: Option<ContentDigest>,
        rates: Vec<DatedPriceRate>,
        operation_mappings: Vec<OperationCostMapping>,
    ) -> Result<Self, PricingManifestError> {
        if provider_id.len() < MIN_PROVIDER_ID_LEN || provider_id.len() > MAX_PROVIDER_ID_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "provider_id",
                length: provider_id.len(),
                min: MIN_PROVIDER_ID_LEN,
                max: MAX_PROVIDER_ID_LEN,
            });
        }
        reject_latest_alias(&provider_id, "provider_id")?;

        if pricing_tier.len() < MIN_TIER_LEN || pricing_tier.len() > MAX_TIER_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "pricing_tier",
                length: pricing_tier.len(),
                min: MIN_TIER_LEN,
                max: MAX_TIER_LEN,
            });
        }
        reject_latest_alias(&pricing_tier, "pricing_tier")?;

        if currency.len() < MIN_CURRENCY_LEN || currency.len() > MAX_CURRENCY_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "currency",
                length: currency.len(),
                min: MIN_CURRENCY_LEN,
                max: MAX_CURRENCY_LEN,
            });
        }
        if !currency.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(PricingManifestError::CurrencyCodeInvalid {
                code: currency.clone(),
            });
        }

        provenance.validate()?;

        if rates.len() > MAX_RATES_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "rates",
                count: rates.len(),
                max: MAX_RATES_COUNT,
            });
        }

        if operation_mappings.len() > MAX_MAPPINGS_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "operation_mappings",
                count: operation_mappings.len(),
                max: MAX_MAPPINGS_COUNT,
            });
        }

        for r in &rates {
            r.validate()?;
        }
        for m in &operation_mappings {
            m.validate()?;
        }

        // Canonical sort and duplicate check for rates
        let mut sorted_rates = rates;
        sorted_rates.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        for window in sorted_rates.windows(2) {
            if window[0].canonical_key() == window[1].canonical_key() {
                return Err(PricingManifestError::DuplicateRate {
                    cost_class: window[0].cost_class,
                    operation_name: window[0].operation_name.clone(),
                });
            }
        }

        // Canonical sort and duplicate check for operation mappings
        let mut sorted_mappings = operation_mappings;
        sorted_mappings.sort_by(|a, b| a.provider_operation.cmp(&b.provider_operation));
        for window in sorted_mappings.windows(2) {
            if window[0].provider_operation == window[1].provider_operation {
                return Err(PricingManifestError::DuplicateOperationMapping {
                    operation: window[0].provider_operation.clone(),
                });
            }
        }

        let mut manifest = Self {
            manifest_version: PROVIDER_PRICING_MANIFEST_VERSION_1,
            provider_id,
            pricing_tier,
            currency,
            provenance,
            supersedes_manifest,
            rates: sorted_rates,
            operation_mappings: sorted_mappings,
            manifest_digest: ContentDigest::sha256(&[]),
        };

        manifest.manifest_digest = manifest.compute_manifest_digest()?;
        Ok(manifest)
    }

    /// Manifest format version.
    #[must_use]
    pub const fn manifest_version(&self) -> u32 {
        self.manifest_version
    }

    /// Provider identifier.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Pricing tier identifier.
    #[must_use]
    pub fn pricing_tier(&self) -> &str {
        &self.pricing_tier
    }

    /// Currency code (e.g. `USD`).
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Provenance metadata.
    #[must_use]
    pub fn provenance(&self) -> &PricingProvenance {
        &self.provenance
    }

    /// Prior manifest digest superseded by this generation.
    #[must_use]
    pub const fn supersedes_manifest(&self) -> Option<ContentDigest> {
        self.supersedes_manifest
    }

    /// Sorted list of configured price rates.
    #[must_use]
    pub fn rates(&self) -> &[DatedPriceRate] {
        &self.rates
    }

    /// Sorted list of provider operation cost mappings.
    #[must_use]
    pub fn operation_mappings(&self) -> &[OperationCostMapping] {
        &self.operation_mappings
    }

    /// Validates all structural constraints and bounds of this manifest.
    pub fn validate(&self) -> Result<(), PricingManifestError> {
        if self.provider_id.len() < MIN_PROVIDER_ID_LEN
            || self.provider_id.len() > MAX_PROVIDER_ID_LEN
        {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "provider_id",
                length: self.provider_id.len(),
                min: MIN_PROVIDER_ID_LEN,
                max: MAX_PROVIDER_ID_LEN,
            });
        }
        reject_latest_alias(&self.provider_id, "provider_id")?;

        if self.pricing_tier.len() < MIN_TIER_LEN || self.pricing_tier.len() > MAX_TIER_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "pricing_tier",
                length: self.pricing_tier.len(),
                min: MIN_TIER_LEN,
                max: MAX_TIER_LEN,
            });
        }
        reject_latest_alias(&self.pricing_tier, "pricing_tier")?;

        if self.currency.len() < MIN_CURRENCY_LEN || self.currency.len() > MAX_CURRENCY_LEN {
            return Err(PricingManifestError::StringLengthOutOfBounds {
                field: "currency",
                length: self.currency.len(),
                min: MIN_CURRENCY_LEN,
                max: MAX_CURRENCY_LEN,
            });
        }
        if !self.currency.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(PricingManifestError::CurrencyCodeInvalid {
                code: self.currency.clone(),
            });
        }

        self.provenance.validate()?;

        if self.rates.len() > MAX_RATES_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "rates",
                count: self.rates.len(),
                max: MAX_RATES_COUNT,
            });
        }
        if self.operation_mappings.len() > MAX_MAPPINGS_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "operation_mappings",
                count: self.operation_mappings.len(),
                max: MAX_MAPPINGS_COUNT,
            });
        }

        for r in &self.rates {
            r.validate()?;
        }
        for m in &self.operation_mappings {
            m.validate()?;
        }

        for window in self.rates.windows(2) {
            if window[0].canonical_key() >= window[1].canonical_key() {
                return Err(PricingManifestError::NonCanonicalOrder { field: "rates" });
            }
        }
        for window in self.operation_mappings.windows(2) {
            if window[0].provider_operation >= window[1].provider_operation {
                return Err(PricingManifestError::NonCanonicalOrder {
                    field: "operation_mappings",
                });
            }
        }

        Ok(())
    }

    /// Canonical content digest over all fields under the registered domain.
    pub fn manifest_digest(&self) -> Result<ContentDigest, PricingManifestError> {
        self.compute_manifest_digest()
    }

    /// Returns the precomputed canonical content digest.
    #[must_use]
    pub const fn precomputed_digest(&self) -> ContentDigest {
        self.manifest_digest
    }

    /// Checks that the query timestamp falls within the certified validity window
    /// and that the provenance classification is acceptable.
    ///
    /// Fails closed with typed errors; never falls back to defaults or last-known values.
    fn check_validity(&self, at_time: TimestampNs) -> Result<(), PriceLookupError> {
        if at_time < self.provenance.validity_window.earliest {
            return Err(PriceLookupError::Premature {
                valid_from: self.provenance.validity_window.earliest,
                query_time: at_time,
            });
        }
        if at_time > self.provenance.validity_window.latest {
            return Err(PriceLookupError::Stale {
                expired_at: self.provenance.validity_window.latest,
                query_time: at_time,
            });
        }
        match self.provenance.provenance_class {
            ProvenanceClass::VendorClaimed
            | ProvenanceClass::Observed
            | ProvenanceClass::OperatorAsserted
            | ProvenanceClass::Policy => Ok(()),
            other => Err(PriceLookupError::UnknownProvenance {
                reason: format!("unsupported provenance class: {other:?}"),
            }),
        }
    }

    /// Looks up the price rate for a given cost class at a specific query time.
    ///
    /// Returns [`PriceLookupError::Premature`] if `at_time` is before validity window,
    /// [`PriceLookupError::Stale`] if `at_time` is after validity window,
    /// [`PriceLookupError::UnknownProvenance`] if provenance is synthetic or unknown,
    /// or [`PriceLookupError::CostClassNotFound`] if the cost class is not configured.
    pub fn lookup_rate(
        &self,
        cost_class: CostClass,
        at_time: TimestampNs,
    ) -> Result<&DatedPriceRate, PriceLookupError> {
        self.check_validity(at_time)?;

        // Find general rate (operation_name == None) for this cost class
        self.rates
            .iter()
            .find(|r| r.cost_class == cost_class && r.operation_name.is_none())
            .ok_or(PriceLookupError::CostClassNotFound { cost_class })
    }

    /// Looks up the price rate for a specific provider operation at a specific query time.
    ///
    /// Checks operation mappings first, then looks for operation-specific rate overrides
    /// before falling back to the cost class default rate.
    pub fn lookup_operation_rate(
        &self,
        operation: &str,
        at_time: TimestampNs,
    ) -> Result<(&OperationCostMapping, &DatedPriceRate), PriceLookupError> {
        self.check_validity(at_time)?;

        let mapping = self
            .operation_mappings
            .iter()
            .find(|m| m.provider_operation == operation)
            .ok_or_else(|| PriceLookupError::UnmappedOperation {
                operation: operation.to_string(),
            })?;

        // Check if there is an operation-specific rate override
        let rate = self
            .rates
            .iter()
            .find(|r| {
                r.cost_class == mapping.cost_class && r.operation_name.as_deref() == Some(operation)
            })
            .or_else(|| {
                // Fall back to general rate for mapped cost class
                self.rates
                    .iter()
                    .find(|r| r.cost_class == mapping.cost_class && r.operation_name.is_none())
            })
            .ok_or(PriceLookupError::CostClassNotFound {
                cost_class: mapping.cost_class,
            })?;

        Ok((mapping, rate))
    }

    /// Calculates cost in pico-currency for a given cost class and quantity at `at_time`.
    ///
    /// Accounts for unit conversions, minimum billable units, and free tier allowances.
    pub fn calculate_cost(
        &self,
        cost_class: CostClass,
        quantity: u64,
        at_time: TimestampNs,
    ) -> Result<u128, PriceLookupError> {
        let rate = self.lookup_rate(cost_class, at_time)?;

        let billable_quantity = if let Some(free) = rate.free_tier_allowance {
            quantity.saturating_sub(free)
        } else {
            quantity
        };

        if billable_quantity == 0 {
            return Ok(0);
        }

        let effective_units = if let Some(min_unit) = rate.minimum_billable_unit {
            billable_quantity.max(min_unit)
        } else {
            billable_quantity
        };

        match rate.unit {
            PricingUnit::PerByteMonth
            | PricingUnit::PerGibMonth
            | PricingUnit::PerOperation
            | PricingUnit::PerByte
            | PricingUnit::PerGib
            | PricingUnit::PerJoule => {
                let qty_u128 = u128::from(effective_units);
                qty_u128
                    .checked_mul(rate.rate_pico_currency)
                    .ok_or(PriceLookupError::ArithmeticOverflow)
            }
            PricingUnit::PerMillionOperations => {
                let qty_u128 = u128::from(effective_units);
                let product = qty_u128
                    .checked_mul(rate.rate_pico_currency)
                    .ok_or(PriceLookupError::ArithmeticOverflow)?;
                Ok(product / 1_000_000)
            }
            PricingUnit::PerTbMonth => {
                let qty_u128 = u128::from(effective_units);
                let product = qty_u128
                    .checked_mul(rate.rate_pico_currency)
                    .ok_or(PriceLookupError::ArithmeticOverflow)?;
                Ok(product / u128::from(GB_PER_TB))
            }
        }
    }

    /// Computes the complete archive monthly cost breakdown for the given usage.
    pub fn calculate_archive_monthly_cost(
        &self,
        usage: &ArchiveMonthlyUsage,
        at_time: TimestampNs,
    ) -> Result<ArchiveMonthlyCost, PriceLookupError> {
        self.check_validity(at_time)?;

        let storage_cost =
            self.calculate_cost(CostClass::Storage, usage.retained_gb_months, at_time)?;
        let class_a_cost = self.calculate_cost(
            CostClass::ClassAOperations,
            usage.class_a_operations,
            at_time,
        )?;
        let class_b_cost = self.calculate_cost(
            CostClass::ClassBOperations,
            usage.class_b_operations,
            at_time,
        )?;
        let egress_cost = self.calculate_cost(CostClass::Egress, usage.egress_gb, at_time)?;

        let total = storage_cost
            .checked_add(class_a_cost)
            .and_then(|sum| sum.checked_add(class_b_cost))
            .and_then(|sum| sum.checked_add(egress_cost))
            .ok_or(PriceLookupError::ArithmeticOverflow)?;

        Ok(ArchiveMonthlyCost {
            storage_pico_currency: storage_cost,
            class_a_pico_currency: class_a_cost,
            class_b_pico_currency: class_b_cost,
            egress_pico_currency: egress_cost,
            total_pico_currency: total,
            currency: self.currency.clone(),
            validity_window: self.provenance.validity_window,
        })
    }

    /// Computes the cryptographic manifest digest over exact canonical bytes.
    fn compute_manifest_digest(&self) -> Result<ContentDigest, PricingManifestError> {
        if self.rates.len() > MAX_RATES_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "rates",
                count: self.rates.len(),
                max: MAX_RATES_COUNT,
            });
        }
        if self.operation_mappings.len() > MAX_MAPPINGS_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "operation_mappings",
                count: self.operation_mappings.len(),
                max: MAX_MAPPINGS_COUNT,
            });
        }

        let mut hasher = Sha256Hasher::new();
        hasher.update(PROVIDER_PRICING_MANIFEST_DOMAIN.as_bytes());
        hasher.update(&PROVIDER_PRICING_MANIFEST_MAGIC);
        hasher.update(&self.manifest_version.to_be_bytes());
        hasher.update(self.provider_id.as_bytes());
        hasher.update(self.pricing_tier.as_bytes());
        hasher.update(self.currency.as_bytes());
        hasher.update(self.provenance.source.as_bytes());
        hasher.update(&self.provenance.retrieved_at.0.to_be_bytes());
        hasher.update(&self.provenance.validity_window.earliest.0.to_be_bytes());
        hasher.update(&self.provenance.validity_window.latest.0.to_be_bytes());

        if let Some(witness) = self.provenance.retrieval_witness {
            hasher.update(&[1]);
            hasher.update(&witness.bytes());
        } else {
            hasher.update(&[0]);
        }
        hasher.update(&[provenance_class_to_u8(self.provenance.provenance_class)]);

        if let Some(supersedes) = self.supersedes_manifest {
            hasher.update(&[1]);
            hasher.update(&supersedes.bytes());
        } else {
            hasher.update(&[0]);
        }

        let rates_count = match u32::try_from(self.rates.len()) {
            Ok(count) => count,
            Err(_) => {
                return Err(PricingManifestError::OverLimit {
                    field: "rates",
                    count: self.rates.len(),
                    max: MAX_RATES_COUNT,
                });
            }
        };
        hasher.update(&rates_count.to_be_bytes());
        for r in &self.rates {
            hasher.update(&[r.cost_class.as_u8()]);
            if let Some(op) = &r.operation_name {
                hasher.update(&[1]);
                hasher.update(op.as_bytes());
            } else {
                hasher.update(&[0]);
            }
            hasher.update(&[r.unit.as_u8()]);
            hasher.update(&r.rate_pico_currency.to_be_bytes());
            if let Some(free) = r.free_tier_allowance {
                hasher.update(&[1]);
                hasher.update(&free.to_be_bytes());
            } else {
                hasher.update(&[0]);
            }
            if let Some(min_u) = r.minimum_billable_unit {
                hasher.update(&[1]);
                hasher.update(&min_u.to_be_bytes());
            } else {
                hasher.update(&[0]);
            }
        }

        let mappings_count = match u32::try_from(self.operation_mappings.len()) {
            Ok(count) => count,
            Err(_) => {
                return Err(PricingManifestError::OverLimit {
                    field: "operation_mappings",
                    count: self.operation_mappings.len(),
                    max: MAX_MAPPINGS_COUNT,
                });
            }
        };
        hasher.update(&mappings_count.to_be_bytes());
        for m in &self.operation_mappings {
            hasher.update(m.provider_operation.as_bytes());
            hasher.update(&[m.cost_class.as_u8()]);
        }

        let bytes = hasher.finalize().map_err(PricingManifestError::Contract)?;
        Ok(ContentDigest::new(DigestAlgorithm::Sha256, bytes))
    }

    /// Encodes into a canonical byte envelope, returning typed [`PricingManifestError::OverLimit`] if bounds are exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, PricingManifestError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical_checked(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Decodes from a canonical byte envelope, verifying canonical sort and bound invariants.
    pub fn decode(bytes: &[u8]) -> Result<Self, PricingManifestError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let manifest = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(manifest)
    }

    /// Canonical encoding with explicit boundary checking.
    pub fn encode_canonical_checked(
        &self,
        encoder: &mut CanonicalEncoder,
    ) -> Result<(), PricingManifestError> {
        if self.rates.len() > MAX_RATES_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "rates",
                count: self.rates.len(),
                max: MAX_RATES_COUNT,
            });
        }
        if self.operation_mappings.len() > MAX_MAPPINGS_COUNT {
            return Err(PricingManifestError::OverLimit {
                field: "operation_mappings",
                count: self.operation_mappings.len(),
                max: MAX_MAPPINGS_COUNT,
            });
        }

        encoder.bytes(&PROVIDER_PRICING_MANIFEST_MAGIC);
        encoder.text(PROVIDER_PRICING_MANIFEST_DOMAIN);
        encoder.u32(self.manifest_version);
        encoder.text(&self.provider_id);
        encoder.text(&self.pricing_tier);
        encoder.text(&self.currency);

        // Provenance
        encoder.text(&self.provenance.source);
        self.provenance.retrieved_at.encode_canonical(encoder);
        self.provenance.validity_window.encode_canonical(encoder);
        if let Some(witness) = self.provenance.retrieval_witness {
            encoder.tag(1);
            witness.encode_canonical(encoder);
        } else {
            encoder.tag(0);
        }
        encoder.tag(provenance_class_to_u8(self.provenance.provenance_class));

        // Supersedes
        if let Some(supersedes) = self.supersedes_manifest {
            encoder.tag(1);
            supersedes.encode_canonical(encoder);
        } else {
            encoder.tag(0);
        }

        // Rates
        let rates_count = match u32::try_from(self.rates.len()) {
            Ok(count) => count,
            Err(_) => {
                return Err(PricingManifestError::OverLimit {
                    field: "rates",
                    count: self.rates.len(),
                    max: MAX_RATES_COUNT,
                });
            }
        };
        encoder.u32(rates_count);
        for r in &self.rates {
            encoder.tag(r.cost_class.as_u8());
            if let Some(op) = &r.operation_name {
                encoder.tag(1);
                encoder.text(op);
            } else {
                encoder.tag(0);
            }
            encoder.tag(r.unit.as_u8());
            encoder.bytes(&r.rate_pico_currency.to_be_bytes());
            if let Some(free) = r.free_tier_allowance {
                encoder.tag(1);
                encoder.u64(free);
            } else {
                encoder.tag(0);
            }
            if let Some(min_u) = r.minimum_billable_unit {
                encoder.tag(1);
                encoder.u64(min_u);
            } else {
                encoder.tag(0);
            }
        }

        // Operation mappings
        let mappings_count = match u32::try_from(self.operation_mappings.len()) {
            Ok(count) => count,
            Err(_) => {
                return Err(PricingManifestError::OverLimit {
                    field: "operation_mappings",
                    count: self.operation_mappings.len(),
                    max: MAX_MAPPINGS_COUNT,
                });
            }
        };
        encoder.u32(mappings_count);
        for m in &self.operation_mappings {
            encoder.text(&m.provider_operation);
            encoder.tag(m.cost_class.as_u8());
        }

        Ok(())
    }
}

impl CanonicalEncode for ProviderPricingManifest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let _ = self.encode_canonical_checked(encoder);
    }
}

impl CanonicalDecode for ProviderPricingManifest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let magic_bytes = decoder.bytes()?;
        if magic_bytes != PROVIDER_PRICING_MANIFEST_MAGIC.as_slice() {
            return Err(ContractError::InvalidDigest);
        }

        let domain = decoder.text()?;
        if domain != PROVIDER_PRICING_MANIFEST_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }

        let manifest_version = decoder.u32()?;
        if manifest_version != PROVIDER_PRICING_MANIFEST_VERSION_1 {
            return Err(ContractError::InvalidIdentifier);
        }

        let provider_id = decoder.text()?.to_string();
        if provider_id.len() < MIN_PROVIDER_ID_LEN || provider_id.len() > MAX_PROVIDER_ID_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if reject_latest_alias(&provider_id, "provider_id").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }

        let pricing_tier = decoder.text()?.to_string();
        if pricing_tier.len() < MIN_TIER_LEN || pricing_tier.len() > MAX_TIER_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if reject_latest_alias(&pricing_tier, "pricing_tier").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }

        let currency = decoder.text()?.to_string();
        if currency.len() < MIN_CURRENCY_LEN || currency.len() > MAX_CURRENCY_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if !currency.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(ContractError::InvalidIdentifier);
        }

        // Provenance
        let source = decoder.text()?.to_string();
        if source.len() < MIN_SOURCE_LEN || source.len() > MAX_SOURCE_LEN {
            return Err(ContractError::InvalidIdentifier);
        }
        if reject_latest_alias(&source, "source").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }

        let retrieved_at = TimestampNs::decode_canonical(decoder)?;
        let validity_window = CaptureInterval::decode_canonical(decoder)?;
        if validity_window.earliest > validity_window.latest {
            return Err(ContractError::InvertedTimeInterval);
        }

        let witness_tag = decoder.tag()?;
        let retrieval_witness = match witness_tag {
            0 => None,
            1 => Some(ContentDigest::decode_canonical(decoder)?),
            _ => return Err(ContractError::InvalidDigest),
        };

        let prov_tag = decoder.tag()?;
        let provenance_class = provenance_class_from_u8(prov_tag)?;

        let provenance = PricingProvenance {
            source,
            retrieved_at,
            validity_window,
            retrieval_witness,
            provenance_class,
        };

        // Supersedes
        let supersedes_tag = decoder.tag()?;
        let supersedes_manifest = match supersedes_tag {
            0 => None,
            1 => Some(ContentDigest::decode_canonical(decoder)?),
            _ => return Err(ContractError::InvalidDigest),
        };

        // Rates
        let rates_count = decoder.u32()? as usize;
        if rates_count > MAX_RATES_COUNT {
            return Err(ContractError::InvalidIdentifier);
        }

        let mut rates = Vec::with_capacity(rates_count);
        for _ in 0..rates_count {
            let cc_tag = decoder.tag()?;
            let cost_class =
                CostClass::from_u8(cc_tag).map_err(|_| ContractError::InvalidIdentifier)?;

            let op_tag = decoder.tag()?;
            let operation_name = match op_tag {
                0 => None,
                1 => {
                    let op = decoder.text()?.to_string();
                    if op.len() < MIN_OPERATION_LEN || op.len() > MAX_OPERATION_LEN {
                        return Err(ContractError::InvalidIdentifier);
                    }
                    if reject_latest_alias(&op, "operation_name").is_err() {
                        return Err(ContractError::InvalidIdentifier);
                    }
                    Some(op)
                }
                _ => return Err(ContractError::InvalidIdentifier),
            };

            let unit_tag = decoder.tag()?;
            let unit =
                PricingUnit::from_u8(unit_tag).map_err(|_| ContractError::InvalidIdentifier)?;

            let rate_bytes = decoder.bytes()?;
            let rate_slice: [u8; 16] = rate_bytes
                .try_into()
                .map_err(|_| ContractError::InvalidDigest)?;
            let rate_pico_currency = u128::from_be_bytes(rate_slice);

            let free_tag = decoder.tag()?;
            let free_tier_allowance = match free_tag {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(ContractError::InvalidIdentifier),
            };

            let min_u_tag = decoder.tag()?;
            let minimum_billable_unit = match min_u_tag {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(ContractError::InvalidIdentifier),
            };

            rates.push(DatedPriceRate {
                cost_class,
                operation_name,
                unit,
                rate_pico_currency,
                free_tier_allowance,
                minimum_billable_unit,
            });
        }

        // Verify strictly canonical order and no duplicate rates
        for window in rates.windows(2) {
            let key_a = window[0].canonical_key();
            let key_b = window[1].canonical_key();
            if key_a >= key_b {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }

        // Operation mappings
        let mappings_count = decoder.u32()? as usize;
        if mappings_count > MAX_MAPPINGS_COUNT {
            return Err(ContractError::InvalidIdentifier);
        }

        let mut operation_mappings = Vec::with_capacity(mappings_count);
        for _ in 0..mappings_count {
            let provider_operation = decoder.text()?.to_string();
            if provider_operation.len() < MIN_OPERATION_LEN
                || provider_operation.len() > MAX_OPERATION_LEN
            {
                return Err(ContractError::InvalidIdentifier);
            }
            if reject_latest_alias(&provider_operation, "provider_operation").is_err() {
                return Err(ContractError::InvalidIdentifier);
            }

            let cc_tag = decoder.tag()?;
            let cost_class =
                CostClass::from_u8(cc_tag).map_err(|_| ContractError::InvalidIdentifier)?;

            operation_mappings.push(OperationCostMapping {
                provider_operation,
                cost_class,
            });
        }

        // Verify strictly canonical order and no duplicate mappings
        for window in operation_mappings.windows(2) {
            if window[0].provider_operation >= window[1].provider_operation {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }

        let mut manifest = Self {
            manifest_version,
            provider_id,
            pricing_tier,
            currency,
            provenance,
            supersedes_manifest,
            rates,
            operation_mappings,
            manifest_digest: ContentDigest::sha256(&[]),
        };

        manifest.manifest_digest = manifest
            .compute_manifest_digest()
            .map_err(|_| ContractError::InvalidDigest)?;
        Ok(manifest)
    }
}

/// Errors occurring during pricing rate lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PriceLookupError {
    /// Query time precedes the manifest validity window.
    Premature {
        /// Earliest validity timestamp.
        valid_from: TimestampNs,
        /// Query timestamp.
        query_time: TimestampNs,
    },
    /// Query time is after the manifest validity window has expired.
    Stale {
        /// Latest validity timestamp.
        expired_at: TimestampNs,
        /// Query timestamp.
        query_time: TimestampNs,
    },
    /// Pricing provenance is uncertified, synthetic, or unrecognized.
    UnknownProvenance {
        /// Explanation of provenance deficiency.
        reason: String,
    },
    /// The requested cost class was not configured in this manifest.
    CostClassNotFound {
        /// Cost class requested.
        cost_class: CostClass,
    },
    /// The requested provider operation has no registered cost mapping.
    UnmappedOperation {
        /// Operation requested.
        operation: String,
    },
    /// Arithmetic overflow occurred in cost calculations.
    ArithmeticOverflow,
}

impl fmt::Display for PriceLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Premature {
                valid_from,
                query_time,
            } => {
                write!(
                    f,
                    "pricing lookup premature: valid from {valid_from}, queried at {query_time}"
                )
            }
            Self::Stale {
                expired_at,
                query_time,
            } => {
                write!(
                    f,
                    "pricing lookup stale/expired: validity ended at {expired_at}, queried at {query_time}"
                )
            }
            Self::UnknownProvenance { reason } => {
                write!(
                    f,
                    "pricing lookup rejected for unknown provenance: {reason}"
                )
            }
            Self::CostClassNotFound { cost_class } => {
                write!(
                    f,
                    "cost class not configured in pricing manifest: {cost_class}"
                )
            }
            Self::UnmappedOperation { operation } => {
                write!(
                    f,
                    "provider operation has no registered cost mapping: {operation}"
                )
            }
            Self::ArithmeticOverflow => {
                f.write_str("arithmetic overflow in pricing rate calculation")
            }
        }
    }
}

impl Error for PriceLookupError {}

/// Errors occurring during pricing manifest construction, validation, or canonical decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricingManifestError {
    /// Bad envelope magic prefix.
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 4],
        /// Actual magic bytes found.
        actual: [u8; 4],
    },
    /// Unsupported manifest version.
    UnsupportedVersion {
        /// Actual version found.
        actual: u32,
    },
    /// Rejection of floating "latest" alias.
    LatestNotResolvable {
        /// Field name containing the prohibited alias.
        field: &'static str,
    },
    /// String field length exceeds bounds.
    StringLengthOutOfBounds {
        /// Field name.
        field: &'static str,
        /// Actual byte length.
        length: usize,
        /// Minimum permitted length.
        min: usize,
        /// Maximum permitted length.
        max: usize,
    },
    /// List item count exceeds maximum permitted limit.
    OverLimit {
        /// Field name.
        field: &'static str,
        /// Actual item count.
        count: usize,
        /// Maximum permitted count.
        max: usize,
    },
    /// Inverted validity window (`earliest > latest`).
    InvertedValidityWindow {
        /// Earliest timestamp.
        earliest: TimestampNs,
        /// Latest timestamp.
        latest: TimestampNs,
    },
    /// Duplicate rate declared for the same cost class and operation.
    DuplicateRate {
        /// Cost class.
        cost_class: CostClass,
        /// Optional operation name.
        operation_name: Option<String>,
    },
    /// Duplicate operation mapping declared.
    DuplicateOperationMapping {
        /// Operation string that was duplicated.
        operation: String,
    },
    /// Non-canonical sorted order.
    NonCanonicalOrder {
        /// Field or collection name.
        field: &'static str,
    },
    /// Currency code is not valid uppercase ASCII.
    CurrencyCodeInvalid {
        /// Invalid currency string.
        code: String,
    },
    /// Invalid canonical tag.
    InvalidTag {
        /// Field name.
        field: &'static str,
        /// Tag byte encountered.
        tag: u8,
    },
    /// Canonical contract error.
    Contract(ContractError),
}

impl fmt::Display for PricingManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { expected, actual } => {
                write!(
                    f,
                    "pricing manifest bad magic: expected {expected:?}, found {actual:?}"
                )
            }
            Self::UnsupportedVersion { actual } => {
                write!(f, "pricing manifest unsupported version: {actual}")
            }
            Self::LatestNotResolvable { field } => {
                write!(
                    f,
                    "pricing manifest field '{field}' contains forbidden floating alias 'latest'"
                )
            }
            Self::StringLengthOutOfBounds {
                field,
                length,
                min,
                max,
            } => {
                write!(
                    f,
                    "pricing manifest field '{field}' length {length} out of bounds [{min}..={max}]"
                )
            }
            Self::OverLimit { field, count, max } => {
                write!(
                    f,
                    "pricing manifest list '{field}' count {count} exceeds maximum {max}"
                )
            }
            Self::InvertedValidityWindow { earliest, latest } => {
                write!(
                    f,
                    "pricing manifest inverted validity window: {earliest} > {latest}"
                )
            }
            Self::DuplicateRate {
                cost_class,
                operation_name,
            } => {
                write!(
                    f,
                    "pricing manifest duplicate rate for {cost_class} (op: {operation_name:?})"
                )
            }
            Self::DuplicateOperationMapping { operation } => {
                write!(
                    f,
                    "pricing manifest duplicate mapping for operation '{operation}'"
                )
            }
            Self::NonCanonicalOrder { field } => {
                write!(
                    f,
                    "pricing manifest list '{field}' is not in strict canonical sorted order"
                )
            }
            Self::CurrencyCodeInvalid { code } => {
                write!(f, "pricing manifest invalid currency code: '{code}'")
            }
            Self::InvalidTag { field, tag } => {
                write!(f, "pricing manifest invalid tag {tag} for field '{field}'")
            }
            Self::Contract(err) => write!(f, "pricing manifest contract error: {err}"),
        }
    }
}

impl Error for PricingManifestError {}

impl From<ContractError> for PricingManifestError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}
