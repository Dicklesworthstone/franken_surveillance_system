#![forbid(unsafe_code)]
//! Deterministic payload-proportional token, byte, and storage/decode-work pricing for H0..=H3.
//!
//! Legacy H0/H1 fixed quotes (`5_000` / `16_000` tokens) remain intact under [`PricingProfile::LegacyV1`]
//! so existing pinned H0/H1 contracts stay byte-compatible. H2 and H3 (and opt-in v2 H0/H1) use
//! [`PricingProfile::PayloadProportionalV2`], pricing tokens deterministically as
//! `ceil(serialized_bytes / 4)` alongside explicit byte and storage-operation charges.

use fss_core::{BudgetVector, HydrationLevel};
use fss_reference::agent_event_hydration::{
    EVENT_HYDRATION_H0_TOKENS, EVENT_HYDRATION_H1_TOKENS, MAX_EVENT_HYDRATION_READ_BYTES,
    MAX_EVENT_HYDRATION_READ_OBJECTS,
};

use super::HydrationError;
use crate::agent_json;
use crate::json_output::{object, string};

/// Pricing strategy applied to compute a hydration [`BudgetVector`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PricingProfile {
    /// Existing pinned H0/H1 fixed-quote model (falls back to v2 for H2/H3).
    LegacyV1,
    /// Deterministic payload-proportional token pricing (`ceil(serialized_bytes / 4)`).
    PayloadProportionalV2,
}

impl PricingProfile {
    /// Stable non-localized identifier for receipts and budget reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyV1 => "legacy_v1",
            Self::PayloadProportionalV2 => "payload_proportional_v2",
        }
    }
}

/// Measured inputs feeding deterministic hydration cost accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HydrationCostInputs {
    /// Delivered hydration level.
    pub level: HydrationLevel,
    /// Serialized UTF-8 JSON payload size in bytes.
    pub serialized_bytes: usize,
    /// Bounded retained-source storage read attempts performed.
    pub storage_reads: u64,
    /// Retained source/media bytes read during hydration.
    pub media_bytes_read: u64,
    /// Deterministic codec decode work units charged (0 for H0/H1/H2).
    pub decode_work_units: u64,
    /// Deterministic codec encode work units charged (0 for H0/H1/H2).
    pub encode_work_units: u64,
    /// Number of visual frames returned (0 for H0/H1/H2).
    pub frame_count: usize,
}

/// Complete deterministic hydration cost report bound into H2/H3 outputs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HydrationBudgetReport {
    /// Active pricing profile label.
    pub pricing_profile: &'static str,
    /// Serialized payload byte length used for token pricing.
    pub serialized_bytes: usize,
    /// Deterministic token charge (`ceil(serialized_bytes / 4)` under v2).
    pub payload_tokens: u64,
    /// Source media bytes read from retained custody.
    pub media_bytes_read: u64,
    /// Storage read operations performed.
    pub storage_operations: u64,
    /// Deterministic codec decode work units consumed.
    pub decode_work_units: u64,
    /// Deterministic codec encode work units consumed.
    pub encode_work_units: u64,
    /// Canonical `fss-core` budget vector.
    pub vector: BudgetVector,
}

impl HydrationBudgetReport {
    /// Renders this budget report as deterministic JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&[
            ("pricingProfile", string(self.pricing_profile)),
            ("serializedBytes", self.serialized_bytes.to_string()),
            ("payloadTokens", self.payload_tokens.to_string()),
            ("mediaBytesRead", self.media_bytes_read.to_string()),
            ("storageOperations", self.storage_operations.to_string()),
            ("decodeWorkUnits", self.decode_work_units.to_string()),
            ("encodeWorkUnits", self.encode_work_units.to_string()),
            ("budgetVector", agent_json::budget(&self.vector)),
        ])
    }
}

/// Computes deterministic token cost as `ceil(serialized_bytes / 4)` (0 for empty payload).
#[must_use]
pub const fn estimate_payload_tokens(serialized_bytes: usize) -> u64 {
    (serialized_bytes as u64).div_ceil(4)
}

/// Computes the canonical [`HydrationBudgetReport`] for H0, H1, H2, or H3.
pub fn compute_budget(
    profile: PricingProfile,
    inputs: &HydrationCostInputs,
) -> Result<HydrationBudgetReport, HydrationError> {
    let effective_profile = match (profile, inputs.level) {
        (PricingProfile::LegacyV1, HydrationLevel::H0 | HydrationLevel::H1) => {
            PricingProfile::LegacyV1
        }
        _ => PricingProfile::PayloadProportionalV2,
    };

    let (tokens, bytes, storage_ops, privacy_exposure) = match effective_profile {
        PricingProfile::LegacyV1 => {
            let fixed_tokens = match inputs.level {
                HydrationLevel::H0 => EVENT_HYDRATION_H0_TOKENS,
                HydrationLevel::H1 => EVENT_HYDRATION_H1_TOKENS,
                _ => estimate_payload_tokens(inputs.serialized_bytes),
            };
            (
                fixed_tokens,
                MAX_EVENT_HYDRATION_READ_BYTES as u64,
                MAX_EVENT_HYDRATION_READ_OBJECTS as u64,
                0.0,
            )
        }
        PricingProfile::PayloadProportionalV2 => {
            let payload_tokens = estimate_payload_tokens(inputs.serialized_bytes);
            let total_bytes =
                (inputs.serialized_bytes as u64).saturating_add(inputs.media_bytes_read);
            let privacy = match inputs.level {
                HydrationLevel::H0 | HydrationLevel::H1 => 0.0,
                HydrationLevel::H2 => 0.25,
                HydrationLevel::H3 => 0.50,
                HydrationLevel::H4 => 1.0,
            };
            (payload_tokens, total_bytes, inputs.storage_reads, privacy)
        }
    };

    let vector = BudgetVector::builder()
        .tokens(tokens)
        .bytes(bytes)
        .storage_operations(storage_ops)
        .privacy_exposure(privacy_exposure)
        .build()
        .map_err(|_| {
            HydrationError::BoundsExceeded("hydration budget vector failed contract bounds".into())
        })?;

    Ok(HydrationBudgetReport {
        pricing_profile: effective_profile.as_str(),
        serialized_bytes: inputs.serialized_bytes,
        payload_tokens: tokens,
        media_bytes_read: inputs.media_bytes_read,
        storage_operations: storage_ops,
        decode_work_units: inputs.decode_work_units,
        encode_work_units: inputs.encode_work_units,
        vector,
    })
}
