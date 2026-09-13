//! Immutable semantic handles and bounded progressive evidence hydration.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    CaptureInterval, Completeness, ContentDigest, ContinuationCursor, ContinuationError,
    ContinuationScope, ContractBasis, ContractError, LedgerAnchor, RecoveryClass, SessionId,
    TimestampNs,
};

const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of capability grants or authorized privacy classes in one hydration request.
pub const MAX_REQUEST_SET_ITEMS: usize = 1_024;
/// Registered hydration view used by exact continuation cursors.
pub const HYDRATION_VIEW_ID: &str = "AVIEW-HYDRATION";

mod admission;
mod artifact;
mod error;
pub mod h4;
mod handle;
mod receipt;
mod request;

pub use artifact::HydrationArtifact;
pub use error::HydrationError;
pub use h4::{
    AlternateSystem, H4LaboratoryExpansion, H4LaboratoryExpansionParams, H4_CONTENT,
    H4_LEVEL_ID, H4_LEVEL_NAME, H4_OWNER, H4_SCHEMA, IntermediateArtifact,
    LaboratoryQuarantine, OracleComparison, ReplayBundleRef, MAX_H4_ALTERNATE_SYSTEMS,
    MAX_H4_IDENTIFIER_LEN, MAX_H4_INTERMEDIATES, MAX_H4_METADATA_LEN,
    MAX_H4_ORACLE_COMPARISONS, MAX_H4_PROOF_ROOTS,
};
pub use handle::{SemanticHandle, SemanticHandleSpec};
pub use receipt::{HydrationReceipt, HydrationReceiptSpec, HydrationResponse};
pub use request::{HydrationRequest, HydrationRequestSpec};

/// Progressive hydration level for one immutable semantic subject.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HydrationLevel {
    /// Identity, bounds, source, availability, cost, and authority only.
    H0,
    /// Typed semantic synopsis, provenance, contradictions, quality, and omissions.
    H1,
    /// Redacted decision artifact such as a crop, keyframe, trajectory, or graph neighborhood.
    H2,
    /// Authorized source evidence such as exact packets, object bytes, or full-resolution media.
    H3,
    /// Qualification or explicitly granted debugging expansion.
    H4,
}

impl HydrationLevel {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H0 => "H0",
            Self::H1 => "H1",
            Self::H2 => "H2",
            Self::H3 => "H3",
            Self::H4 => "H4",
        }
    }

    /// Returns the monotone ladder ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::H0 => 0,
            Self::H1 => 1,
            Self::H2 => 2,
            Self::H3 => 3,
            Self::H4 => 4,
        }
    }

    /// Resolves one ladder ordinal.
    #[must_use]
    pub const fn from_ordinal(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::H0),
            1 => Some(Self::H1),
            2 => Some(Self::H2),
            3 => Some(Self::H3),
            4 => Some(Self::H4),
            _ => None,
        }
    }

    /// Returns the next richer level.
    #[must_use]
    pub const fn successor(self) -> Option<Self> {
        Self::from_ordinal(self.ordinal() + 1)
    }
}

impl CanonicalEncode for HydrationLevel {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for HydrationLevel {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.text()? {
            "H0" => Ok(Self::H0),
            "H1" => Ok(Self::H1),
            "H2" => Ok(Self::H2),
            "H3" => Ok(Self::H3),
            "H4" => Ok(Self::H4),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Availability state of the exact subject named by a semantic handle descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HandleAvailability {
    /// The exact subject is currently available for authorized hydration.
    Available,
    /// A newer subject exists, but this handle still denotes the older exact subject.
    Superseded,
    /// The exact subject was deleted under an authoritative deletion record.
    Deleted,
    /// The retention horizon elapsed.
    Expired,
    /// Integrity verification failed for the exact subject.
    Corrupt,
    /// Only a distinct privacy-transformed derivative remains available.
    PrivacyTransformed,
    /// The requested subject could not be observed or materialized.
    NotObservable,
}

impl HandleAvailability {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Superseded => "superseded",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
            Self::Corrupt => "corrupt",
            Self::PrivacyTransformed => "privacy_transformed",
            Self::NotObservable => "not_observable",
        }
    }

    /// Returns the conservative response completeness for an unavailable subject.
    #[must_use]
    pub const fn unavailable_completeness(self) -> Completeness {
        match self {
            Self::Available => Completeness::Complete,
            Self::Superseded | Self::Expired => Completeness::Stale,
            Self::Deleted | Self::Corrupt | Self::NotObservable => Completeness::NotObservable,
            Self::PrivacyTransformed => Completeness::Unauthorized,
        }
    }
}

impl CanonicalEncode for HandleAvailability {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for HandleAvailability {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.text()? {
            "available" => Ok(Self::Available),
            "superseded" => Ok(Self::Superseded),
            "deleted" => Ok(Self::Deleted),
            "expired" => Ok(Self::Expired),
            "corrupt" => Ok(Self::Corrupt),
            "privacy_transformed" => Ok(Self::PrivacyTransformed),
            "not_observable" => Ok(Self::NotObservable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Why H4 laboratory material is being requested.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HydrationPurpose {
    /// Routine mission reasoning.
    Routine,
    /// Human or agent incident adjudication.
    IncidentAdjudication,
    /// Retained qualification or differential test execution.
    Qualification,
    /// Explicitly granted debugging.
    Debugging,
}

impl HydrationPurpose {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::IncidentAdjudication => "incident_adjudication",
            Self::Qualification => "qualification",
            Self::Debugging => "debugging",
        }
    }
}

impl CanonicalEncode for HydrationPurpose {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for HydrationPurpose {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.text()? {
            "routine" => Ok(Self::Routine),
            "incident_adjudication" => Ok(Self::IncidentAdjudication),
            "qualification" => Ok(Self::Qualification),
            "debugging" => Ok(Self::Debugging),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Policy governing H4 laboratory expansion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LaboratoryAccess {
    /// H4 is not published for this subject.
    Unavailable,
    /// H4 is restricted to qualification runs.
    QualificationOnly,
    /// H4 is available to qualification or an explicit debugging grant.
    QualificationOrDebugGrant,
}

impl LaboratoryAccess {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::QualificationOnly => "qualification_only",
            Self::QualificationOrDebugGrant => "qualification_or_debug_grant",
        }
    }
}

impl CanonicalEncode for LaboratoryAccess {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for LaboratoryAccess {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.text()? {
            "unavailable" => Ok(Self::Unavailable),
            "qualification_only" => Ok(Self::QualificationOnly),
            "qualification_or_debug_grant" => Ok(Self::QualificationOrDebugGrant),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

fn validate_contiguous_levels(levels: &BTreeSet<HydrationLevel>) -> Result<(), HydrationError> {
    let Some(maximum) = levels.last().copied() else {
        return Err(HydrationError::LevelUnavailable);
    };
    for ordinal in 0..=maximum.ordinal() {
        let level =
            HydrationLevel::from_ordinal(ordinal).ok_or(HydrationError::LevelUnavailable)?;
        if !levels.contains(&level) {
            return Err(HydrationError::LevelUnavailable);
        }
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn encode_optional_interval(value: Option<CaptureInterval>, encoder: &mut CanonicalEncoder) {
    match value {
        Some(interval) => {
            encoder.bool(true);
            interval.encode_canonical(encoder);
        }
        None => encoder.bool(false),
    }
}

fn encode_optional_text(value: Option<&str>, encoder: &mut CanonicalEncoder) {
    match value {
        Some(text) => {
            encoder.bool(true);
            encoder.text(text);
        }
        None => encoder.bool(false),
    }
}

fn encode_levels(values: &BTreeSet<HydrationLevel>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        value.encode_canonical(encoder);
    }
}

fn encode_capability_map(
    values: &BTreeMap<HydrationLevel, BTreeSet<String>>,
    encoder: &mut CanonicalEncoder,
) {
    encoder.u64(values.len() as u64);
    for (level, capabilities) in values {
        level.encode_canonical(encoder);
        encode_text_set(capabilities, encoder);
    }
}

fn encode_cost_map(
    values: &BTreeMap<HydrationLevel, BudgetVector>,
    encoder: &mut CanonicalEncoder,
) {
    encoder.u64(values.len() as u64);
    for (level, cost) in values {
        level.encode_canonical(encoder);
        encode_budget(*cost, encoder);
    }
}

fn encode_text_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_digest_set(values: &BTreeSet<ContentDigest>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.digest(*value);
    }
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    value.encode_to_canonical(encoder);
}

fn completeness_code(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 1,
        Completeness::Bounded => 2,
        Completeness::Partial => 3,
        Completeness::Unknown => 4,
        Completeness::NotObservable => 5,
        Completeness::Unauthorized => 6,
        Completeness::Stale => 7,
    }
}

#[cfg(test)]
mod tests;
