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
mod h0;
mod handle;
mod receipt;
mod request;

pub use artifact::HydrationArtifact;
pub use error::HydrationError;
pub use h0::{
    H0_CONTENT, H0_LEVEL_ID, H0_LEVEL_NAME, H0_SCHEMA, H0_SEMANTIC_OWNER, H0Identity,
    H0IdentityParams, is_valid_h0_screened_field,
};
pub use handle::{SemanticHandle, SemanticHandleSpec};
pub use receipt::{HydrationReceipt, HydrationReceiptSpec, HydrationResponse};
pub use request::{HydrationRequest, HydrationRequestSpec};

/// Normative semantic owner declared in `architecture/semantic_hydration.json`.
pub const SEMANTIC_HYDRATION_OWNER: &str = "fss-agent-core";

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
    /// All 5 normative hydration ladder levels in progressive order.
    pub const ALL: [Self; 5] = [Self::H0, Self::H1, Self::H2, Self::H3, Self::H4];

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

    /// Returns the stable identifier (e.g. `H0`).
    #[must_use]
    pub const fn level_id(self) -> &'static str {
        self.as_str()
    }

    /// Returns the stable registry name for this level.
    #[must_use]
    pub const fn level_name(self) -> &'static str {
        match self {
            Self::H0 => "identity",
            Self::H1 => "semantic_synopsis",
            Self::H2 => "decision_artifact",
            Self::H3 => "source_evidence",
            Self::H4 => "laboratory_expansion",
        }
    }

    /// Returns the exact normative content declaration from the agent abstraction registry.
    #[must_use]
    pub const fn content(self) -> &'static str {
        match self {
            Self::H0 => {
                "digest, type, time/spatial bounds, source, availability, cost, and authority"
            }
            Self::H1 => {
                "typed facts, knowledge states, provenance, contradictions, quality, and omissions"
            }
            Self::H2 => {
                "authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features"
            }
            Self::H3 => {
                "authorized original encoded packets, object bytes, exact metadata, or full-resolution media"
            }
            Self::H4 => {
                "replay bundle, intermediates, alternate decoders/models, and oracle comparisons"
            }
        }
    }

    /// Returns the owning subsystem for this hydration level.
    ///
    /// Per `architecture/semantic_hydration.json`, `semantic_owner` is `"fss-agent-core"`
    /// for the entire hydration ladder (`H0`..=`H4`).
    #[must_use]
    pub const fn owner(self) -> &'static str {
        SEMANTIC_HYDRATION_OWNER
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

impl core::str::FromStr for HydrationLevel {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "H0" => Ok(Self::H0),
            "H1" => Ok(Self::H1),
            "H2" => Ok(Self::H2),
            "H3" => Ok(Self::H3),
            "H4" => Ok(Self::H4),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for HydrationLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.as_str(), self.level_name())
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
    /// All 7 normative availability states.
    pub const ALL: [Self; 7] = [
        Self::Available,
        Self::Superseded,
        Self::Deleted,
        Self::Expired,
        Self::Corrupt,
        Self::PrivacyTransformed,
        Self::NotObservable,
    ];

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

impl core::str::FromStr for HandleAvailability {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
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

impl fmt::Display for HandleAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.chars().any(|c| {
            c.is_ascii_control()
                || ('\u{0080}'..='\u{009F}').contains(&c)
                || ('\u{202A}'..='\u{202E}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
                || ('\u{200B}'..='\u{200F}').contains(&c)
                || c == '\u{2028}'
                || c == '\u{2029}'
                || c == '\u{061C}'
                || c == '\u{FEFF}'
        })
}

pub(crate) fn encode_optional_interval(
    value: Option<CaptureInterval>,
    encoder: &mut CanonicalEncoder,
) {
    match value {
        Some(interval) => {
            encoder.bool(true);
            interval.encode_canonical(encoder);
        }
        None => encoder.bool(false),
    }
}

pub(crate) fn decode_optional_interval(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<CaptureInterval>, ContractError> {
    if decoder.bool()? {
        Ok(Some(CaptureInterval::decode_canonical(decoder)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn encode_optional_text(value: Option<&str>, encoder: &mut CanonicalEncoder) {
    match value {
        Some(text) => {
            encoder.bool(true);
            encoder.text(text);
        }
        None => encoder.bool(false),
    }
}

pub(crate) fn decode_optional_text<'a>(
    decoder: &mut CanonicalDecoder<'a>,
) -> Result<Option<&'a str>, ContractError> {
    if decoder.bool()? {
        Ok(Some(decoder.text()?))
    } else {
        Ok(None)
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

pub(crate) fn encode_text_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

pub(crate) fn decode_text_set(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<BTreeSet<String>, HydrationError> {
    let count_u64 = decoder.u64().map_err(|err| match err {
        ContractError::InvalidDigest => HydrationError::Truncated,
        other => HydrationError::Contract(other),
    })?;
    let count = usize::try_from(count_u64).map_err(|_| HydrationError::CapacityExceeded)?;
    if count > MAX_REQUEST_SET_ITEMS {
        return Err(HydrationError::CapacityExceeded);
    }
    if decoder.remaining() < count {
        return Err(HydrationError::Truncated);
    }
    let mut set = BTreeSet::new();
    let mut prev: Option<&str> = None;
    for _ in 0..count {
        let text = decoder.text().map_err(|err| match err {
            ContractError::InvalidDigest => HydrationError::Truncated,
            other => HydrationError::Contract(other),
        })?;
        if text.trim().is_empty() || !valid_text(text) {
            return Err(HydrationError::Contract(ContractError::InvalidIdentifier));
        }
        if let Some(p) = prev
            && p >= text
        {
            return Err(HydrationError::Contract(
                ContractError::NonCanonicalOrdering,
            ));
        }
        prev = Some(text);
        set.insert(text.to_string());
    }
    Ok(set)
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
