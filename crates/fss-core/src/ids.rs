//! Stable identifiers and generation newtypes used by the reference semantic kernel.

use core::fmt;
use core::ops::Deref;
use core::str::FromStr;
use std::collections::BTreeMap;

use crate::canonical::{CanonicalDecode, CanonicalDecoder};
use crate::{CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError};

/// Minimum allowed length for a stable identifier.
pub const MIN_STABLE_ID_LEN: usize = 1;

/// Maximum allowed length for a stable identifier.
pub const MAX_STABLE_ID_LEN: usize = 128;

/// Minimum allowed length for a subsystem generation identifier.
pub const MIN_SUBSYSTEM_GENERATION_LEN: usize = 8;

/// Maximum allowed length for a subsystem generation identifier.
pub const MAX_SUBSYSTEM_GENERATION_LEN: usize = 256;

/// Validates that an identifier matches the canonical portable alphabet:
/// non-empty, up to 128 ASCII alphanumeric characters or `'-'`, `'_'`, `'.'`. `':'`.
pub fn validate_id(value: &str) -> Result<(), ContractError> {
    if value.len() < MIN_STABLE_ID_LEN
        || value.len() > MAX_STABLE_ID_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Validates a subsystem generation identifier matching `^[a-z0-9][a-z0-9:+._-]{7,255}$`.
///
/// Under ADR-0004 and NEG-003, mutable aliases containing `latest` are strictly prohibited.
pub fn validate_subsystem_generation(value: &str) -> Result<(), ContractError> {
    if value.len() < MIN_SUBSYSTEM_GENERATION_LEN || value.len() > MAX_SUBSYSTEM_GENERATION_LEN {
        return Err(ContractError::InvalidIdentifier);
    }
    let bytes = value.as_bytes();
    let first = bytes[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(ContractError::InvalidIdentifier);
    }
    for &byte in &bytes[1..] {
        let valid = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b':' | b'+' | b'.' | b'_' | b'-');
        if !valid {
            return Err(ContractError::InvalidIdentifier);
        }
    }
    if is_latest_subsystem_generation_alias(value) {
        return Err(ContractError::LatestNotResolvable);
    }
    Ok(())
}

/// Detects whether a generation string contains a forbidden `latest` alias token (ADR-0004).
#[must_use]
pub fn is_latest_subsystem_generation_alias(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "latest" || lower == "latest.weights" {
        return true;
    }
    lower
        .split(|c: char| !c.is_alphanumeric())
        .any(|token| token == "latest")
}

macro_rules! stable_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses an identifier in the canonical portable alphabet.
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper and returns the inner String.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl CanonicalEncode for $name {
            fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
                encoder.text(&self.0);
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
                let text = decoder.text()?;
                Self::parse(text)
            }
        }
    };
}

// Core sensor and transport stable IDs
stable_id!(
    SensorId,
    "A stable opaque identifier for a configured sensor."
);
stable_id!(
    StreamId,
    "A stable opaque identifier for one logical stream generation."
);
stable_id!(
    CapsuleId,
    "A stable identifier for one immutable sensor capsule."
);
stable_id!(BatchId, "A stable identifier for one evidence delta batch.");
stable_id!(EventId, "A stable identifier for one event lineage.");
stable_id!(OperationId, "A stable identifier for one effect operation.");
stable_id!(
    IdempotencyKey,
    "A stable idempotency identity for replay-safe effects."
);
stable_id!(
    ObligationId,
    "A stable identifier for a terminal-proof obligation."
);
stable_id!(PrincipalId, "A stable principal identity.");
stable_id!(SessionId, "A stable agent session identity.");
stable_id!(MissionId, "A stable mission identity.");
stable_id!(HandoffId, "A stable handoff-capsule identity.");
stable_id!(ObjectId, "A stable object identity in the semantic ledger.");

// Additional architectural stable IDs
macro_rules! stable_id_with_prefix_alias {
    ($name:ident, $description:literal, $canonical_prefix:literal, $alt_prefix:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Canonical prefix for this identifier.
            pub const PREFIX: &'static str = $canonical_prefix;
            /// Alternative accepted prefix for this identifier.
            pub const ALT_PREFIX: &'static str = $alt_prefix;

            /// Parses an identifier in the canonical portable alphabet, normalizing any accepted alternative prefix.
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                let normalized = if let Some(suffix) = value.strip_prefix(Self::ALT_PREFIX) {
                    format!("{}{suffix}", Self::PREFIX)
                } else {
                    value
                };
                validate_id(&normalized)?;
                Ok(Self(normalized))
            }

            /// Creates an identifier from a suffix using the canonical prefix.
            pub fn from_suffix(suffix: &str) -> Result<Self, ContractError> {
                let text = format!("{}{suffix}", Self::PREFIX);
                Self::parse(text)
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper and returns the inner String.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl CanonicalEncode for $name {
            fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
                encoder.text(&self.0);
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
                let text = decoder.text()?;
                Self::parse(text)
            }
        }
    };
}

stable_id_with_prefix_alias!(
    SourceId,
    "A stable opaque identifier for an evidence source.",
    "src:",
    "source:"
);
stable_id_with_prefix_alias!(
    DeviceId,
    "A stable physical or virtual device identity.",
    "device:",
    "dev:"
);
stable_id_with_prefix_alias!(
    AdapterId,
    "A stable opaque identifier for a device adapter.",
    "adapter:",
    "adp:"
);

impl SourceId {
    /// Returns true if the identifier text begins with a recognized source prefix (`src:` or `source:`).
    #[must_use]
    pub fn has_source_prefix(&self) -> bool {
        self.as_str().starts_with(Self::PREFIX) || self.as_str().starts_with(Self::ALT_PREFIX)
    }
}

impl DeviceId {
    /// Returns true if the identifier text begins with a recognized device prefix (`device:` or `dev:`).
    #[must_use]
    pub fn has_device_prefix(&self) -> bool {
        self.as_str().starts_with(Self::PREFIX) || self.as_str().starts_with(Self::ALT_PREFIX)
    }
}

impl AdapterId {
    /// Returns true if the identifier text begins with a recognized adapter prefix (`adapter:` or `adp:`).
    #[must_use]
    pub fn has_adapter_prefix(&self) -> bool {
        self.as_str().starts_with(Self::PREFIX) || self.as_str().starts_with(Self::ALT_PREFIX)
    }
}
stable_id!(TrackId, "A stable tracked subject trajectory identity.");
stable_id!(CaseId, "A stable investigation case identity.");
stable_id!(HypothesisId, "A stable competing hypothesis identity.");
stable_id!(PlanId, "A stable agent control plan identity.");
stable_id!(EpisodeId, "A stable execution episode identity.");
stable_id!(FindingId, "A stable investigation finding identity.");
stable_id!(ContextPackId, "A stable context pack identity.");
stable_id!(WorkspaceId, "A stable agent workspace identity.");
stable_id!(AffordanceId, "A stable action affordance identity.");
stable_id!(PropertyId, "A stable property or installation identity.");
stable_id!(TombstoneId, "A stable tombstone record identity.");
stable_id!(SchemaId, "A stable schema version identifier.");
stable_id!(PolicyId, "A stable policy definition identifier.");

/// A monotonically increasing numeric revision generation.
///
/// Object generation starts at 1 (genesis) and increments strictly by 1
/// on every mutable revision. Stale generations and duplicate generations
/// cause [`ContractError::GenerationConflict`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(pub u64);

impl Generation {
    /// Genesis revision generation for any newly created object.
    pub const GENESIS: Self = Self(1);

    /// Special zero generation used for unversioned or uncommitted state.
    pub const UNVERSIONED: Self = Self(0);

    /// Constructs a generation from a raw `u64`.
    #[must_use]
    pub const fn from_u64(val: u64) -> Self {
        Self(val)
    }

    /// Returns the raw generation number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Parses a strictly positive generation (>= 1).
    pub fn parse_positive(val: u64) -> Result<Self, ContractError> {
        if val == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(val))
    }

    /// Computes the next monotonic successor generation (`self + 1`).
    ///
    /// Returns [`ContractError::GenerationConflict`] on overflow.
    pub fn next(self) -> Result<Self, ContractError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ContractError::GenerationConflict)
    }

    /// Returns true when `self` is the direct successor (`prior + 1`) of `prior`.
    #[must_use]
    pub fn is_successor_of(self, prior: Self) -> bool {
        prior.0 > 0 && self.0 == prior.0.saturating_add(1) && prior.0 < u64::MAX
    }

    /// Validates an MVCC transition from an optional prior generation to this generation.
    ///
    /// Creation requires `prior == None` and `self == GENESIS`.
    /// Modification requires `prior == Some(p)` with `p > 0` and `self == p.next()?`.
    pub fn validate_transition(prior: Option<Self>, current: Self) -> Result<(), ContractError> {
        match prior {
            None => {
                if current != Self::GENESIS {
                    return Err(ContractError::GenerationConflict);
                }
            }
            Some(p) => {
                if p.0 == 0 || !current.is_successor_of(p) {
                    return Err(ContractError::GenerationConflict);
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gen:{}", self.0)
    }
}

impl From<Generation> for u64 {
    fn from(generation: Generation) -> Self {
        generation.0
    }
}

impl CanonicalEncode for Generation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.0);
    }
}

impl CanonicalDecode for Generation {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.u64().map(Self)
    }
}

macro_rules! epoch_newtype {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u64);

        impl $name {
            /// Genesis epoch constant (1).
            pub const GENESIS: Self = Self(1);

            /// Zero epoch constant (0).
            pub const ZERO: Self = Self(0);

            /// Constructs an epoch from a raw `u64`.
            #[must_use]
            pub const fn from_u64(val: u64) -> Self {
                Self(val)
            }

            /// Returns the raw epoch number.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Computes the next epoch number (`self + 1`).
            pub fn next(self) -> Result<Self, ContractError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(ContractError::GenerationConflict)
            }

            /// Validates that `self` is monotonically non-decreasing with respect to `prior`.
            pub fn validate_monotonic(self, prior: Self) -> Result<(), ContractError> {
                if self.0 < prior.0 {
                    return Err(ContractError::InvalidAnchorSuccessor);
                }
                Ok(())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "epoch:{}", self.0)
            }
        }

        impl From<$name> for u64 {
            fn from(epoch: $name) -> Self {
                epoch.0
            }
        }

        impl CanonicalEncode for $name {
            fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
                encoder.u64(self.0);
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
                decoder.u64().map(Self)
            }
        }
    };
}

epoch_newtype!(Epoch, "A generic monotonic epoch counter.");
epoch_newtype!(SchemaEpoch, "Schema epoch counter.");
epoch_newtype!(PolicyEpoch, "Policy epoch counter.");
epoch_newtype!(AdapterEpoch, "Adapter registry epoch counter.");
epoch_newtype!(PrivacyEpoch, "Privacy epoch counter.");
epoch_newtype!(LedgerEpoch, "Ledger epoch counter.");

macro_rules! subsystem_generation {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses a subsystem generation identifier matching `^[a-z0-9][a-z0-9:+._-]{7,255}$`.
            pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_subsystem_generation(&value)?;
                Ok(Self(value))
            }

            /// Constructs an unvalidated identifier for testing defense-in-depth and negative boundaries.
            /// Strictly gated behind the non-default `test-support` feature; unavailable in production builds.
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            #[must_use]
            pub fn from_unvalidated_for_test(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper and returns the inner String.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl CanonicalEncode for $name {
            fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
                encoder.text(&self.0);
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
                let text = decoder.text()?;
                Self::parse(text)
            }
        }
    };
}

subsystem_generation!(
    DeviceGeneration,
    "An immutable device configuration and calibration generation identifier."
);
subsystem_generation!(
    StreamGeneration,
    "An immutable stream generation identifier."
);
subsystem_generation!(
    ModelGeneration,
    "An immutable model package generation identifier."
);
subsystem_generation!(
    CalibrationGeneration,
    "An immutable metric calibration generation identifier."
);
subsystem_generation!(
    GraphGeneration,
    "An immutable graph projection generation identifier."
);
subsystem_generation!(
    SearchGeneration,
    "An immutable search index generation identifier."
);
subsystem_generation!(
    PolicyGeneration,
    "An immutable alert and retention policy generation identifier."
);
subsystem_generation!(
    AdapterGeneration,
    "An immutable vendor adapter generation identifier."
);
subsystem_generation!(
    OntologyGeneration,
    "An immutable ontology generation identifier."
);
subsystem_generation!(
    PrivacyGeneration,
    "An immutable privacy projection generation identifier."
);

impl PrivacyGeneration {
    /// Canonical default privacy projection generation string.
    pub const CANONICAL_V1: &str = "privacy:projection:v1";

    /// Returns a canonical default privacy projection generation instance.
    #[must_use]
    pub fn canonical_v1() -> Self {
        Self(String::from(Self::CANONICAL_V1))
    }

    /// Constructs a privacy projection generation for the specified epoch.
    #[must_use]
    pub fn for_epoch(epoch: u64) -> Self {
        Self(format!("privacy:projection:v{epoch}"))
    }
}
subsystem_generation!(
    FirmwareGeneration,
    "An immutable device firmware build and release generation identifier."
);
subsystem_generation!(
    AppGeneration,
    "An immutable device application or agent release generation identifier."
);
/// Type alias for [`AppGeneration`].
pub type ApplicationGeneration = AppGeneration;

/// The semantic reason why an identity was tombstoned.
///
/// Handles unknown tags gracefully via [`TombstoneReason::Unknown`], preserving
/// forward compatibility without panicking.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TombstoneReason {
    /// Object was deleted by owner authorization or retention expiry.
    Deleted,
    /// Object was replaced/superseded by a newer revision or entity.
    Superseded,
    /// Capability grant or credential was revoked.
    Revoked,
    /// Object was invalidated by calibration or model failure.
    Invalidated,
    /// Lease or temporary state expired.
    Expired,
    /// Forward-compatible unknown tombstone reason tag.
    Unknown(u8),
}

impl TombstoneReason {
    /// Constructs a forward-compatible unknown tombstone reason tag.
    ///
    /// Rejects tags corresponding to known variants (`1..=5`) with [`ContractError::InvalidIdentifier`].
    pub fn unknown(tag: u8) -> Result<Self, ContractError> {
        if (1..=5).contains(&tag) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self::Unknown(tag))
    }

    /// Returns the stable discriminant tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Deleted => 1,
            Self::Superseded => 2,
            Self::Revoked => 3,
            Self::Invalidated => 4,
            Self::Expired => 5,
            Self::Unknown(tag) => tag,
        }
    }

    /// Decodes a reason from a raw byte tag, mapping unrecognized tags to [`Self::Unknown`].
    #[must_use]
    pub const fn from_tag(tag: u8) -> Self {
        match tag {
            1 => Self::Deleted,
            2 => Self::Superseded,
            3 => Self::Revoked,
            4 => Self::Invalidated,
            5 => Self::Expired,
            other => Self::Unknown(other),
        }
    }

    /// Returns the stable string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Parses a reason from a string spelling.
    pub fn parse(code: &str) -> Result<Self, ContractError> {
        match code {
            "deleted" => Ok(Self::Deleted),
            "superseded" => Ok(Self::Superseded),
            "revoked" => Ok(Self::Revoked),
            "invalidated" => Ok(Self::Invalidated),
            "expired" => Ok(Self::Expired),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl Ord for TombstoneReason {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.tag().cmp(&other.tag())
    }
}

impl PartialOrd for TombstoneReason {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for TombstoneReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl CanonicalEncode for TombstoneReason {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
    }
}

impl CanonicalDecode for TombstoneReason {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.u8()?;
        Ok(Self::from_tag(tag))
    }
}

/// A permanent tombstone record in the canonical evidence universe.
///
/// Follows non-negotiable rule INV-036: "External object identities are stable and
/// never recycled; stale internal handles are rejected by generation."
/// And: "Stable IDs are never renumbered; superseded entries remain tombstoned."
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TombstoneRecord {
    /// Stable object identity that was tombstoned.
    pub id: ObjectId,
    /// Monotonic generation of the tombstone itself (strictly `prior_generation + 1`).
    pub tombstone_generation: Generation,
    /// Last active generation of the object before tombstoning.
    pub prior_generation: Generation,
    /// Semantic reason for tombstoning.
    pub reason: TombstoneReason,
    /// Optional witness digest proving deletion authority or coverage proof.
    pub witness_digest: Option<ContentDigest>,
    /// Digest of the tombstoned deletion payload/manifest.
    pub payload_digest: ContentDigest,
}

impl TombstoneRecord {
    /// Magic discriminator byte for tombstone records in binary encoding.
    pub const DISCRIMINATOR: u8 = 0xFD;

    /// Constructs and validates a new tombstone record.
    ///
    /// Requires `prior_generation > 0` and `tombstone_generation == prior_generation.next()?`.
    /// If `tombstone_generation <= prior_generation` or `prior_generation == 0`,
    /// fails with [`ContractError::GenerationConflict`].
    pub fn new(
        id: ObjectId,
        tombstone_generation: Generation,
        prior_generation: Generation,
        reason: TombstoneReason,
        witness_digest: Option<ContentDigest>,
        payload_digest: ContentDigest,
    ) -> Result<Self, ContractError> {
        if prior_generation.0 == 0 || !tombstone_generation.is_successor_of(prior_generation) {
            return Err(ContractError::GenerationConflict);
        }
        Ok(Self {
            id,
            tombstone_generation,
            prior_generation,
            reason,
            witness_digest,
            payload_digest,
        })
    }

    /// Returns the canonical sort key `(object_id, tombstone_generation)`.
    #[must_use]
    pub fn sort_key(&self) -> (&str, u64) {
        (self.id.as_str(), self.tombstone_generation.get())
    }

    /// Computes the canonical domain-separated digest of this tombstone record.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, "fss.tombstone.v1")
    }
}

impl CanonicalEncode for TombstoneRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.tag(Self::DISCRIMINATOR);
        self.id.encode_canonical(encoder);
        self.tombstone_generation.encode_canonical(encoder);
        self.prior_generation.encode_canonical(encoder);
        self.reason.encode_canonical(encoder);
        match self.witness_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => {
                encoder.bool(false);
            }
        }
        encoder.digest(self.payload_digest);
    }
}

impl CanonicalDecode for TombstoneRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.tag()?;
        if tag != Self::DISCRIMINATOR {
            return Err(ContractError::InvalidDigest);
        }
        let id = ObjectId::decode_canonical(decoder)?;
        let tombstone_generation = Generation::decode_canonical(decoder)?;
        let prior_generation = Generation::decode_canonical(decoder)?;
        let reason = TombstoneReason::decode_canonical(decoder)?;
        let has_witness = decoder.bool()?;
        let witness_digest = if has_witness {
            Some(decoder.digest()?)
        } else {
            None
        };
        let payload_digest = decoder.digest()?;
        Self::new(
            id,
            tombstone_generation,
            prior_generation,
            reason,
            witness_digest,
            payload_digest,
        )
    }
}

/// The lifecycle state of a stable identity in the semantic ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityLifecycleState {
    /// Object is currently active and mutable.
    Active {
        /// Current active generation.
        current_generation: Generation,
    },
    /// Object has been permanently tombstoned.
    Tombstoned {
        /// Retained tombstone proof.
        tombstone: TombstoneRecord,
    },
}

impl IdentityLifecycleState {
    /// Creates a newly initialized active identity at generation 1.
    #[must_use]
    pub const fn create() -> Self {
        Self::Active {
            current_generation: Generation::GENESIS,
        }
    }

    /// Mutates an active identity, verifying that `prior_generation` matches current.
    ///
    /// Returns the new generation number.
    /// Fails with [`ContractError::GenerationConflict`] if the identity is tombstoned
    /// or if `prior_generation` does not match.
    pub fn mutate(&mut self, prior_generation: Generation) -> Result<Generation, ContractError> {
        match self {
            Self::Active { current_generation } => {
                if *current_generation != prior_generation {
                    return Err(ContractError::GenerationConflict);
                }
                let next_gen = current_generation.next()?;
                *current_generation = next_gen;
                Ok(next_gen)
            }
            Self::Tombstoned { .. } => Err(ContractError::GenerationConflict),
        }
    }

    /// Transitions an active identity into a permanent tombstone.
    ///
    /// Fails with [`ContractError::GenerationConflict`] if already tombstoned.
    pub fn tombstone(
        &mut self,
        id: ObjectId,
        reason: TombstoneReason,
        witness_digest: Option<ContentDigest>,
        payload_digest: ContentDigest,
    ) -> Result<TombstoneRecord, ContractError> {
        match self {
            Self::Active { current_generation } => {
                let tombstone_gen = current_generation.next()?;
                let record = TombstoneRecord::new(
                    id,
                    tombstone_gen,
                    *current_generation,
                    reason,
                    witness_digest,
                    payload_digest,
                )?;
                *self = Self::Tombstoned {
                    tombstone: record.clone(),
                };
                Ok(record)
            }
            Self::Tombstoned { .. } => Err(ContractError::GenerationConflict),
        }
    }

    /// Returns true if the identity is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Returns true if the identity is tombstoned.
    #[must_use]
    pub const fn is_tombstoned(&self) -> bool {
        matches!(self, Self::Tombstoned { .. })
    }

    /// Returns the current generation (either active generation or tombstone generation).
    #[must_use]
    pub const fn generation(&self) -> Generation {
        match self {
            Self::Active { current_generation } => *current_generation,
            Self::Tombstoned { tombstone } => tombstone.tombstone_generation,
        }
    }
}

/// An in-memory registry tracking active and tombstoned object identities.
///
/// Enforces non-negotiable tombstone rules:
/// 1. Published IDs are never renumbered.
/// 2. Superseded entries remain as tombstones.
/// 3. Tombstoned IDs cannot be resurrected with stale or equal generations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TombstoneRegistry {
    entries: BTreeMap<ObjectId, IdentityLifecycleState>,
}

impl TombstoneRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Registers a newly created active object identity.
    pub fn register_active(&mut self, id: ObjectId) -> Result<Generation, ContractError> {
        if self.entries.contains_key(&id) {
            return Err(ContractError::GenerationConflict);
        }
        self.entries.insert(id, IdentityLifecycleState::create());
        Ok(Generation::GENESIS)
    }

    /// Mutates an active identity to the next generation.
    pub fn mutate(
        &mut self,
        id: &ObjectId,
        prior_generation: Generation,
    ) -> Result<Generation, ContractError> {
        let state = self.entries.get_mut(id).ok_or(ContractError::NotFound)?;
        state.mutate(prior_generation)
    }

    /// Tombstones an active identity.
    pub fn tombstone(
        &mut self,
        id: ObjectId,
        reason: TombstoneReason,
        witness_digest: Option<ContentDigest>,
        payload_digest: ContentDigest,
    ) -> Result<TombstoneRecord, ContractError> {
        let state = self.entries.get_mut(&id).ok_or(ContractError::NotFound)?;
        state.tombstone(id, reason, witness_digest, payload_digest)
    }

    /// Returns true if an identity has been tombstoned.
    #[must_use]
    pub fn is_tombstoned(&self, id: &ObjectId) -> bool {
        matches!(
            self.entries.get(id),
            Some(IdentityLifecycleState::Tombstoned { .. })
        )
    }

    /// Returns the tombstone record if the identity is tombstoned.
    #[must_use]
    pub fn get_tombstone(&self, id: &ObjectId) -> Option<&TombstoneRecord> {
        match self.entries.get(id) {
            Some(IdentityLifecycleState::Tombstoned { tombstone }) => Some(tombstone),
            _ => None,
        }
    }

    /// Returns the current lifecycle state of an identity.
    #[must_use]
    pub fn get_state(&self, id: &ObjectId) -> Option<&IdentityLifecycleState> {
        self.entries.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_accepted() -> Result<(), ContractError> {
        let sensor = SensorId::parse("cam-front-01")?;
        assert_eq!(sensor.as_str(), "cam-front-01");
        assert_eq!(sensor.to_string(), "cam-front-01");

        let batch = BatchId::parse("batch:2026-09-10:001")?;
        assert_eq!(batch.as_str(), "batch:2026-09-10:001");
        Ok(())
    }

    #[test]
    fn invalid_identifiers_rejected() {
        assert_eq!(SensorId::parse(""), Err(ContractError::InvalidIdentifier));
        assert_eq!(
            SensorId::parse("cam with spaces"),
            Err(ContractError::InvalidIdentifier)
        );
        assert_eq!(
            SensorId::parse("cam/slash"),
            Err(ContractError::InvalidIdentifier)
        );
        let oversized = "a".repeat(129);
        assert_eq!(
            SensorId::parse(oversized),
            Err(ContractError::InvalidIdentifier)
        );
    }

    #[test]
    fn subsystem_generation_validation() -> Result<(), ContractError> {
        let dev_gen = DeviceGeneration::parse("insta360:v1.0.0")?;
        assert_eq!(dev_gen.as_str(), "insta360:v1.0.0");

        let model_gen = ModelGeneration::parse("model:yolo26:fp16:v1")?;
        assert_eq!(model_gen.as_str(), "model:yolo26:fp16:v1");

        // Too short (< 8 chars)
        assert_eq!(
            DeviceGeneration::parse("dev:1"),
            Err(ContractError::InvalidIdentifier)
        );
        // Uppercase forbidden
        assert_eq!(
            DeviceGeneration::parse("Device:v1.0.0"),
            Err(ContractError::InvalidIdentifier)
        );
        // Invalid starting char
        assert_eq!(
            DeviceGeneration::parse(":dev:v1.0.0"),
            Err(ContractError::InvalidIdentifier)
        );
        Ok(())
    }

    #[test]
    fn generation_transitions() -> Result<(), ContractError> {
        let genesis = Generation::GENESIS;
        assert_eq!(genesis.get(), 1);

        let next = genesis.next()?;
        assert_eq!(next.get(), 2);
        assert!(next.is_successor_of(genesis));
        assert!(!genesis.is_successor_of(next));

        Generation::validate_transition(None, Generation::GENESIS)?;
        Generation::validate_transition(Some(genesis), next)?;

        // Creation with non-genesis fails
        assert_eq!(
            Generation::validate_transition(None, next),
            Err(ContractError::GenerationConflict)
        );
        // Stale transition fails
        assert_eq!(
            Generation::validate_transition(Some(next), next),
            Err(ContractError::GenerationConflict)
        );
        Ok(())
    }

    #[test]
    fn tombstone_state_machine() -> Result<(), ContractError> {
        let mut registry = TombstoneRegistry::new();
        let obj_id = ObjectId::parse("obj-sensor-evidence-001")?;

        let gen1 = registry.register_active(obj_id.clone())?;
        assert_eq!(gen1, Generation::GENESIS);

        let gen2 = registry.mutate(&obj_id, gen1)?;
        assert_eq!(gen2.get(), 2);

        // Stale mutation fails
        assert_eq!(
            registry.mutate(&obj_id, gen1),
            Err(ContractError::GenerationConflict)
        );

        // Tombstone the object
        let dummy_payload = ContentDigest::sha256(b"deletion payload");
        let tombstone = registry.tombstone(
            obj_id.clone(),
            TombstoneReason::Deleted,
            None,
            dummy_payload,
        )?;
        assert_eq!(tombstone.prior_generation.get(), 2);
        assert_eq!(tombstone.tombstone_generation.get(), 3);
        assert!(registry.is_tombstoned(&obj_id));

        // Attempt to mutate tombstoned object fails closed
        assert_eq!(
            registry.mutate(&obj_id, gen2),
            Err(ContractError::GenerationConflict)
        );

        // Attempt to re-tombstone fails closed
        assert_eq!(
            registry.tombstone(
                obj_id.clone(),
                TombstoneReason::Deleted,
                None,
                dummy_payload
            ),
            Err(ContractError::GenerationConflict)
        );

        // Attempt to re-register existing tombstoned ID fails closed
        assert_eq!(
            registry.register_active(obj_id.clone()),
            Err(ContractError::GenerationConflict)
        );
        Ok(())
    }

    #[test]
    fn tombstone_canonical_round_trip() -> Result<(), ContractError> {
        let obj_id = ObjectId::parse("obj-del-01")?;
        let dummy_payload = ContentDigest::sha256(b"tombstone payload");
        let record = TombstoneRecord::new(
            obj_id,
            Generation(2),
            Generation(1),
            TombstoneReason::Superseded,
            None,
            dummy_payload,
        )?;

        let bytes = record.canonical_bytes();
        let decoded = TombstoneRecord::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded, record);
        assert_eq!(decoded.reason, TombstoneReason::Superseded);
        Ok(())
    }

    #[test]
    fn unknown_tombstone_reason_forward_compatibility() {
        let reason = TombstoneReason::from_tag(250);
        assert_eq!(reason, TombstoneReason::Unknown(250));
        assert_eq!(reason.tag(), 250);
        assert_eq!(reason.as_str(), "unknown");
    }
}
