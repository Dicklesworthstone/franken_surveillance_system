#![forbid(unsafe_code)]
//! Realization of hydration ladder level H0: identity (AGT-H0, fss-x4a.30.82.12).
//!
//! H0 represents the immutable identity descriptor for an evidence subject, exposing:
//! - digest
//! - type
//! - time/spatial bounds
//! - source
//! - availability
//! - cost
//! - authority
//!
//! H0 strictly forbids exposing raw payload bytes, decoded media, or ungrounded cognition.

use std::collections::BTreeSet;

use super::{
    HandleAvailability, HydrationError, HydrationLevel, MAX_REQUEST_SET_ITEMS, SemanticHandle,
    decode_optional_interval, decode_optional_text, decode_text_set, encode_optional_interval,
    encode_optional_text, encode_text_set, valid_text,
};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::{
    BudgetVector, CaptureInterval, ContentDigest, ContractBasis, LedgerAnchor, TimestampNs,
};

/// Stable identifier for hydration ladder level H0.
pub const H0_LEVEL_ID: &str = "H0";

/// Stable name for hydration ladder level H0.
pub const H0_LEVEL_NAME: &str = "identity";

/// Normative content declaration for hydration ladder level H0 from the agent abstraction registry.
pub const H0_CONTENT: &str =
    "digest, type, time/spatial bounds, source, availability, cost, and authority";

/// Canonical schema discriminator tag for H0 identity binary envelopes.
pub const H0_SCHEMA: &str = "fss.h0_identity.v1";

/// Parameters used to construct an [`H0Identity`] descriptor directly.
#[derive(Clone, Debug, PartialEq)]
pub struct H0IdentityParams {
    /// Content-derived handle identifier (e.g. `semantic-handle:sha256:...`).
    pub handle_id: String,
    /// Stable canonical subject identity (e.g. `evidence:pkg-42`).
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Registered semantic type (e.g. `evidence_bundle`).
    pub semantic_type: String,
    /// Stable source sensor/device identity.
    pub source_id: String,
    /// Optional conservative capture time interval.
    pub capture_interval: Option<CaptureInterval>,
    /// Optional spatial or graph scope.
    pub spatial_scope: Option<String>,
    /// Optional privacy or derivation transform applied to this subject.
    pub applied_transform: Option<String>,
    /// Current availability of the exact subject.
    pub availability: HandleAvailability,
    /// Conservative estimated resource cost to hydrate at H0.
    pub estimated_cost: BudgetVector,
    /// Authority anchor of this descriptor revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Required capability identifiers at H0.
    pub required_capabilities: BTreeSet<String>,
    /// Privacy class independently authorized at hydration time.
    pub privacy_class: String,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Time after which this descriptor must return an expired state.
    pub retention_until: TimestampNs,
}

/// Strongly typed representation of the H0 Identity level of the progressive hydration ladder.
///
/// Encapsulates the content specified by normative row H0:
/// digest, type, time/spatial bounds, source, availability, cost, and authority.
#[derive(Clone, Debug, PartialEq)]
pub struct H0Identity {
    handle_id: String,
    subject_id: String,
    subject_digest: ContentDigest,
    semantic_type: String,
    source_id: String,
    capture_interval: Option<CaptureInterval>,
    spatial_scope: Option<String>,
    applied_transform: Option<String>,
    availability: HandleAvailability,
    estimated_cost: BudgetVector,
    anchor: LedgerAnchor,
    contract_basis: ContractBasis,
    required_capabilities: BTreeSet<String>,
    privacy_class: String,
    published_at: TimestampNs,
    retention_until: TimestampNs,
}

fn contains_prohibited_terms(s: &str) -> bool {
    let normalized: String = s
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    const PROHIBITED_ROOTS: &[&str] = &[
        "rawbyte",
        "rawbytes",
        "decodedframe",
        "payloadstream",
        "unredactedmedia",
        "modelweight",
        "modelweights",
        "vlmfeature",
        "vlmfeatures",
    ];
    for root in PROHIBITED_ROOTS {
        if normalized.contains(root) {
            return true;
        }
    }
    false
}

impl H0Identity {
    /// Constructs an [`H0Identity`] from strongly typed parameters and validates all invariants.
    pub fn new(params: H0IdentityParams) -> Result<Self, HydrationError> {
        let identity = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            semantic_type: params.semantic_type,
            source_id: params.source_id,
            capture_interval: params.capture_interval,
            spatial_scope: params.spatial_scope,
            applied_transform: params.applied_transform,
            availability: params.availability,
            estimated_cost: params.estimated_cost,
            anchor: params.anchor,
            contract_basis: params.contract_basis,
            required_capabilities: params.required_capabilities,
            privacy_class: params.privacy_class,
            published_at: params.published_at,
            retention_until: params.retention_until,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Computes the deterministic canonical identity digest for handle binding.
    pub fn compute_identity_digest(
        subject_id: &str,
        subject_digest: ContentDigest,
        semantic_type: &str,
        source_id: &str,
        capture_interval: Option<CaptureInterval>,
        spatial_scope: Option<&str>,
        applied_transform: Option<&str>,
    ) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.semantic_handle_identity.v1");
        encoder.text(subject_id);
        encoder.digest(subject_digest);
        encoder.text(semantic_type);
        encoder.text(source_id);
        encode_optional_interval(capture_interval, &mut encoder);
        encode_optional_text(spatial_scope, &mut encoder);
        encode_optional_text(applied_transform, &mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Returns the computed identity digest of this descriptor.
    pub fn identity_digest(&self) -> Result<ContentDigest, ContractError> {
        Self::compute_identity_digest(
            &self.subject_id,
            self.subject_digest,
            &self.semantic_type,
            &self.source_id,
            self.capture_interval,
            self.spatial_scope.as_deref(),
            self.applied_transform.as_deref(),
        )
    }

    /// Extracts and validates an H0 identity descriptor from a published [`SemanticHandle`].
    pub fn from_semantic_handle(handle: &SemanticHandle) -> Result<Self, HydrationError> {
        if !handle.levels.contains(&HydrationLevel::H0) {
            return Err(HydrationError::LevelUnavailable);
        }

        let estimated_cost = handle
            .estimated_costs
            .get(&HydrationLevel::H0)
            .copied()
            .ok_or(HydrationError::LevelUnavailable)?;

        let required_capabilities = handle
            .required_capabilities
            .get(&HydrationLevel::H0)
            .cloned()
            .ok_or(HydrationError::LevelUnavailable)?;

        handle.verify()?;

        let identity = Self {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            semantic_type: handle.semantic_type.clone(),
            source_id: handle.source_id.clone(),
            capture_interval: handle.capture_interval,
            spatial_scope: handle.spatial_scope.clone(),
            applied_transform: handle.applied_transform.clone(),
            availability: handle.availability,
            estimated_cost,
            anchor: handle.anchor.clone(),
            contract_basis: handle.contract_basis.clone(),
            required_capabilities,
            privacy_class: handle.privacy_class.clone(),
            published_at: handle.published_at,
            retention_until: handle.retention_until,
        };

        identity.validate()?;
        Ok(identity)
    }

    /// Validates the H0 identity invariant and semantic bounds.
    pub fn validate(&self) -> Result<(), HydrationError> {
        // Semantic protocol must be exact "fss/1"
        if self.contract_basis.semantic_protocol != "fss/1" {
            return Err(ContractError::InvalidIdentifier.into());
        }

        // Bounded text validation with control character checks and non-whitespace check
        if !valid_text(&self.handle_id)
            || self.handle_id.trim().is_empty()
            || !valid_text(&self.subject_id)
            || self.subject_id.trim().is_empty()
            || !valid_text(&self.semantic_type)
            || self.semantic_type.trim().is_empty()
            || !valid_text(&self.source_id)
            || self.source_id.trim().is_empty()
            || !valid_text(&self.privacy_class)
            || self.privacy_class.trim().is_empty()
        {
            return Err(ContractError::InvalidIdentifier.into());
        }

        if let Some(ref scope) = self.spatial_scope
            && (!valid_text(scope) || scope.trim().is_empty())
        {
            return Err(ContractError::InvalidIdentifier.into());
        }

        if let Some(ref transform) = self.applied_transform
            && (!valid_text(transform) || transform.trim().is_empty())
        {
            return Err(ContractError::InvalidIdentifier.into());
        }

        if self.required_capabilities.len() > MAX_REQUEST_SET_ITEMS {
            return Err(HydrationError::CapacityExceeded);
        }

        for cap in &self.required_capabilities {
            if !valid_text(cap) || cap.trim().is_empty() {
                return Err(ContractError::InvalidIdentifier.into());
            }
        }

        // Subject digest must not be zeroed
        if self.subject_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest.into());
        }

        // Handle ID must be bound to the identity core digest
        let expected_handle_id = format!("semantic-handle:{}", self.identity_digest()?);
        if self.handle_id != expected_handle_id {
            return Err(HydrationError::HandleRebound);
        }

        // Capture interval must be non-inverted if present
        if let Some(ci) = self.capture_interval
            && ci.earliest > ci.latest
        {
            return Err(ContractError::InvertedTimeInterval.into());
        }

        // Retention must strictly succeed publication (retention_until <= published_at is rejected)
        if self.retention_until <= self.published_at {
            return Err(ContractError::InvertedTimeInterval.into());
        }

        // Anchor check
        if self.anchor.site_lineage.trim().is_empty() {
            return Err(ContractError::InvalidIdentifier.into());
        }

        // Estimated cost check
        if let Err(err) = self.estimated_cost.validate() {
            return Err(ContractError::InvalidBudget(err).into());
        }

        // Semantic invariant: H0 strictly prohibits exposing raw payload, decode, or ungrounded cognition
        if !self.is_pure_metadata() {
            return Err(ContractError::ProhibitedEvidencePromotion.into());
        }

        Ok(())
    }

    /// Verifies that H0 exposes metadata only and contains no raw payload bytes or decode artifacts.
    #[must_use]
    pub fn is_pure_metadata(&self) -> bool {
        if contains_prohibited_terms(&self.semantic_type) {
            return false;
        }
        if let Some(ref scope) = self.spatial_scope
            && contains_prohibited_terms(scope)
        {
            return false;
        }
        if let Some(ref transform) = self.applied_transform
            && contains_prohibited_terms(transform)
        {
            return false;
        }
        true
    }

    /// Returns the handle identifier.
    #[must_use]
    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    /// Returns the canonical subject identifier.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Returns the exact subject content digest.
    #[must_use]
    pub fn subject_digest(&self) -> ContentDigest {
        self.subject_digest
    }

    /// Returns the registered semantic type.
    #[must_use]
    pub fn semantic_type(&self) -> &str {
        &self.semantic_type
    }

    /// Returns the source sensor or device identifier.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the optional capture interval.
    #[must_use]
    pub fn capture_interval(&self) -> Option<CaptureInterval> {
        self.capture_interval
    }

    /// Returns the optional spatial scope.
    #[must_use]
    pub fn spatial_scope(&self) -> Option<&str> {
        self.spatial_scope.as_deref()
    }

    /// Returns the optional applied privacy or derivation transform.
    #[must_use]
    pub fn applied_transform(&self) -> Option<&str> {
        self.applied_transform.as_deref()
    }

    /// Returns the subject availability.
    #[must_use]
    pub fn availability(&self) -> HandleAvailability {
        self.availability
    }

    /// Returns the estimated hydration resource cost.
    #[must_use]
    pub fn estimated_cost(&self) -> BudgetVector {
        self.estimated_cost
    }

    /// Returns the authority ledger anchor.
    #[must_use]
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Returns the contract basis.
    #[must_use]
    pub fn contract_basis(&self) -> &ContractBasis {
        &self.contract_basis
    }

    /// Returns the required capability set.
    #[must_use]
    pub fn required_capabilities(&self) -> &BTreeSet<String> {
        &self.required_capabilities
    }

    /// Returns the privacy classification.
    #[must_use]
    pub fn privacy_class(&self) -> &str {
        &self.privacy_class
    }

    /// Returns the publication timestamp.
    #[must_use]
    pub fn published_at(&self) -> TimestampNs {
        self.published_at
    }

    /// Returns the retention expiration timestamp.
    #[must_use]
    pub fn retention_until(&self) -> TimestampNs {
        self.retention_until
    }

    /// Returns the exact hydration level ([`HydrationLevel::H0`]).
    #[must_use]
    pub const fn level(&self) -> HydrationLevel {
        HydrationLevel::H0
    }

    /// Returns the normative level identifier (`"H0"`).
    #[must_use]
    pub const fn level_id(&self) -> &'static str {
        H0_LEVEL_ID
    }

    /// Returns the normative level name (`"identity"`).
    #[must_use]
    pub const fn level_name(&self) -> &'static str {
        H0_LEVEL_NAME
    }

    /// Returns the exact normative content declaration from the agent abstraction registry.
    #[must_use]
    pub const fn content_declaration(&self) -> &'static str {
        H0_CONTENT
    }

    /// Returns true if this identity descriptor has passed its retention expiration timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: TimestampNs) -> bool {
        now > self.retention_until
    }

    /// Checks whether a specific capability is required for H0 access.
    #[must_use]
    pub fn requires_capability(&self, cap: &str) -> bool {
        self.required_capabilities.contains(cap)
    }

    /// Checks whether the estimated cost fits within the provided budget.
    #[must_use]
    pub fn satisfies_budget(&self, budget: &BudgetVector) -> bool {
        self.estimated_cost.fits_within(*budget)
    }

    /// Computes the deterministic canonical digest of this H0 identity descriptor.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        Ok(ContentDigest::sha256(&encoder.finish_checked()?))
    }

    /// Decodes an [`H0Identity`] from canonical binary bytes and verifies no trailing bytes exist.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let identity = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(identity)
    }
}

impl CanonicalEncode for H0Identity {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(H0_SCHEMA);
        encoder.text(&self.handle_id);
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        encoder.text(&self.semantic_type);
        encoder.text(&self.source_id);
        encode_optional_interval(self.capture_interval, encoder);
        encode_optional_text(self.spatial_scope.as_deref(), encoder);
        encode_optional_text(self.applied_transform.as_deref(), encoder);
        self.availability.encode_canonical(encoder);
        self.estimated_cost.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        self.contract_basis.encode_canonical(encoder);
        encode_text_set(&self.required_capabilities, encoder);
        encoder.text(&self.privacy_class);
        self.published_at.encode_canonical(encoder);
        self.retention_until.encode_canonical(encoder);
    }
}

impl CanonicalDecode for H0Identity {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H0_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_string();
        let subject_id = decoder.text()?.to_string();
        let subject_digest = decoder.digest()?;
        let semantic_type = decoder.text()?.to_string();
        let source_id = decoder.text()?.to_string();
        let capture_interval = decode_optional_interval(decoder)?;
        let spatial_scope = decode_optional_text(decoder)?.map(|s| s.to_string());
        let applied_transform = decode_optional_text(decoder)?.map(|s| s.to_string());
        let availability = HandleAvailability::decode_canonical(decoder)?;
        let estimated_cost = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let contract_basis = ContractBasis::decode_canonical(decoder)?;
        let required_capabilities = decode_text_set(decoder)?;
        let privacy_class = decoder.text()?.to_string();
        let published_at = TimestampNs::decode_canonical(decoder)?;
        let retention_until = TimestampNs::decode_canonical(decoder)?;

        let identity = Self {
            handle_id,
            subject_id,
            subject_digest,
            semantic_type,
            source_id,
            capture_interval,
            spatial_scope,
            applied_transform,
            availability,
            estimated_cost,
            anchor,
            contract_basis,
            required_capabilities,
            privacy_class,
            published_at,
            retention_until,
        };
        identity.validate().map_err(|e| match e {
            HydrationError::Contract(c) => c,
            HydrationError::HandleRebound => ContractError::InvalidIdentifier,
            HydrationError::CapacityExceeded => ContractError::ArithmeticOverflow,
            _ => ContractError::InvalidIdentifier,
        })?;
        Ok(identity)
    }
}
