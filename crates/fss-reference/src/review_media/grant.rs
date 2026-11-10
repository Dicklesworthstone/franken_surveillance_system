#![forbid(unsafe_code)]
//! Exact local review scope. Serialized grants are records, never bearer capabilities.
//!
//! Preparation grants no access: the lifecycle owner must verify committed publication,
//! current authority, source custody and revocation before invoking reader admission. These
//! contracts neither authenticate an external reviewer nor attest a payment-zone mask.

use fss_core::region::ContextAuthority;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, PrincipalId, SensorId, TimestampNs, validate_id,
};

use crate::evidence_export::{CAP_EXPORT_PREPARE, MAX_PURPOSE_BYTES};

/// Existing positive media-read capability, required in addition to an exact retained grant.
pub const CAP_READ_REVIEW_MEDIA: &str = "CAP-READ-MEDIA-001";
/// Maximum disclosed bytes under one immutable local review grant.
pub const MAX_REVIEW_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
/// Hard bound checked before decoding the access request.
pub const MAX_ACCESS_REQUEST_BYTES: usize = 4096;
/// Hard bound checked before decoding the complete grant record.
pub const MAX_REVIEW_GRANT_BYTES: usize = 8192;
const REQUEST_DOMAIN: &str = "fss.review_media_access.v1";
const GRANT_DOMAIN: &str = "fss.review_media_grant.v1";

/// Exact source, privacy, recipient and validity scope approved by the local owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewAccessRequest {
    /// Exact completed retained import identity.
    pub import_identity: ContentDigest,
    /// Exact published retained-import root, independently checked by the lifecycle.
    pub import_root: ContentDigest,
    /// Exact sensor of the retained import.
    pub sensor: SensorId,
    /// Inclusive requested start on the source's movie timeline.
    pub movie_start_tick: u64,
    /// Exclusive requested end on the source's movie timeline.
    pub movie_end_tick: u64,
    /// Digest of the complete current native mask binding, including explicit no-mask state.
    pub expected_privacy: ContentDigest,
    /// Locally authenticated principal allowed to read this derivative.
    pub recipient: PrincipalId,
    /// Bounded purpose, retained as an owner assertion.
    pub purpose: String,
    /// Owner-attested issuance instant; no ambient clock is consulted.
    pub issued_at: TimestampNs,
    /// Exclusive validity end in the same declared clock coordinates.
    pub expires_at: TimestampNs,
    /// Immutable maximum number of complete derivative media bytes.
    pub maximum_media_bytes: u64,
}

impl ReviewAccessRequest {
    /// Refuse malformed scopes before source access, rendering or publication.
    pub fn validate(&self) -> Result<(), GrantError> {
        if ![
            self.import_identity,
            self.import_root,
            self.expected_privacy,
        ]
        .into_iter()
        .all(valid_digest)
            || self.movie_start_tick >= self.movie_end_tick
            || self.issued_at >= self.expires_at
            || self.maximum_media_bytes == 0
            || self.maximum_media_bytes > MAX_REVIEW_MEDIA_BYTES
            || self.purpose.trim().is_empty()
            || self.purpose.len() > MAX_PURPOSE_BYTES
            || self.purpose.chars().any(char::is_control)
        {
            return Err(GrantError::InvalidRequest);
        }
        Ok(())
    }

    /// Canonical bounded owner request; these bytes confer no authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(REQUEST_DOMAIN);
        e.digest(self.import_identity);
        e.digest(self.import_root);
        self.sensor.encode_canonical(&mut e);
        e.u64(self.movie_start_tick);
        e.u64(self.movie_end_tick);
        e.digest(self.expected_privacy);
        self.recipient.encode_canonical(&mut e);
        e.text(&self.purpose);
        self.issued_at.encode_canonical(&mut e);
        self.expires_at.encode_canonical(&mut e);
        e.u64(self.maximum_media_bytes);
        Ok(e.finish())
    }

    /// Immutable request identity, including its recipient, timing and disclosure bound.
    pub fn digest(&self) -> Result<ContentDigest, GrantError> {
        Ok(ContentDigest::sha256(&self.to_bytes()?))
    }

    /// Strict canonical decode against an independently supplied digest.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, GrantError> {
        verify_bytes(bytes, expected, MAX_ACCESS_REQUEST_BYTES)?;
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != REQUEST_DOMAIN {
            return Err(GrantError::InvalidRecord);
        }
        let value = Self {
            import_identity: d.digest()?,
            import_root: d.digest()?,
            sensor: SensorId::decode_canonical(&mut d)?,
            movie_start_tick: d.u64()?,
            movie_end_tick: d.u64()?,
            expected_privacy: d.digest()?,
            recipient: PrincipalId::decode_canonical(&mut d)?,
            purpose: d.text()?.to_owned(),
            issued_at: TimestampNs::decode_canonical(&mut d)?,
            expires_at: TimestampNs::decode_canonical(&mut d)?,
            maximum_media_bytes: d.u64()?,
        };
        d.ensure_finished()?;
        value.validate().map_err(|_| GrantError::InvalidRecord)?;
        if value.to_bytes()? != bytes {
            return Err(GrantError::InvalidRecord);
        }
        Ok(value)
    }
}

/// Immutable owner-approved scope bound to the exact native renderer receipt.
///
/// A decoded or prepared record is not proof of publication or current access. The lifecycle
/// verifies those facts independently before admitting disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewGrant {
    request: ReviewAccessRequest,
    owner: PrincipalId,
    site: String,
    render_receipt: ContentDigest,
}

impl ReviewGrant {
    /// Prepare a candidate under export-preview authority. Committing it is a separate effect.
    pub fn prepare(
        request: ReviewAccessRequest,
        authority: &ContextAuthority,
        site: &str,
        render_receipt: ContentDigest,
    ) -> Result<Self, GrantError> {
        request.validate()?;
        check_authority(authority, site, CAP_EXPORT_PREPARE)?;
        if authority
            .deadline
            .is_some_and(|deadline| request.issued_at >= deadline)
        {
            return Err(GrantError::Unauthorized);
        }
        let value = Self {
            request,
            owner: PrincipalId::parse(authority.principal.clone())?,
            site: site.to_owned(),
            render_receipt,
        };
        value.validate()?;
        Ok(value)
    }

    /// Approved access request.
    pub fn request(&self) -> &ReviewAccessRequest {
        &self.request
    }
    /// Local approving principal, not the external recipient's identity proof.
    pub fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    /// Exact deployment lineage.
    pub fn site(&self) -> &str {
        &self.site
    }
    /// Native receipt binding source, interval, screened pixels and render configuration.
    pub const fn render_receipt(&self) -> ContentDigest {
        self.render_receipt
    }

    fn validate(&self) -> Result<(), GrantError> {
        self.request.validate()?;
        validate_id(&self.site).map_err(|_| GrantError::InvalidRecord)?;
        if !valid_digest(self.render_receipt) {
            return Err(GrantError::InvalidRecord);
        }
        Ok(())
    }

    /// Canonical grant record, with no implicit capability or publication proof.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(GRANT_DOMAIN);
        e.bytes(&self.request.to_bytes()?);
        self.owner.encode_canonical(&mut e);
        e.text(&self.site);
        e.digest(self.render_receipt);
        Ok(e.finish())
    }

    /// Identity of the complete immutable grant record.
    pub fn digest(&self) -> Result<ContentDigest, GrantError> {
        Ok(ContentDigest::sha256(&self.to_bytes()?))
    }

    /// Decode a record; the lifecycle must still prove its current committed custody.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, GrantError> {
        verify_bytes(bytes, expected, MAX_REVIEW_GRANT_BYTES)?;
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != GRANT_DOMAIN {
            return Err(GrantError::InvalidRecord);
        }
        let request = d.bytes()?;
        let value = Self {
            request: ReviewAccessRequest::from_bytes(request, ContentDigest::sha256(request))?,
            owner: PrincipalId::decode_canonical(&mut d)?,
            site: d.text()?.to_owned(),
            render_receipt: d.digest()?,
        };
        d.ensure_finished()?;
        value.validate().map_err(|_| GrantError::InvalidRecord)?;
        if value.to_bytes()? != bytes {
            return Err(GrantError::InvalidRecord);
        }
        Ok(value)
    }

    /// Admit only a currently authorized exact recipient of a verified retained grant.
    ///
    /// `revoked` must come from verified current lifecycle authority, never a caller assertion.
    /// This check neither reads media nor proves source custody or record publication.
    pub(crate) fn authorize_reader(
        &self,
        authority: &ContextAuthority,
        site: &str,
        render_receipt: ContentDigest,
        current_privacy: ContentDigest,
        attested_now: CaptureInterval,
        revoked: bool,
    ) -> Result<(), GrantError> {
        check_authority(authority, site, CAP_READ_REVIEW_MEDIA)?;
        if authority.principal != self.request.recipient.as_str()
            || site != self.site
            || render_receipt != self.render_receipt
        {
            return Err(GrantError::ScopeMismatch);
        }
        if revoked {
            return Err(GrantError::Revoked);
        }
        if current_privacy != self.request.expected_privacy {
            return Err(GrantError::PrivacyChanged);
        }
        if attested_now.earliest > attested_now.latest {
            return Err(GrantError::InvalidRequest);
        }
        if authority
            .deadline
            .is_some_and(|deadline| attested_now.latest >= deadline)
        {
            return Err(GrantError::Unauthorized);
        }
        if attested_now.earliest < self.request.issued_at {
            return Err(GrantError::NotYetValid);
        }
        if attested_now.earliest >= self.request.expires_at {
            return Err(GrantError::Expired);
        }
        if attested_now.latest >= self.request.expires_at {
            return Err(GrantError::ExpiryUncertain);
        }
        Ok(())
    }
}

fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}

fn verify_bytes(bytes: &[u8], expected: ContentDigest, maximum: usize) -> Result<(), GrantError> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || !valid_digest(expected)
        || ContentDigest::sha256(bytes) != expected
    {
        return Err(GrantError::InvalidRecord);
    }
    Ok(())
}

fn check_authority(authority: &ContextAuthority, site: &str, cap: &str) -> Result<(), GrantError> {
    authority.validate().map_err(|_| GrantError::Unauthorized)?;
    validate_id(site).map_err(|_| GrantError::Unauthorized)?;
    if authority.cancellation_reason.is_some() {
        return Err(GrantError::Cancelled);
    }
    if !authority.has_capability(cap)
        || authority.anchor_universe != ContentDigest::sha256(site.as_bytes())
    {
        return Err(GrantError::Unauthorized);
    }
    Ok(())
}

/// Typed fail-closed distinction within existing registered export and access error families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    /// Malformed source, interval, label, lifetime or byte bound.
    InvalidRequest,
    /// Canonical framing, identity or record fields failed verification.
    InvalidRecord,
    /// Current context lacks required authority or has expired.
    Unauthorized,
    /// Recipient, deployment or exact render receipt differs.
    ScopeMismatch,
    /// Some plausible current time precedes issuance.
    NotYetValid,
    /// Entire current-time interval has reached exclusive expiry.
    Expired,
    /// Current-time uncertainty overlaps exclusive expiry.
    ExpiryUncertain,
    /// Verified current authority has revoked this grant.
    Revoked,
    /// Current full privacy binding differs from the rendered one.
    PrivacyChanged,
    /// Current context has requested cancellation.
    Cancelled,
}

impl GrantError {
    /// Existing registered stable error family.
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::InvalidRecord => "ERR-EXPORT-CUSTODY-001",
            Self::InvalidRequest | Self::NotYetValid | Self::Expired | Self::ExpiryUncertain => {
                "ERR-EXPORT-REQUEST-001"
            }
            Self::Cancelled => "ERR-EXPORT-CANCELLED-001",
            Self::Unauthorized | Self::ScopeMismatch | Self::Revoked | Self::PrivacyChanged => {
                "ERR-AUTH-DENIED-001"
            }
        }
    }

    /// Stable narrow reason; no source pixels, recipient labels or secrets are disclosed.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_review_access_request",
            Self::InvalidRecord => "invalid_review_grant_record",
            Self::Unauthorized => "review_authority_denied",
            Self::ScopeMismatch => "review_grant_scope_mismatch",
            Self::NotYetValid => "review_grant_issuance_not_reached",
            Self::Expired => "review_grant_expired",
            Self::ExpiryUncertain => "review_grant_expiry_uncertain",
            Self::Revoked => "review_grant_revoked",
            Self::PrivacyChanged => "review_privacy_changed",
            Self::Cancelled => "review_access_cancelled",
        }
    }
}
impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())
    }
}
impl std::error::Error for GrantError {}
impl From<ContractError> for GrantError {
    fn from(_: ContractError) -> Self {
        Self::InvalidRecord
    }
}

#[cfg(test)]
#[path = "grant_tests.rs"]
mod tests;
