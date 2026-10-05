#![forbid(unsafe_code)]
//! Portable, bounded copies of already-approved redacted event exports.
//!
//! A package contains exactly one canonical `EventExportRecord`, not a general archive. The
//! manifest is reconstructed using the existing export profile. No source/media/model digest is
//! followed, and there are no filenames, optional children, compression, or extraction commands.
//!
//! Offline verification requires an export root supplied independently of the package. It proves
//! byte identity against that root, NOT a signature, current ledger membership, physical truth,
//! recipient authentication, delivery, or erasure. Expiry is checked conservatively against an
//! explicitly supplied time interval; this module never reads an ambient clock.

use std::fmt;

use fss_core::region::ContextAuthority;
use fss_core::{CaptureInterval, ContentDigest, DigestAlgorithm, ObjectId};

use crate::deletion::DeletionIndex;
use crate::evidence_export::{
    CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EXPORT_OBJECT_PREFIX, EventExportRecord, ExportError,
    FAMILY_EVIDENCE_EXPORT, MAX_EXPORT_RECORD_BYTES, MAX_RECIPIENT_BYTES, read_export,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Fixed envelope magic; incompatible layouts require a different version.
pub const PACKAGE_MAGIC: [u8; 8] = *b"FSSXPK01";
/// Envelope version, encoded as an unsigned big-endian 32-bit integer.
pub const PACKAGE_VERSION: u32 = 1;
/// Magic (8), version (4), SHA-256 export-root bytes (32), and payload length (4).
pub const PACKAGE_HEADER_BYTES: usize = 48;
/// SHA-256 checksum of every preceding envelope byte.
pub const PACKAGE_TRAILER_BYTES: usize = 32;
/// Hard bound checked before decoding or allocating from a length field.
pub const MAX_PACKAGE_BYTES: usize =
    PACKAGE_HEADER_BYTES + MAX_EXPORT_RECORD_BYTES + PACKAGE_TRAILER_BYTES;

/// Recipient label and owner-attested current time, in the export's declared clock coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageScope {
    /// Must equal the recipient of the approved export, byte-for-byte.
    pub recipient: String,
    /// Both endpoints must precede the exclusive export expiry for use to be admitted.
    pub attested_now: CaptureInterval,
}

impl PackageScope {
    /// Refuses unbounded labels and inverted intervals before any package or deployment read.
    pub fn validate(&self) -> Result<(), PackageError> {
        if self.recipient.trim().is_empty()
            || self.recipient.len() > MAX_RECIPIENT_BYTES
            || self.recipient.chars().any(char::is_control)
            || self.attested_now.earliest > self.attested_now.latest
        {
            return Err(PackageError::InvalidScope);
        }
        Ok(())
    }

    fn admits(&self, record: &EventExportRecord) -> Result<(), PackageError> {
        self.validate()?;
        if self.recipient != record.request().recipient {
            return Err(PackageError::RecipientMismatch);
        }
        let expiry = record.request().expires_at;
        if self.attested_now.earliest >= expiry {
            return Err(PackageError::Expired);
        }
        if self.attested_now.latest >= expiry {
            return Err(PackageError::ExpiryUncertain);
        }
        Ok(())
    }
}

/// Exact redacted record verified against a caller-supplied export root.
///
/// Fields are private so arbitrary metadata cannot be relabelled as a verified package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    root: ContentDigest,
    package_digest: ContentDigest,
    record: EventExportRecord,
}

impl VerifiedPackage {
    /// Independently supplied root that verification matched.
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// SHA-256 of the complete portable envelope, including its checksum.
    pub const fn package_digest(&self) -> ContentDigest {
        self.package_digest
    }
    /// The exact approved-profile record, not hydrated source evidence.
    pub fn record(&self) -> &EventExportRecord {
        &self.record
    }
}

/// A portable package read from verified committed export custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPackage {
    bytes: Vec<u8>,
    verified: VerifiedPackage,
}

impl PreparedPackage {
    /// Complete deterministic envelope; no source bytes or additional children are included.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Validated root, record, and envelope identity.
    pub fn verified(&self) -> &VerifiedPackage {
        &self.verified
    }
}

/// Typed refusal; malformed, expired and uncertain packages never yield a partial record.
#[derive(Debug)]
pub enum PackageError {
    /// Malformed or unbounded recipient/time scope.
    InvalidScope,
    /// Envelope framing, checksum, or canonical record does not verify.
    Malformed,
    /// The supplied root is invalid or differs from the envelope or its reconstructed manifest.
    RootMismatch,
    /// The caller requested another recipient; no relabelling is permitted.
    RecipientMismatch,
    /// The entire attested current-time interval is at or beyond expiry.
    Expired,
    /// Current-time uncertainty overlaps expiry; admission is refused, not guessed.
    ExpiryUncertain,
    /// Package size exceeds its complete bounded format.
    Limit,
    /// Export capability, original approving principal, or context scope is not admitted.
    Unauthorized,
    /// Custody was tombstoned, including an interrupted deletion whose bytes still exist.
    Deleted,
    /// Current authority or deletion history could not be verified.
    AuthorityChanged,
    /// Cooperative cancellation before any output is returned.
    Cancelled,
    /// Existing export owner refused the record or its custody.
    Export(ExportError),
}

impl PackageError {
    /// Existing registered export error family; `reason()` retains the narrower distinction.
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized | Self::RecipientMismatch => "ERR-AUTH-DENIED-001",
            Self::Limit => "ERR-EXPORT-BOUND-001",
            Self::Cancelled => "ERR-EXPORT-CANCELLED-001",
            Self::InvalidScope | Self::Expired | Self::ExpiryUncertain => "ERR-EXPORT-REQUEST-001",
            Self::Deleted => "ERR-EVIDENCE-DELETED-001",
            Self::Malformed | Self::RootMismatch | Self::AuthorityChanged => "ERR-EXPORT-CUSTODY-001",
            Self::Export(error) => error.stable_id(),
        }
    }

    /// Stable machine-readable distinction within the existing export error family.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidScope => "invalid_recipient_or_time_scope",
            Self::Malformed => "malformed_package",
            Self::RootMismatch => "expected_export_root_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
            Self::Expired => "expired_under_attested_time",
            Self::ExpiryUncertain => "expiry_overlaps_attested_time",
            Self::Limit => "package_byte_bound",
            Self::Unauthorized => "export_authority_denied",
            Self::Deleted => "export_custody_deleted",
            Self::AuthorityChanged => "export_authority_unverifiable",
            Self::Cancelled => "package_cancelled",
            Self::Export(_) => "export_owner_refusal",
        }
    }
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())
    }
}
impl std::error::Error for PackageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Export(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ExportError> for PackageError {
    fn from(error: ExportError) -> Self {
        Self::Export(error)
    }
}

fn valid_root(root: ContentDigest) -> bool {
    root.algorithm() == DigestAlgorithm::Sha256 && root.bytes() != [0; 32]
}

fn encode_record(record: &EventExportRecord) -> Result<Vec<u8>, PackageError> {
    let payload = record.to_bytes();
    if payload.is_empty() || payload.len() > MAX_EXPORT_RECORD_BYTES {
        return Err(PackageError::Limit);
    }
    // Reuse the canonical export decoder, including its closed profile and field constraints.
    EventExportRecord::from_bytes(&payload, record.digest())?;
    let root = record.manifest()?.root();
    let length = u32::try_from(payload.len()).map_err(|_| PackageError::Limit)?;
    let mut bytes = Vec::with_capacity(PACKAGE_HEADER_BYTES + payload.len() + PACKAGE_TRAILER_BYTES);
    bytes.extend_from_slice(&PACKAGE_MAGIC);
    bytes.extend_from_slice(&PACKAGE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&root.bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&payload);
    let checksum = ContentDigest::sha256(&bytes);
    bytes.extend_from_slice(&checksum.bytes());
    Ok(bytes)
}

/// Verify a package without a deployment, network, media decoder, or extraction directory.
///
/// `expected_root` MUST come from a trusted channel independent of these bytes. A package's own
/// header and checksum are not an authentication authority. Successful expiry admission means
/// only that `scope.attested_now.latest` is strictly before the approved exclusive expiry.
pub fn verify_package(
    bytes: &[u8],
    expected_root: ContentDigest,
    scope: &PackageScope,
) -> Result<VerifiedPackage, PackageError> {
    scope.validate()?;
    if !valid_root(expected_root) {
        return Err(PackageError::RootMismatch);
    }
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::Limit);
    }
    if bytes.len() < PACKAGE_HEADER_BYTES + PACKAGE_TRAILER_BYTES
        || bytes[..8] != PACKAGE_MAGIC
        || bytes[8..12] != PACKAGE_VERSION.to_be_bytes()
    {
        return Err(PackageError::Malformed);
    }
    let length = u32::from_be_bytes(
        bytes[44..48].try_into().map_err(|_| PackageError::Malformed)?,
    ) as usize;
    if length == 0 || length > MAX_EXPORT_RECORD_BYTES {
        return Err(PackageError::Malformed);
    }
    let end = PACKAGE_HEADER_BYTES.checked_add(length).ok_or(PackageError::Limit)?;
    if end.checked_add(PACKAGE_TRAILER_BYTES) != Some(bytes.len()) {
        return Err(PackageError::Malformed);
    }
    if bytes[12..44] != expected_root.bytes() {
        return Err(PackageError::RootMismatch);
    }
    if bytes[end..] != ContentDigest::sha256(&bytes[..end]).bytes() {
        return Err(PackageError::Malformed);
    }
    let payload = &bytes[PACKAGE_HEADER_BYTES..end];
    let record = EventExportRecord::from_bytes(payload, ContentDigest::sha256(payload))?;
    if record.manifest()?.root() != expected_root {
        return Err(PackageError::RootMismatch);
    }
    scope.admits(&record)?;
    Ok(VerifiedPackage {
        root: expected_root,
        package_digest: ContentDigest::sha256(bytes),
        record,
    })
}

/// Read one already-committed export as a portable package; this function writes nothing.
///
/// The original approving principal needs BOTH export capabilities. Preparing a new export is
/// a separate operation: a preview-only or merely staged root is refused. Finite-deadline
/// delegation is refused because this synchronous reference has no independent clock owner.
/// Opening the deployment is the caller's responsibility and can have its existing recovery
/// effects; this function does not claim that `ReferenceDeployment::open` is read-only.
pub fn prepare_package(
    deployment: &ReferenceDeployment,
    export_root: ContentDigest,
    scope: &PackageScope,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<PreparedPackage, PackageError> {
    scope.validate()?;
    authority.validate().map_err(|_| PackageError::Unauthorized)?;
    if !authority.has_capability(CAP_EXPORT_PREPARE)
        || !authority.has_capability(CAP_EXPORT_COMMIT)
        || authority.deadline.is_some()
        || authority.cancellation_reason.is_some()
        || authority.principal.len() > 256
        || cx.root_dir() != deployment.root()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
    {
        return Err(PackageError::Unauthorized);
    }
    cx.checkpoint("export_package:read").map_err(|_| PackageError::Cancelled)?;
    deployment.ledger().verify_durable_head().map_err(|_| PackageError::AuthorityChanged)?;
    let deleted = DeletionIndex::read(deployment).map_err(|_| PackageError::AuthorityChanged)?;
    if deleted.object(export_root).is_some() {
        return Err(PackageError::Deleted);
    }
    let (record, _) = read_export(deployment, export_root, authority, cx)?;
    if deleted.object(record.digest()).is_some() {
        return Err(PackageError::Deleted);
    }
    if authority.principal != record.principal() || record.site() != deployment.site_lineage() {
        return Err(PackageError::Unauthorized);
    }
    let hex: String = record.digest().bytes().iter().map(|b| format!("{b:02x}")).collect();
    let object = ObjectId::parse(format!("{EXPORT_OBJECT_PREFIX}{hex}"))
        .map_err(|_| PackageError::AuthorityChanged)?;
    let current = deployment.ledger().current().objects.get(&object)
        .ok_or(PackageError::AuthorityChanged)?;
    if current.family != FAMILY_EVIDENCE_EXPORT
        || current.generation != 1
        || current.payload_digest != export_root
    {
        return Err(PackageError::AuthorityChanged);
    }
    scope.admits(&record)?;
    let bytes = encode_record(&record)?;
    let verified = verify_package(&bytes, export_root, scope)?;
    deployment.ledger().verify_durable_head().map_err(|_| PackageError::AuthorityChanged)?;
    cx.checkpoint("export_package:ready").map_err(|_| PackageError::Cancelled)?;
    Ok(PreparedPackage { bytes, verified })
}

#[cfg(test)]
mod tests;
