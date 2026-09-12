#![forbid(unsafe_code)]
//! Sensor capsule v1 binary/JSON contract (FSS-006).
//!
//! Provides the canonical `SensorCapsuleV1` type with:
//! - Versioned binary encoding (`FSSC` envelope v1) and deterministic JSON projection
//!   that round-trip bit-identically.
//! - Registered schema `fss.sensor_capsule.v1` and digest domain `fss.sensor_capsule.metadata.v1`.
//! - Binding of source, device, and adapter identities from FSS-005.
//! - Source custody and explicit omission fields.
//! - Typed decode errors for truncation, unknown version, trailing bytes, over-limit
//!   lengths, and non-canonical encodings.
//! - Hard size bounds, tested at exact bound and bound+1.

use core::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::identity::{AdapterIdentity, DeviceIdentity, MediaKind, SourceIdentity};
use crate::ids::{AdapterId, CapsuleId, DeviceId, SensorId, SourceId, StreamId};
use crate::time::{CaptureInterval, TimestampNs};
use crate::{ClockBasis, ContentDigest, ContractError};

/// Canonical schema identifier for sensor capsule v1.
pub const SENSOR_CAPSULE_SCHEMA: &str = SensorCapsuleV1::SCHEMA;

/// Canonical metadata digest domain tag for sensor capsule v1.
pub const SENSOR_CAPSULE_METADATA_DOMAIN: &str = "fss.sensor_capsule.metadata.v1";

/// Format magic header for versioned binary sensor capsule envelopes (`FSSC`).
pub const SENSOR_CAPSULE_MAGIC: [u8; 4] = *b"FSSC";

/// Current binary format version.
pub const SENSOR_CAPSULE_VERSION_1: u16 = 1;

// Hard bounds for bounded fields
/// Maximum byte length for capsule identifier.
pub const MAX_CAPSULE_ID_LEN: usize = 128;
/// Maximum byte length for general identifier string.
pub const MAX_STR_LEN: usize = 128;
/// Maximum byte length for codec name string.
pub const MAX_CODEC_LEN: usize = 64;
/// Maximum byte length for container name string.
pub const MAX_CONTAINER_LEN: usize = 64;
/// Maximum byte length for custody storage handle.
pub const MAX_STORAGE_HANDLE_LEN: usize = 256;
/// Maximum byte length for omission policy rule.
pub const MAX_POLICY_RULE_LEN: usize = 256;
/// Maximum byte length for firmware fingerprint.
pub const MAX_FIRMWARE_FINGERPRINT_LEN: usize = 256;
/// Maximum byte length for retention class string.
pub const MAX_RETENTION_CLASS_LEN: usize = 64;
/// Maximum byte length for uncertainty reason string.
pub const MAX_UNCERTAINTY_REASON_LEN: usize = 256;

/// Typed decode errors with no default-on-error behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapsuleDecodeError {
    /// Input data was truncated before reading required field or byte sequence.
    Truncated {
        /// Minimum bytes expected.
        expected_min: usize,
        /// Actual available bytes.
        actual: usize,
    },
    /// Unknown or unsupported encoding format version.
    UnknownVersion {
        /// Decoded version number.
        version: u16,
    },
    /// Trailing unparsed bytes remaining after complete decode.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
    /// A field length strictly exceeds its declared hard bound.
    OverLimitLength {
        /// Name of the offending field.
        field: &'static str,
        /// Hard limit bound.
        limit: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// Non-canonical encoding (e.g. invalid discriminator, illegal magic, non-canonical numbers).
    NonCanonicalEncoding {
        /// Diagnostic detail.
        detail: String,
    },
    /// Schema identity constant mismatch.
    SchemaMismatch {
        /// Expected schema identifier.
        expected: &'static str,
        /// Observed schema identifier.
        found: String,
    },
    /// JSON syntactic or semantic parse error.
    JsonError {
        /// Diagnostic detail.
        detail: String,
    },
    /// Underlying invariant or contract violation.
    Contract(ContractError),
}

impl fmt::Display for CapsuleDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "truncated input: expected at least {expected_min} bytes, found {actual}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(f, "unknown capsule format version: {version}")
            }
            Self::TrailingBytes { count } => {
                write!(f, "trailing unconsumed bytes after decode: {count} bytes")
            }
            Self::OverLimitLength {
                field,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' length exceeds bound: limit={limit}, actual={actual}"
                )
            }
            Self::NonCanonicalEncoding { detail } => {
                write!(f, "non-canonical encoding: {detail}")
            }
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected '{expected}', found '{found}'")
            }
            Self::JsonError { detail } => {
                write!(f, "json decode error: {detail}")
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for CapsuleDecodeError {}

impl From<ContractError> for CapsuleDecodeError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Transport continuity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ContinuityState {
    /// Transport continuity has not been checked.
    Unverified = 1,
    /// Continuous without packet or sequence loss.
    Verified = 2,
    /// At least one packet or sequence gap precedes this capsule.
    Gapped = 3,
    /// Continuity cannot be determined from available transport telemetry.
    Indeterminate = 4,
}

impl ContinuityState {
    /// Returns canonical string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Verified => "verified",
            Self::Gapped => "gapped",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Parses from string.
    pub fn parse(s: &str) -> Result<Self, CapsuleDecodeError> {
        match s {
            "unverified" => Ok(Self::Unverified),
            "verified" => Ok(Self::Verified),
            "gapped" => Ok(Self::Gapped),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown continuity state '{s}'"),
            }),
        }
    }
}

/// Media decodability verification state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DecodeState {
    /// Decode has not been attempted.
    NotAttempted = 1,
    /// Fully decoded and verified without errors.
    Verified = 2,
    /// Decoded with concealed errors or missing slices.
    ConcealedErrors = 3,
    /// Decode failed completely.
    Failed = 4,
}

impl DecodeState {
    /// Returns canonical string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Verified => "verified",
            Self::ConcealedErrors => "concealed_errors",
            Self::Failed => "failed",
        }
    }

    /// Parses from string.
    pub fn parse(s: &str) -> Result<Self, CapsuleDecodeError> {
        match s {
            "not_attempted" => Ok(Self::NotAttempted),
            "verified" => Ok(Self::Verified),
            "concealed_errors" => Ok(Self::ConcealedErrors),
            "failed" => Ok(Self::Failed),
            _ => Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown decode state '{s}'"),
            }),
        }
    }
}

/// Publication status in the canonical ledger.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PublicationState {
    /// Capsule identity reserved but payload not yet materialized.
    Reserved = 1,
    /// Materialized in local spool.
    Materialized = 2,
    /// Published and visible at a canonical ledger commit.
    Published = 3,
    /// Publication aborted or discarded.
    Aborted = 4,
    /// Publication outcome indeterminate; requires reconciliation.
    Indeterminate = 5,
}

impl PublicationState {
    /// Returns canonical string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Materialized => "materialized",
            Self::Published => "published",
            Self::Aborted => "aborted",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Parses from string.
    pub fn parse(s: &str) -> Result<Self, CapsuleDecodeError> {
        match s {
            "reserved" => Ok(Self::Reserved),
            "materialized" => Ok(Self::Materialized),
            "published" => Ok(Self::Published),
            "aborted" => Ok(Self::Aborted),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown publication state '{s}'"),
            }),
        }
    }
}

/// Redaction lifecycle state under privacy policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RedactionState {
    /// No redaction required by active privacy policy.
    NotRequired = 1,
    /// Redaction mask applied to retained media.
    Applied = 2,
    /// Redaction deferred to downstream pipeline.
    Deferred = 3,
    /// Redaction failed closed; raw media suppressed.
    FailedClosed = 4,
}

impl RedactionState {
    /// Returns canonical string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Applied => "applied",
            Self::Deferred => "deferred",
            Self::FailedClosed => "failed_closed",
        }
    }

    /// Parses from string.
    pub fn parse(s: &str) -> Result<Self, CapsuleDecodeError> {
        match s {
            "not_required" => Ok(Self::NotRequired),
            "applied" => Ok(Self::Applied),
            "deferred" => Ok(Self::Deferred),
            "failed_closed" => Ok(Self::FailedClosed),
            _ => Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown redaction state '{s}'"),
            }),
        }
    }
}

/// Explicit semantic reason for omitted media or frames.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OmissionReason {
    /// No omission; complete source captured.
    None = 0,
    /// Omitted to satisfy a privacy mask or redaction rule.
    PrivacyRedaction = 1,
    /// Omitted under resource pressure or budget exhaustion.
    ResourcePressure = 2,
    /// Omitted per retention window or policy expiry.
    RetentionPolicy = 3,
    /// Filtered by missing caller or adapter capability.
    CapabilityFiltered = 4,
    /// Transient preview only; source payload deliberately not ingested.
    TransientPreviewOnly = 5,
    /// Upstream source gap or hardware dropout.
    UpstreamMissing = 6,
}

impl OmissionReason {
    /// Returns canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PrivacyRedaction => "privacy_redaction",
            Self::ResourcePressure => "resource_pressure",
            Self::RetentionPolicy => "retention_policy",
            Self::CapabilityFiltered => "capability_filtered",
            Self::TransientPreviewOnly => "transient_preview_only",
            Self::UpstreamMissing => "upstream_missing",
        }
    }

    /// Parses from string representation.
    pub fn parse(s: &str) -> Result<Self, CapsuleDecodeError> {
        match s {
            "none" => Ok(Self::None),
            "privacy_redaction" => Ok(Self::PrivacyRedaction),
            "resource_pressure" => Ok(Self::ResourcePressure),
            "retention_policy" => Ok(Self::RetentionPolicy),
            "capability_filtered" => Ok(Self::CapabilityFiltered),
            "transient_preview_only" => Ok(Self::TransientPreviewOnly),
            "upstream_missing" => Ok(Self::UpstreamMissing),
            _ => Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown omission reason '{s}'"),
            }),
        }
    }
}

/// Source custody status binding exact source bytes to content-addressed storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceCustody {
    /// Exact source bytes retained under verified custody.
    Retained {
        /// Content digest of exact source bytes.
        source_digest: ContentDigest,
        /// Number of source bytes retained.
        source_bytes: u64,
        /// Storage reference, content-addressed path, or spool handle.
        storage_handle: String,
    },
    /// Source bytes not retained in custody.
    NotRetained,
}

impl SourceCustody {
    /// Returns true if source evidence is retained under custody.
    #[must_use]
    pub const fn is_retained(&self) -> bool {
        matches!(self, Self::Retained { .. })
    }

    /// Returns the source digest if retained.
    #[must_use]
    pub const fn source_digest(&self) -> Option<&ContentDigest> {
        match self {
            Self::Retained { source_digest, .. } => Some(source_digest),
            Self::NotRetained => None,
        }
    }

    /// Returns the retained source byte count.
    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        match self {
            Self::Retained { source_bytes, .. } => *source_bytes,
            Self::NotRetained => 0,
        }
    }

    /// Returns the storage handle if retained.
    #[must_use]
    pub fn storage_handle(&self) -> Option<&str> {
        match self {
            Self::Retained { storage_handle, .. } => Some(storage_handle.as_str()),
            Self::NotRetained => None,
        }
    }
}

/// Explicit omission field declaring intentional or policy omissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplicitOmission {
    /// No omission; complete source captured.
    None,
    /// Explicitly omitted with structured reason and policy rule.
    Omitted {
        /// Categorized reason for omission.
        reason: OmissionReason,
        /// Policy rule identifier or specification.
        policy_rule: String,
        /// Number of omitted bytes.
        omitted_bytes: u64,
        /// Number of omitted frames.
        omitted_frames: u32,
    },
}

impl ExplicitOmission {
    /// Returns true if an omission was declared.
    #[must_use]
    pub const fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted { .. })
    }

    /// Returns the omission reason if omitted.
    #[must_use]
    pub const fn reason(&self) -> Option<OmissionReason> {
        match self {
            Self::Omitted { reason, .. } => Some(*reason),
            Self::None => None,
        }
    }
}

/// Bounded media stream descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDescriptor {
    /// Domain of media.
    pub kind: MediaKind,
    /// Codec designation (e.g. "h264", "opus", "pcm_s16le").
    pub codec: String,
    /// Container format (e.g. "mp4", "mkv", "raw").
    pub container: Option<String>,
    /// Frame width in pixels, if applicable.
    pub width: Option<u32>,
    /// Frame height in pixels, if applicable.
    pub height: Option<u32>,
    /// Total source payload bytes represented.
    pub source_bytes: u64,
    /// Total decoded frames represented.
    pub frame_count: u32,
    /// Optional digest of raw source bytes.
    pub source_digest: Option<ContentDigest>,
    /// Optional digest of decoded or proxy representation.
    pub proxy_digest: Option<ContentDigest>,
}

/// Integrity witness for transport and media decodability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityWitness {
    /// Metadata digest binding frame timing and parameters.
    pub metadata_digest: ContentDigest,
    /// Transport continuity state.
    pub continuity: ContinuityState,
    /// Media decodability state.
    pub decode: DecodeState,
    /// Hardware/firmware fingerprint string.
    pub firmware_fingerprint: Option<String>,
}

/// Privacy and redaction metadata descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyDescriptor {
    /// Generation digest of the active privacy mask, if applied.
    pub mask_generation: Option<ContentDigest>,
    /// Redaction application lifecycle state.
    pub redaction_state: RedactionState,
    /// Retention policy classification code.
    pub retention_class: String,
}

/// Root-last publication descriptor for canonical ledger entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationDescriptor {
    /// Publication lifecycle state.
    pub state: PublicationState,
    /// Merkle root digest under which this capsule is published.
    pub root_digest: ContentDigest,
    /// Canonical ledger revision sequence.
    pub ledger_revision: Option<u64>,
}

/// One canonical sensor capsule representing a bounded media/metadata segment (FSS-006).
///
/// Binds:
/// - Exact source, device, and adapter identities from FSS-005.
/// - Conservative capture-time interval, host arrival time, and clock basis.
/// - Verifiable source custody. A capsule without source custody is not "retained evidence".
/// - Explicit omission declaration for transparent accounting.
/// - Media descriptor, integrity witness, privacy, and publication state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorCapsuleV1 {
    /// Schema identity constant (`fss.sensor_capsule.v1`).
    pub schema: String,
    /// Stable unique capsule identifier.
    pub capsule_id: CapsuleId,
    /// Bound source identifier.
    pub source_id: SourceId,
    /// Bound physical or virtual device identifier.
    pub device_id: DeviceId,
    /// Bound adapter driver identifier.
    pub adapter_id: AdapterId,
    /// Sensor identifier (backward compatibility mapping).
    pub sensor_id: SensorId,
    /// Stream identifier (backward compatibility mapping).
    pub stream_id: StreamId,
    /// Bound immutable source identity from FSS-005.
    pub source_identity: SourceIdentity,
    /// Bound immutable device identity from FSS-005.
    pub device_identity: DeviceIdentity,
    /// Bound immutable adapter identity from FSS-005.
    pub adapter_identity: AdapterIdentity,
    /// Monotonic sequence number within the stream generation.
    pub sequence: u64,
    /// Conservative capture-time interval.
    pub capture_interval: CaptureInterval,
    /// Host arrival receive time.
    pub receive_time_ns: TimestampNs,
    /// Clock synchronization reference basis.
    pub clock_basis: ClockBasis,
    /// Source custody proof.
    pub custody: SourceCustody,
    /// Explicit omission declaration.
    pub omission: ExplicitOmission,
    /// Media payload descriptor.
    pub media: MediaDescriptor,
    /// Integrity and decode witness.
    pub integrity: IntegrityWitness,
    /// Privacy and redaction state.
    pub privacy: PrivacyDescriptor,
    /// Publication state in canonical ledger.
    pub publication: PublicationDescriptor,
}

impl SensorCapsuleV1 {
    /// Schema identity constant.
    pub const SCHEMA: &'static str = "fss.sensor_capsule.v1";
    /// Metadata digest domain constant.
    pub const METADATA_DOMAIN: &'static str = SENSOR_CAPSULE_METADATA_DOMAIN;

    /// Validates field bounds, schema constant, and relational invariants.
    pub fn verify(&self) -> Result<(), CapsuleDecodeError> {
        if self.schema != Self::SCHEMA {
            return Err(CapsuleDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: self.schema.clone(),
            });
        }
        if self.capsule_id.len() > MAX_CAPSULE_ID_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "capsuleId",
                limit: MAX_CAPSULE_ID_LEN,
                actual: self.capsule_id.len(),
            });
        }
        if self.source_id.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "sourceId",
                limit: MAX_STR_LEN,
                actual: self.source_id.len(),
            });
        }
        if self.device_id.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "deviceId",
                limit: MAX_STR_LEN,
                actual: self.device_id.len(),
            });
        }
        if self.adapter_id.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "adapterId",
                limit: MAX_STR_LEN,
                actual: self.adapter_id.len(),
            });
        }
        if self.media.codec.is_empty() || self.media.codec.len() > MAX_CODEC_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "media.codec",
                limit: MAX_CODEC_LEN,
                actual: self.media.codec.len(),
            });
        }
        if let Some(container) = &self.media.container
            && container.len() > MAX_CONTAINER_LEN
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "media.container",
                limit: MAX_CONTAINER_LEN,
                actual: container.len(),
            });
        }
        if let Some(fp) = &self.integrity.firmware_fingerprint
            && fp.len() > MAX_FIRMWARE_FINGERPRINT_LEN
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "integrity.firmwareFingerprint",
                limit: MAX_FIRMWARE_FINGERPRINT_LEN,
                actual: fp.len(),
            });
        }
        if self.privacy.retention_class.len() > MAX_RETENTION_CLASS_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "privacy.retentionClass",
                limit: MAX_RETENTION_CLASS_LEN,
                actual: self.privacy.retention_class.len(),
            });
        }
        if let SourceCustody::Retained { storage_handle, .. } = &self.custody
            && (storage_handle.is_empty() || storage_handle.len() > MAX_STORAGE_HANDLE_LEN)
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "custody.storageHandle",
                limit: MAX_STORAGE_HANDLE_LEN,
                actual: storage_handle.len(),
            });
        }
        if let ExplicitOmission::Omitted { policy_rule, .. } = &self.omission
            && (policy_rule.is_empty() || policy_rule.len() > MAX_POLICY_RULE_LEN)
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "omission.policyRule",
                limit: MAX_POLICY_RULE_LEN,
                actual: policy_rule.len(),
            });
        }

        // Validate temporal invariants
        if self.capture_interval.earliest > self.capture_interval.latest {
            return Err(CapsuleDecodeError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }
        if self.receive_time_ns < self.capture_interval.earliest {
            return Err(CapsuleDecodeError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }

        // Verify embedded identities from 6.5
        self.source_identity
            .verify()
            .map_err(CapsuleDecodeError::Contract)?;
        self.device_identity
            .verify()
            .map_err(CapsuleDecodeError::Contract)?;
        self.adapter_identity
            .verify()
            .map_err(CapsuleDecodeError::Contract)?;

        // Relational binding check: capsule IDs must match embedded identities
        if self.source_id != self.source_identity.source_id {
            return Err(CapsuleDecodeError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if self.device_id != self.device_identity.device_id
            || self.source_identity.device_id != self.device_identity.device_id
        {
            return Err(CapsuleDecodeError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if self.adapter_id != self.adapter_identity.adapter_id
            || self.source_identity.adapter_id != self.adapter_identity.adapter_id
        {
            return Err(CapsuleDecodeError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }

        // Custody check: if retained custody is claimed, digest must match media source digest
        if let SourceCustody::Retained {
            source_digest,
            source_bytes,
            ..
        } = &self.custody
        {
            if let Some(media_digest) = &self.media.source_digest
                && media_digest != source_digest
            {
                return Err(CapsuleDecodeError::Contract(ContractError::DigestMismatch));
            }
            if *source_bytes != self.media.source_bytes {
                return Err(CapsuleDecodeError::Contract(ContractError::DigestMismatch));
            }
        }

        Ok(())
    }

    /// Returns true if this capsule possesses verified source custody.
    ///
    /// Non-negotiable invariant: A capsule without source custody is NOT "retained evidence".
    #[must_use]
    pub fn is_retained_evidence(&self) -> bool {
        self.custody.is_retained()
    }

    /// Fails closed with [`ContractError::EvidenceRequired`] if source custody is missing.
    pub fn require_retained_evidence(&self) -> Result<(), CapsuleDecodeError> {
        if self.is_retained_evidence() {
            Ok(())
        } else {
            Err(CapsuleDecodeError::Contract(
                ContractError::EvidenceRequired,
            ))
        }
    }

    /// Computes the domain-separated metadata digest for this capsule.
    #[must_use]
    pub fn metadata_digest(&self) -> ContentDigest {
        CanonicalEncode::canonical_digest(self, Self::METADATA_DOMAIN)
    }

    /// Serializes this capsule into the canonical versioned binary envelope (`FSSC` v1).
    pub fn to_versioned_bytes(&self) -> Result<Vec<u8>, CapsuleDecodeError> {
        self.verify()?;
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let payload = encoder
            .finish_checked()
            .map_err(CapsuleDecodeError::Contract)?;

        let mut out = Vec::with_capacity(6 + payload.len());
        out.extend_from_slice(&SENSOR_CAPSULE_MAGIC);
        out.extend_from_slice(&SENSOR_CAPSULE_VERSION_1.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decodes a sensor capsule from a complete versioned binary envelope (`FSSC` v1).
    pub fn from_versioned_bytes(bytes: &[u8]) -> Result<Self, CapsuleDecodeError> {
        if bytes.len() < 6 {
            return Err(CapsuleDecodeError::Truncated {
                expected_min: 6,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != SENSOR_CAPSULE_MAGIC {
            return Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: "invalid magic header: expected FSSC".to_string(),
            });
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != SENSOR_CAPSULE_VERSION_1 {
            return Err(CapsuleDecodeError::UnknownVersion { version });
        }

        let mut decoder = CanonicalDecoder::new(&bytes[6..]);
        let capsule = Self::decode_canonical_checked(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(CapsuleDecodeError::TrailingBytes {
                count: decoder.remaining(),
            });
        }
        capsule.verify()?;
        Ok(capsule)
    }

    fn decode_canonical_checked(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, CapsuleDecodeError> {
        let schema = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if schema != Self::SCHEMA {
            return Err(CapsuleDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema.to_string(),
            });
        }
        let capsule_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if capsule_id_str.len() > MAX_CAPSULE_ID_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "capsuleId",
                limit: MAX_CAPSULE_ID_LEN,
                actual: capsule_id_str.len(),
            });
        }
        let capsule_id = CapsuleId::parse(capsule_id_str).map_err(CapsuleDecodeError::Contract)?;

        let source_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if source_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "sourceId",
                limit: MAX_STR_LEN,
                actual: source_id_str.len(),
            });
        }
        let source_id = SourceId::parse(source_id_str).map_err(CapsuleDecodeError::Contract)?;

        let device_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if device_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "deviceId",
                limit: MAX_STR_LEN,
                actual: device_id_str.len(),
            });
        }
        let device_id = DeviceId::parse(device_id_str).map_err(CapsuleDecodeError::Contract)?;

        let adapter_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if adapter_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "adapterId",
                limit: MAX_STR_LEN,
                actual: adapter_id_str.len(),
            });
        }
        let adapter_id = AdapterId::parse(adapter_id_str).map_err(CapsuleDecodeError::Contract)?;

        let sensor_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let sensor_id = SensorId::parse(sensor_id_str).map_err(CapsuleDecodeError::Contract)?;

        let stream_id_str = decoder.text().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let stream_id = StreamId::parse(stream_id_str).map_err(CapsuleDecodeError::Contract)?;

        let sequence = decoder.u64().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;
        let capture_interval =
            CaptureInterval::decode_canonical(decoder).map_err(CapsuleDecodeError::Contract)?;
        let receive_time_ns =
            TimestampNs::decode_canonical(decoder).map_err(CapsuleDecodeError::Contract)?;
        let clock_basis = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => ClockBasis::UtcDisciplined,
            2 => ClockBasis::DeviceMonotonic,
            3 => ClockBasis::HostMonotonic,
            4 => ClockBasis::Estimated,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid clock basis tag".to_string(),
                });
            }
        };

        // Custody
        let custody = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            0 => SourceCustody::NotRetained,
            1 => {
                let source_digest = decoder.digest().map_err(CapsuleDecodeError::Contract)?;
                let source_bytes = decoder.u64().map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 8,
                    actual: 0,
                })?;
                let storage_handle = decoder
                    .text()
                    .map_err(|_| CapsuleDecodeError::Truncated {
                        expected_min: 1,
                        actual: 0,
                    })?
                    .to_string();
                if storage_handle.len() > MAX_STORAGE_HANDLE_LEN {
                    return Err(CapsuleDecodeError::OverLimitLength {
                        field: "custody.storageHandle",
                        limit: MAX_STORAGE_HANDLE_LEN,
                        actual: storage_handle.len(),
                    });
                }
                SourceCustody::Retained {
                    source_digest,
                    source_bytes,
                    storage_handle,
                }
            }
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid custody tag".to_string(),
                });
            }
        };

        // Omission
        let omission = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            0 => ExplicitOmission::None,
            1 => {
                let reason = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })? {
                    0 => OmissionReason::None,
                    1 => OmissionReason::PrivacyRedaction,
                    2 => OmissionReason::ResourcePressure,
                    3 => OmissionReason::RetentionPolicy,
                    4 => OmissionReason::CapabilityFiltered,
                    5 => OmissionReason::TransientPreviewOnly,
                    6 => OmissionReason::UpstreamMissing,
                    _ => {
                        return Err(CapsuleDecodeError::NonCanonicalEncoding {
                            detail: "invalid omission reason tag".to_string(),
                        });
                    }
                };
                let policy_rule = decoder
                    .text()
                    .map_err(|_| CapsuleDecodeError::Truncated {
                        expected_min: 1,
                        actual: 0,
                    })?
                    .to_string();
                if policy_rule.len() > MAX_POLICY_RULE_LEN {
                    return Err(CapsuleDecodeError::OverLimitLength {
                        field: "omission.policyRule",
                        limit: MAX_POLICY_RULE_LEN,
                        actual: policy_rule.len(),
                    });
                }
                let omitted_bytes = decoder.u64().map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 8,
                    actual: 0,
                })?;
                let omitted_frames = decoder.u32().map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 4,
                    actual: 0,
                })?;
                ExplicitOmission::Omitted {
                    reason,
                    policy_rule,
                    omitted_bytes,
                    omitted_frames,
                }
            }
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid omission tag".to_string(),
                });
            }
        };

        // Media
        let kind = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => MediaKind::Video,
            2 => MediaKind::Audio,
            3 => MediaKind::Image,
            4 => MediaKind::Metadata,
            5 => MediaKind::Compound,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid media kind tag".to_string(),
                });
            }
        };
        let codec = decoder
            .text()
            .map_err(|_| CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .to_string();
        if codec.is_empty() || codec.len() > MAX_CODEC_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "media.codec",
                limit: MAX_CODEC_LEN,
                actual: codec.len(),
            });
        }
        let container = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            let c = decoder
                .text()
                .map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if c.len() > MAX_CONTAINER_LEN {
                return Err(CapsuleDecodeError::OverLimitLength {
                    field: "media.container",
                    limit: MAX_CONTAINER_LEN,
                    actual: c.len(),
                });
            }
            Some(c)
        } else {
            None
        };
        let width = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.u32().map_err(|_| CapsuleDecodeError::Truncated {
                expected_min: 4,
                actual: 0,
            })?)
        } else {
            None
        };
        let height = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.u32().map_err(|_| CapsuleDecodeError::Truncated {
                expected_min: 4,
                actual: 0,
            })?)
        } else {
            None
        };
        let source_bytes = decoder.u64().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;
        let frame_count = decoder.u32().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 4,
            actual: 0,
        })?;
        let source_digest = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.digest().map_err(CapsuleDecodeError::Contract)?)
        } else {
            None
        };
        let proxy_digest = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.digest().map_err(CapsuleDecodeError::Contract)?)
        } else {
            None
        };

        let media = MediaDescriptor {
            kind,
            codec,
            container,
            width,
            height,
            source_bytes,
            frame_count,
            source_digest,
            proxy_digest,
        };

        // Integrity
        let metadata_digest = decoder.digest().map_err(CapsuleDecodeError::Contract)?;
        let continuity = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => ContinuityState::Unverified,
            2 => ContinuityState::Verified,
            3 => ContinuityState::Gapped,
            4 => ContinuityState::Indeterminate,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid continuity tag".to_string(),
                });
            }
        };
        let decode = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => DecodeState::NotAttempted,
            2 => DecodeState::Verified,
            3 => DecodeState::ConcealedErrors,
            4 => DecodeState::Failed,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid decode tag".to_string(),
                });
            }
        };
        let firmware_fingerprint = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            let fp = decoder
                .text()
                .map_err(|_| CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if fp.len() > MAX_FIRMWARE_FINGERPRINT_LEN {
                return Err(CapsuleDecodeError::OverLimitLength {
                    field: "integrity.firmwareFingerprint",
                    limit: MAX_FIRMWARE_FINGERPRINT_LEN,
                    actual: fp.len(),
                });
            }
            Some(fp)
        } else {
            None
        };
        let integrity = IntegrityWitness {
            metadata_digest,
            continuity,
            decode,
            firmware_fingerprint,
        };

        // Privacy
        let mask_generation = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.digest().map_err(CapsuleDecodeError::Contract)?)
        } else {
            None
        };
        let redaction_state = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => RedactionState::NotRequired,
            2 => RedactionState::Applied,
            3 => RedactionState::Deferred,
            4 => RedactionState::FailedClosed,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid redaction state tag".to_string(),
                });
            }
        };
        let retention_class = decoder
            .text()
            .map_err(|_| CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .to_string();
        if retention_class.len() > MAX_RETENTION_CLASS_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "privacy.retentionClass",
                limit: MAX_RETENTION_CLASS_LEN,
                actual: retention_class.len(),
            });
        }
        let privacy = PrivacyDescriptor {
            mask_generation,
            redaction_state,
            retention_class,
        };

        // Publication
        let state = match decoder.u8().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            1 => PublicationState::Reserved,
            2 => PublicationState::Materialized,
            3 => PublicationState::Published,
            4 => PublicationState::Aborted,
            5 => PublicationState::Indeterminate,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: "invalid publication state tag".to_string(),
                });
            }
        };
        let root_digest = decoder.digest().map_err(CapsuleDecodeError::Contract)?;
        let ledger_revision = if decoder.bool().map_err(|_| CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })? {
            Some(decoder.u64().map_err(|_| CapsuleDecodeError::Truncated {
                expected_min: 8,
                actual: 0,
            })?)
        } else {
            None
        };
        let publication = PublicationDescriptor {
            state,
            root_digest,
            ledger_revision,
        };

        // Identities
        let source_identity =
            SourceIdentity::decode_canonical(decoder).map_err(CapsuleDecodeError::Contract)?;
        let device_identity =
            DeviceIdentity::decode_canonical(decoder).map_err(CapsuleDecodeError::Contract)?;
        let adapter_identity =
            AdapterIdentity::decode_canonical(decoder).map_err(CapsuleDecodeError::Contract)?;

        Ok(Self {
            schema: schema.to_string(),
            capsule_id,
            source_id,
            device_id,
            adapter_id,
            sensor_id,
            stream_id,
            source_identity,
            device_identity,
            adapter_identity,
            sequence,
            capture_interval,
            receive_time_ns,
            clock_basis,
            custody,
            omission,
            media,
            integrity,
            privacy,
            publication,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push('{');

        // Deterministic alphabetical key serialization
        // 1. adapterId
        out.push_str("\"adapterId\":");
        json_write_str(&mut out, self.adapter_id.as_str());
        out.push(',');

        // 2. adapterIdentity
        out.push_str("\"adapterIdentity\":{");
        out.push_str("\"adapterId\":");
        json_write_str(&mut out, self.adapter_identity.adapter_id.as_str());
        out.push_str(",\"adapterKind\":");
        json_write_str(&mut out, self.adapter_identity.adapter_kind.as_str());
        out.push_str(",\"capabilities\":");
        out.push_str(&self.adapter_identity.capabilities.bits().to_string());
        out.push_str(",\"credentialMethod\":");
        json_write_str(&mut out, self.adapter_identity.credential_method.as_str());
        out.push_str(",\"generation\":");
        json_write_str(&mut out, self.adapter_identity.generation.as_str());
        out.push_str(",\"isolationMode\":");
        json_write_str(&mut out, self.adapter_identity.isolation_mode.as_str());
        out.push_str(",\"maxBandwidthBytesPerSec\":");
        out.push_str(
            &self
                .adapter_identity
                .max_bandwidth_bytes_per_sec
                .to_string(),
        );
        out.push_str(",\"maxBufferFrames\":");
        out.push_str(&self.adapter_identity.max_buffer_frames.to_string());
        out.push_str(",\"protocolProfile\":");
        json_write_str(&mut out, &self.adapter_identity.protocol_profile);
        out.push_str(",\"requestTimeoutNs\":");
        out.push_str(&self.adapter_identity.request_timeout_ns.to_string());
        out.push_str(",\"schema\":");
        json_write_str(&mut out, AdapterIdentity::SCHEMA);
        out.push_str("},\"capsuleId\":");

        // 3. capsuleId
        json_write_str(&mut out, self.capsule_id.as_str());
        out.push_str(",\"captureInterval\":{");

        // 4. captureInterval
        out.push_str("\"earliestNs\":");
        out.push_str(&self.capture_interval.earliest.0.to_string());
        out.push_str(",\"latestNs\":");
        out.push_str(&self.capture_interval.latest.0.to_string());
        out.push_str(",\"uncertaintyReason\":");
        json_write_str(&mut out, "conservative_capture_window");
        out.push_str("},\"clockBasis\":");

        // 5. clockBasis
        match self.clock_basis {
            ClockBasis::UtcDisciplined => json_write_str(&mut out, "utc_disciplined"),
            ClockBasis::DeviceMonotonic => json_write_str(&mut out, "device_monotonic"),
            ClockBasis::HostMonotonic => json_write_str(&mut out, "host_monotonic"),
            ClockBasis::Estimated => json_write_str(&mut out, "estimated"),
        }
        out.push_str(",\"custody\":{");

        // 6. custody
        out.push_str("\"isRetained\":");
        out.push_str(if self.custody.is_retained() {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"sourceBytes\":");
        out.push_str(&self.custody.source_bytes().to_string());
        out.push_str(",\"sourceDigest\":");
        match self.custody.source_digest() {
            Some(d) => json_write_str(&mut out, &d.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"storageHandle\":");
        match self.custody.storage_handle() {
            Some(h) => json_write_str(&mut out, h),
            None => json_write_str(&mut out, ""),
        }
        out.push_str("},\"deviceId\":");

        // 7. deviceId
        json_write_str(&mut out, self.device_id.as_str());
        out.push_str(",\"deviceIdentity\":{");

        // 8. deviceIdentity
        out.push_str("\"applicationVersion\":");
        match &self.device_identity.application_version {
            Some(app) => json_write_str(&mut out, app.as_str()),
            None => out.push_str("null"),
        }
        out.push_str(",\"capabilities\":");
        out.push_str(&self.device_identity.capabilities.bits().to_string());
        out.push_str(",\"deviceClass\":");
        json_write_str(&mut out, self.device_identity.device_class.as_str());
        out.push_str(",\"deviceId\":");
        json_write_str(&mut out, self.device_identity.device_id.as_str());
        out.push_str(",\"failureDomain\":");
        json_write_str(&mut out, &self.device_identity.failure_domain);
        out.push_str(",\"firmwareVersion\":");
        json_write_str(&mut out, self.device_identity.firmware_version.as_str());
        out.push_str(",\"generation\":");
        json_write_str(&mut out, self.device_identity.generation.as_str());
        out.push_str(",\"hardwareRevision\":");
        json_write_str(&mut out, &self.device_identity.hardware_revision);
        out.push_str(",\"manufacturer\":");
        json_write_str(&mut out, &self.device_identity.manufacturer);
        out.push_str(",\"model\":");
        json_write_str(&mut out, &self.device_identity.model);
        out.push_str(",\"modelGeneration\":");
        match &self.device_identity.model_generation {
            Some(mg) => json_write_str(&mut out, mg.as_str()),
            None => out.push_str("null"),
        }
        out.push_str(",\"schema\":");
        json_write_str(&mut out, DeviceIdentity::SCHEMA);
        out.push_str("},\"integrity\":{");

        // 9. integrity
        out.push_str("\"continuity\":");
        json_write_str(&mut out, self.integrity.continuity.as_str());
        out.push_str(",\"decode\":");
        json_write_str(&mut out, self.integrity.decode.as_str());
        out.push_str(",\"firmwareFingerprint\":");
        match &self.integrity.firmware_fingerprint {
            Some(fp) => json_write_str(&mut out, fp),
            None => out.push_str("null"),
        }
        out.push_str(",\"metadataDigest\":");
        json_write_str(&mut out, &self.integrity.metadata_digest.to_string());
        out.push_str("},\"media\":{");

        // 10. media
        out.push_str("\"codec\":");
        json_write_str(&mut out, &self.media.codec);
        out.push_str(",\"container\":");
        match &self.media.container {
            Some(c) => json_write_str(&mut out, c),
            None => out.push_str("null"),
        }
        out.push_str(",\"frameCount\":");
        out.push_str(&self.media.frame_count.to_string());
        out.push_str(",\"height\":");
        match self.media.height {
            Some(h) => out.push_str(&h.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"kind\":");
        json_write_str(&mut out, self.media.kind.as_str());
        out.push_str(",\"proxyDigest\":");
        match &self.media.proxy_digest {
            Some(d) => json_write_str(&mut out, &d.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"sourceBytes\":");
        out.push_str(&self.media.source_bytes.to_string());
        out.push_str(",\"sourceDigest\":");
        match &self.media.source_digest {
            Some(d) => json_write_str(&mut out, &d.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"width\":");
        match self.media.width {
            Some(w) => out.push_str(&w.to_string()),
            None => out.push_str("null"),
        }
        out.push_str("},\"omission\":{");

        // 11. omission
        out.push_str("\"isOmitted\":");
        out.push_str(if self.omission.is_omitted() {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"omittedBytes\":");
        match &self.omission {
            ExplicitOmission::Omitted { omitted_bytes, .. } => {
                out.push_str(&omitted_bytes.to_string())
            }
            ExplicitOmission::None => out.push('0'),
        }
        out.push_str(",\"omittedFrames\":");
        match &self.omission {
            ExplicitOmission::Omitted { omitted_frames, .. } => {
                out.push_str(&omitted_frames.to_string())
            }
            ExplicitOmission::None => out.push('0'),
        }
        out.push_str(",\"policyRule\":");
        match &self.omission {
            ExplicitOmission::Omitted { policy_rule, .. } => json_write_str(&mut out, policy_rule),
            ExplicitOmission::None => json_write_str(&mut out, ""),
        }
        out.push_str(",\"reason\":");
        match &self.omission {
            ExplicitOmission::Omitted { reason, .. } => json_write_str(&mut out, reason.as_str()),
            ExplicitOmission::None => json_write_str(&mut out, "none"),
        }
        out.push_str("},\"privacy\":{");

        // 12. privacy
        out.push_str("\"maskGeneration\":");
        match &self.privacy.mask_generation {
            Some(mg) => json_write_str(&mut out, &mg.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"redactionState\":");
        json_write_str(&mut out, self.privacy.redaction_state.as_str());
        out.push_str(",\"retentionClass\":");
        json_write_str(&mut out, &self.privacy.retention_class);
        out.push_str("},\"publication\":{");

        // 13. publication
        out.push_str("\"ledgerRevision\":");
        match self.publication.ledger_revision {
            Some(rev) => out.push_str(&rev.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"rootDigest\":");
        json_write_str(&mut out, &self.publication.root_digest.to_string());
        out.push_str(",\"state\":");
        json_write_str(&mut out, self.publication.state.as_str());
        out.push_str("},\"receiveTimeNs\":");

        // 14. receiveTimeNs
        out.push_str(&self.receive_time_ns.0.to_string());
        out.push_str(",\"schema\":");

        // 15. schema
        json_write_str(&mut out, Self::SCHEMA);
        out.push_str(",\"sensorId\":");

        // 16. sensorId
        json_write_str(&mut out, self.sensor_id.as_str());
        out.push_str(",\"sequence\":");

        // 17. sequence
        out.push_str(&self.sequence.to_string());
        out.push_str(",\"sourceId\":");

        // 18. sourceId
        json_write_str(&mut out, self.source_id.as_str());
        out.push_str(",\"sourceIdentity\":{");

        // 19. sourceIdentity
        out.push_str("\"adapterId\":");
        json_write_str(&mut out, self.source_identity.adapter_id.as_str());
        out.push_str(",\"channel\":");
        json_write_str(&mut out, &self.source_identity.channel);
        out.push_str(",\"deviceId\":");
        json_write_str(&mut out, self.source_identity.device_id.as_str());
        out.push_str(",\"failureDomain\":");
        json_write_str(&mut out, &self.source_identity.failure_domain);
        out.push_str(",\"isLive\":");
        out.push_str(if self.source_identity.is_live {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"mediaKind\":");
        json_write_str(&mut out, self.source_identity.media_kind.as_str());
        out.push_str(",\"nominalClockBasis\":");
        match self.source_identity.nominal_clock_basis {
            ClockBasis::UtcDisciplined => json_write_str(&mut out, "utc_disciplined"),
            ClockBasis::DeviceMonotonic => json_write_str(&mut out, "device_monotonic"),
            ClockBasis::HostMonotonic => json_write_str(&mut out, "host_monotonic"),
            ClockBasis::Estimated => json_write_str(&mut out, "estimated"),
        }
        out.push_str(",\"schema\":");
        json_write_str(&mut out, SourceIdentity::SCHEMA);
        out.push_str(",\"sourceId\":");
        json_write_str(&mut out, self.source_identity.source_id.as_str());
        out.push_str(",\"sourceKind\":");
        json_write_str(&mut out, self.source_identity.source_kind.as_str());
        out.push_str(",\"streamGeneration\":");
        json_write_str(&mut out, self.source_identity.stream_generation.as_str());
        out.push_str("},\"streamId\":");

        // 20. streamId
        json_write_str(&mut out, self.stream_id.as_str());
        out.push('}');
        out
    }

    /// Decodes a sensor capsule from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, CapsuleDecodeError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser.parse_value()?;
        parser.ensure_finished()?;

        let obj = match root {
            JsonValue::Object(map) => map,
            _ => {
                return Err(CapsuleDecodeError::JsonError {
                    detail: "root must be an object".to_string(),
                });
            }
        };

        let get_field = |name: &str| -> Result<&JsonValue, CapsuleDecodeError> {
            obj.iter().find(|(k, _)| k == name).map(|(_, v)| v).ok_or(
                CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                },
            )
        };

        let schema_val = get_field("schema")?.as_str()?;
        if schema_val != Self::SCHEMA {
            return Err(CapsuleDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let capsule_id_str = get_field("capsuleId")?.as_str()?;
        if capsule_id_str.len() > MAX_CAPSULE_ID_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "capsuleId",
                limit: MAX_CAPSULE_ID_LEN,
                actual: capsule_id_str.len(),
            });
        }
        let capsule_id = CapsuleId::parse(capsule_id_str).map_err(CapsuleDecodeError::Contract)?;

        let source_id_str = get_field("sourceId")?.as_str()?;
        if source_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "sourceId",
                limit: MAX_STR_LEN,
                actual: source_id_str.len(),
            });
        }
        let source_id = SourceId::parse(source_id_str).map_err(CapsuleDecodeError::Contract)?;

        let device_id_str = get_field("deviceId")?.as_str()?;
        if device_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "deviceId",
                limit: MAX_STR_LEN,
                actual: device_id_str.len(),
            });
        }
        let device_id = DeviceId::parse(device_id_str).map_err(CapsuleDecodeError::Contract)?;

        let adapter_id_str = get_field("adapterId")?.as_str()?;
        if adapter_id_str.len() > MAX_STR_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "adapterId",
                limit: MAX_STR_LEN,
                actual: adapter_id_str.len(),
            });
        }
        let adapter_id = AdapterId::parse(adapter_id_str).map_err(CapsuleDecodeError::Contract)?;

        let sensor_id_str = get_field("sensorId")?.as_str()?;
        let sensor_id = SensorId::parse(sensor_id_str).map_err(CapsuleDecodeError::Contract)?;

        let stream_id_str = get_field("streamId")?.as_str()?;
        let stream_id = StreamId::parse(stream_id_str).map_err(CapsuleDecodeError::Contract)?;

        let sequence = get_field("sequence")?.as_u64()?;

        // CaptureInterval
        let interval_obj = get_field("captureInterval")?.as_object()?;
        let earliest_ns = interval_obj
            .iter()
            .find(|(k, _)| k == "earliestNs")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_i128()?;
        let latest_ns = interval_obj
            .iter()
            .find(|(k, _)| k == "latestNs")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_i128()?;
        let capture_interval =
            CaptureInterval::new(TimestampNs(earliest_ns), TimestampNs(latest_ns))
                .map_err(CapsuleDecodeError::Contract)?;

        let receive_time_ns = TimestampNs(get_field("receiveTimeNs")?.as_i128()?);

        let clock_basis_str = get_field("clockBasis")?.as_str()?;
        let clock_basis = match clock_basis_str {
            "utc_disciplined" => ClockBasis::UtcDisciplined,
            "device_monotonic" => ClockBasis::DeviceMonotonic,
            "host_monotonic" => ClockBasis::HostMonotonic,
            "estimated" => ClockBasis::Estimated,
            _ => {
                return Err(CapsuleDecodeError::NonCanonicalEncoding {
                    detail: format!("unknown clock basis '{clock_basis_str}'"),
                });
            }
        };

        // Custody
        let custody_obj = get_field("custody")?.as_object()?;
        let is_retained = custody_obj
            .iter()
            .find(|(k, _)| k == "isRetained")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_bool()?;
        let custody = if is_retained {
            let digest_val = custody_obj
                .iter()
                .find(|(k, _)| k == "sourceDigest")
                .and_then(|(_, v)| v.as_opt_str())
                .flatten()
                .ok_or_else(|| CapsuleDecodeError::JsonError {
                    detail: "retained custody requires sourceDigest".to_string(),
                })?;
            let source_digest =
                ContentDigest::parse(digest_val).map_err(CapsuleDecodeError::Contract)?;
            let source_bytes = custody_obj
                .iter()
                .find(|(k, _)| k == "sourceBytes")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_u64()?;
            let storage_handle = custody_obj
                .iter()
                .find(|(k, _)| k == "storageHandle")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_str()?
                .to_string();
            if storage_handle.len() > MAX_STORAGE_HANDLE_LEN {
                return Err(CapsuleDecodeError::OverLimitLength {
                    field: "custody.storageHandle",
                    limit: MAX_STORAGE_HANDLE_LEN,
                    actual: storage_handle.len(),
                });
            }
            SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            }
        } else {
            SourceCustody::NotRetained
        };

        // Omission
        let omission_obj = get_field("omission")?.as_object()?;
        let is_omitted = omission_obj
            .iter()
            .find(|(k, _)| k == "isOmitted")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_bool()?;
        let omission = if is_omitted {
            let reason_str = omission_obj
                .iter()
                .find(|(k, _)| k == "reason")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_str()?;
            let reason = OmissionReason::parse(reason_str)?;
            let policy_rule = omission_obj
                .iter()
                .find(|(k, _)| k == "policyRule")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_str()?
                .to_string();
            if policy_rule.len() > MAX_POLICY_RULE_LEN {
                return Err(CapsuleDecodeError::OverLimitLength {
                    field: "omission.policyRule",
                    limit: MAX_POLICY_RULE_LEN,
                    actual: policy_rule.len(),
                });
            }
            let omitted_bytes = omission_obj
                .iter()
                .find(|(k, _)| k == "omittedBytes")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_u64()?;
            let omitted_frames = omission_obj
                .iter()
                .find(|(k, _)| k == "omittedFrames")
                .ok_or(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .1
                .as_u32()?;
            ExplicitOmission::Omitted {
                reason,
                policy_rule,
                omitted_bytes,
                omitted_frames,
            }
        } else {
            ExplicitOmission::None
        };

        // Media
        let media_obj = get_field("media")?.as_object()?;
        let kind_str = media_obj
            .iter()
            .find(|(k, _)| k == "kind")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let kind = MediaKind::parse(kind_str).map_err(CapsuleDecodeError::Contract)?;
        let codec = media_obj
            .iter()
            .find(|(k, _)| k == "codec")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?
            .to_string();
        if codec.len() > MAX_CODEC_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "media.codec",
                limit: MAX_CODEC_LEN,
                actual: codec.len(),
            });
        }
        let container = media_obj
            .iter()
            .find(|(k, _)| k == "container")
            .and_then(|(_, v)| v.as_opt_str())
            .flatten()
            .map(ToOwned::to_owned);
        if let Some(c) = &container
            && c.len() > MAX_CONTAINER_LEN
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "media.container",
                limit: MAX_CONTAINER_LEN,
                actual: c.len(),
            });
        }
        let width = media_obj
            .iter()
            .find(|(k, _)| k == "width")
            .and_then(|(_, v)| v.as_opt_u32())
            .flatten();
        let height = media_obj
            .iter()
            .find(|(k, _)| k == "height")
            .and_then(|(_, v)| v.as_opt_u32())
            .flatten();
        let source_bytes = media_obj
            .iter()
            .find(|(k, _)| k == "sourceBytes")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_u64()?;
        let frame_count = media_obj
            .iter()
            .find(|(k, _)| k == "frameCount")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_u32()?;
        let source_digest = media_obj
            .iter()
            .find(|(k, _)| k == "sourceDigest")
            .and_then(|(_, v)| v.as_opt_str())
            .flatten()
            .map(ContentDigest::parse)
            .transpose()
            .map_err(CapsuleDecodeError::Contract)?;
        let proxy_digest = media_obj
            .iter()
            .find(|(k, _)| k == "proxyDigest")
            .and_then(|(_, v)| v.as_opt_str())
            .flatten()
            .map(ContentDigest::parse)
            .transpose()
            .map_err(CapsuleDecodeError::Contract)?;

        let media = MediaDescriptor {
            kind,
            codec,
            container,
            width,
            height,
            source_bytes,
            frame_count,
            source_digest,
            proxy_digest,
        };

        // Integrity
        let integrity_obj = get_field("integrity")?.as_object()?;
        let metadata_digest_str = integrity_obj
            .iter()
            .find(|(k, _)| k == "metadataDigest")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let metadata_digest =
            ContentDigest::parse(metadata_digest_str).map_err(CapsuleDecodeError::Contract)?;
        let continuity_str = integrity_obj
            .iter()
            .find(|(k, _)| k == "continuity")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let continuity = ContinuityState::parse(continuity_str)?;
        let decode_str = integrity_obj
            .iter()
            .find(|(k, _)| k == "decode")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let decode = DecodeState::parse(decode_str)?;
        let firmware_fingerprint = integrity_obj
            .iter()
            .find(|(k, _)| k == "firmwareFingerprint")
            .and_then(|(_, v)| v.as_opt_str())
            .flatten()
            .map(ToOwned::to_owned);
        if let Some(fp) = &firmware_fingerprint
            && fp.len() > MAX_FIRMWARE_FINGERPRINT_LEN
        {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "integrity.firmwareFingerprint",
                limit: MAX_FIRMWARE_FINGERPRINT_LEN,
                actual: fp.len(),
            });
        }
        let integrity = IntegrityWitness {
            metadata_digest,
            continuity,
            decode,
            firmware_fingerprint,
        };

        // Privacy
        let privacy_obj = get_field("privacy")?.as_object()?;
        let mask_generation = privacy_obj
            .iter()
            .find(|(k, _)| k == "maskGeneration")
            .and_then(|(_, v)| v.as_opt_str())
            .flatten()
            .map(ContentDigest::parse)
            .transpose()
            .map_err(CapsuleDecodeError::Contract)?;
        let redaction_str = privacy_obj
            .iter()
            .find(|(k, _)| k == "redactionState")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let redaction_state = RedactionState::parse(redaction_str)?;
        let retention_class = privacy_obj
            .iter()
            .find(|(k, _)| k == "retentionClass")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?
            .to_string();
        if retention_class.len() > MAX_RETENTION_CLASS_LEN {
            return Err(CapsuleDecodeError::OverLimitLength {
                field: "privacy.retentionClass",
                limit: MAX_RETENTION_CLASS_LEN,
                actual: retention_class.len(),
            });
        }
        let privacy = PrivacyDescriptor {
            mask_generation,
            redaction_state,
            retention_class,
        };

        // Publication
        let pub_obj = get_field("publication")?.as_object()?;
        let pub_state_str = pub_obj
            .iter()
            .find(|(k, _)| k == "state")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let state = PublicationState::parse(pub_state_str)?;
        let root_digest_str = pub_obj
            .iter()
            .find(|(k, _)| k == "rootDigest")
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()?;
        let root_digest =
            ContentDigest::parse(root_digest_str).map_err(CapsuleDecodeError::Contract)?;
        let ledger_revision = pub_obj
            .iter()
            .find(|(k, _)| k == "ledgerRevision")
            .and_then(|(_, v)| v.as_opt_u64())
            .flatten();
        let publication = PublicationDescriptor {
            state,
            root_digest,
            ledger_revision,
        };

        // Identities: parse nested SourceIdentity, DeviceIdentity, AdapterIdentity
        let source_id_obj = get_field("sourceIdentity")?.as_object()?;
        let source_identity = parse_source_identity_from_json(source_id_obj)?;

        let device_id_obj = get_field("deviceIdentity")?.as_object()?;
        let device_identity = parse_device_identity_from_json(device_id_obj)?;

        let adapter_id_obj = get_field("adapterIdentity")?.as_object()?;
        let adapter_identity = parse_adapter_identity_from_json(adapter_id_obj)?;

        let capsule = Self {
            schema: schema_val.to_string(),
            capsule_id,
            source_id,
            device_id,
            adapter_id,
            sensor_id,
            stream_id,
            source_identity,
            device_identity,
            adapter_identity,
            sequence,
            capture_interval,
            receive_time_ns,
            clock_basis,
            custody,
            omission,
            media,
            integrity,
            privacy,
            publication,
        };
        capsule.verify()?;
        Ok(capsule)
    }
}

fn parse_source_identity_from_json(
    obj: &[(String, JsonValue)],
) -> Result<SourceIdentity, CapsuleDecodeError> {
    use crate::identity::SourceKind;
    use crate::ids::StreamGeneration;

    let get_str = |name: &str| -> Result<&str, CapsuleDecodeError> {
        obj.iter()
            .find(|(k, _)| k == name)
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()
    };
    let schema = get_str("schema")?;
    if schema != SourceIdentity::SCHEMA {
        return Err(CapsuleDecodeError::SchemaMismatch {
            expected: SourceIdentity::SCHEMA,
            found: schema.to_string(),
        });
    }
    let source_id = SourceId::parse(get_str("sourceId")?).map_err(CapsuleDecodeError::Contract)?;
    let device_id = DeviceId::parse(get_str("deviceId")?).map_err(CapsuleDecodeError::Contract)?;
    let adapter_id =
        AdapterId::parse(get_str("adapterId")?).map_err(CapsuleDecodeError::Contract)?;
    let source_kind =
        SourceKind::parse(get_str("sourceKind")?).map_err(CapsuleDecodeError::Contract)?;
    let media_kind =
        MediaKind::parse(get_str("mediaKind")?).map_err(CapsuleDecodeError::Contract)?;
    let channel = get_str("channel")?.to_string();
    let clock_str = get_str("nominalClockBasis")?;
    let nominal_clock_basis = match clock_str {
        "utc_disciplined" => ClockBasis::UtcDisciplined,
        "device_monotonic" => ClockBasis::DeviceMonotonic,
        "host_monotonic" => ClockBasis::HostMonotonic,
        "estimated" => ClockBasis::Estimated,
        _ => {
            return Err(CapsuleDecodeError::NonCanonicalEncoding {
                detail: format!("unknown clock basis '{clock_str}'"),
            });
        }
    };
    let stream_generation = StreamGeneration::parse(get_str("streamGeneration")?)
        .map_err(CapsuleDecodeError::Contract)?;
    let failure_domain = get_str("failureDomain")?.to_string();
    let is_live = obj
        .iter()
        .find(|(k, _)| k == "isLive")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_bool()?;

    let id = SourceIdentity {
        source_id,
        device_id,
        adapter_id,
        source_kind,
        media_kind,
        channel,
        nominal_clock_basis,
        stream_generation,
        failure_domain,
        is_live,
    };
    id.verify().map_err(CapsuleDecodeError::Contract)?;
    Ok(id)
}

fn parse_device_identity_from_json(
    obj: &[(String, JsonValue)],
) -> Result<DeviceIdentity, CapsuleDecodeError> {
    use crate::identity::{DeviceCapabilities, DeviceClass};
    use crate::ids::{AppGeneration, DeviceGeneration, FirmwareGeneration, ModelGeneration};

    let get_str = |name: &str| -> Result<&str, CapsuleDecodeError> {
        obj.iter()
            .find(|(k, _)| k == name)
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()
    };
    let schema = get_str("schema")?;
    if schema != DeviceIdentity::SCHEMA {
        return Err(CapsuleDecodeError::SchemaMismatch {
            expected: DeviceIdentity::SCHEMA,
            found: schema.to_string(),
        });
    }
    let device_id = DeviceId::parse(get_str("deviceId")?).map_err(CapsuleDecodeError::Contract)?;
    let generation =
        DeviceGeneration::parse(get_str("generation")?).map_err(CapsuleDecodeError::Contract)?;
    let manufacturer = get_str("manufacturer")?.to_string();
    let model = get_str("model")?.to_string();
    let hardware_revision = get_str("hardwareRevision")?.to_string();
    let firmware_version = FirmwareGeneration::parse(get_str("firmwareVersion")?)
        .map_err(CapsuleDecodeError::Contract)?;
    let application_version = obj
        .iter()
        .find(|(k, _)| k == "applicationVersion")
        .and_then(|(_, v)| v.as_opt_str())
        .flatten()
        .map(AppGeneration::parse)
        .transpose()
        .map_err(CapsuleDecodeError::Contract)?;
    let model_generation = obj
        .iter()
        .find(|(k, _)| k == "modelGeneration")
        .and_then(|(_, v)| v.as_opt_str())
        .flatten()
        .map(ModelGeneration::parse)
        .transpose()
        .map_err(CapsuleDecodeError::Contract)?;
    let device_class =
        DeviceClass::parse(get_str("deviceClass")?).map_err(CapsuleDecodeError::Contract)?;
    let cap_bits = obj
        .iter()
        .find(|(k, _)| k == "capabilities")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_u32()?;
    let capabilities =
        DeviceCapabilities::from_bits(cap_bits).map_err(CapsuleDecodeError::Contract)?;
    let failure_domain = get_str("failureDomain")?.to_string();

    let id = DeviceIdentity {
        device_id,
        generation,
        manufacturer,
        model,
        hardware_revision,
        firmware_version,
        application_version,
        model_generation,
        device_class,
        capabilities,
        failure_domain,
    };
    id.verify().map_err(CapsuleDecodeError::Contract)?;
    Ok(id)
}

fn parse_adapter_identity_from_json(
    obj: &[(String, JsonValue)],
) -> Result<AdapterIdentity, CapsuleDecodeError> {
    use crate::identity::{AdapterCapabilities, AdapterKind, CredentialMethod, IsolationMode};
    use crate::ids::AdapterGeneration;

    let get_str = |name: &str| -> Result<&str, CapsuleDecodeError> {
        obj.iter()
            .find(|(k, _)| k == name)
            .ok_or(CapsuleDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .1
            .as_str()
    };
    let schema = get_str("schema")?;
    if schema != AdapterIdentity::SCHEMA {
        return Err(CapsuleDecodeError::SchemaMismatch {
            expected: AdapterIdentity::SCHEMA,
            found: schema.to_string(),
        });
    }
    let adapter_id =
        AdapterId::parse(get_str("adapterId")?).map_err(CapsuleDecodeError::Contract)?;
    let generation =
        AdapterGeneration::parse(get_str("generation")?).map_err(CapsuleDecodeError::Contract)?;
    let adapter_kind =
        AdapterKind::parse(get_str("adapterKind")?).map_err(CapsuleDecodeError::Contract)?;
    let protocol_profile = get_str("protocolProfile")?.to_string();
    let isolation_mode =
        IsolationMode::parse(get_str("isolationMode")?).map_err(CapsuleDecodeError::Contract)?;
    let credential_method = CredentialMethod::parse(get_str("credentialMethod")?)
        .map_err(CapsuleDecodeError::Contract)?;
    let cap_bits = obj
        .iter()
        .find(|(k, _)| k == "capabilities")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_u32()?;
    let capabilities =
        AdapterCapabilities::from_bits(cap_bits).map_err(CapsuleDecodeError::Contract)?;
    let max_bandwidth = obj
        .iter()
        .find(|(k, _)| k == "maxBandwidthBytesPerSec")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_u64()?;
    let max_buffer_frames = obj
        .iter()
        .find(|(k, _)| k == "maxBufferFrames")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_u32()?;
    let request_timeout_ns = obj
        .iter()
        .find(|(k, _)| k == "requestTimeoutNs")
        .ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?
        .1
        .as_u64()?;

    let id = AdapterIdentity {
        adapter_id,
        generation,
        adapter_kind,
        protocol_profile,
        isolation_mode,
        credential_method,
        capabilities,
        max_bandwidth_bytes_per_sec: max_bandwidth,
        max_buffer_frames,
        request_timeout_ns,
    };
    id.verify().map_err(CapsuleDecodeError::Contract)?;
    Ok(id)
}

impl CanonicalEncode for SensorCapsuleV1 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.capsule_id.encode_canonical(encoder);
        self.source_id.encode_canonical(encoder);
        self.device_id.encode_canonical(encoder);
        self.adapter_id.encode_canonical(encoder);
        self.sensor_id.encode_canonical(encoder);
        self.stream_id.encode_canonical(encoder);
        encoder.u64(self.sequence);
        self.capture_interval.encode_canonical(encoder);
        self.receive_time_ns.encode_canonical(encoder);
        encoder.u8(match self.clock_basis {
            ClockBasis::UtcDisciplined => 1,
            ClockBasis::DeviceMonotonic => 2,
            ClockBasis::HostMonotonic => 3,
            ClockBasis::Estimated => 4,
        });

        // Custody
        match &self.custody {
            SourceCustody::NotRetained => {
                encoder.u8(0);
            }
            SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            } => {
                encoder.u8(1);
                encoder.digest(*source_digest);
                encoder.u64(*source_bytes);
                encoder.text(storage_handle);
            }
        }

        // Omission
        match &self.omission {
            ExplicitOmission::None => {
                encoder.u8(0);
            }
            ExplicitOmission::Omitted {
                reason,
                policy_rule,
                omitted_bytes,
                omitted_frames,
            } => {
                encoder.u8(1);
                encoder.u8(*reason as u8);
                encoder.text(policy_rule);
                encoder.u64(*omitted_bytes);
                encoder.u32(*omitted_frames);
            }
        }

        // Media
        encoder.u8(self.media.kind as u8);
        encoder.text(&self.media.codec);
        match &self.media.container {
            Some(c) => {
                encoder.bool(true);
                encoder.text(c);
            }
            None => encoder.bool(false),
        }
        match self.media.width {
            Some(w) => {
                encoder.bool(true);
                encoder.u32(w);
            }
            None => encoder.bool(false),
        }
        match self.media.height {
            Some(h) => {
                encoder.bool(true);
                encoder.u32(h);
            }
            None => encoder.bool(false),
        }
        encoder.u64(self.media.source_bytes);
        encoder.u32(self.media.frame_count);
        match &self.media.source_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(*d);
            }
            None => encoder.bool(false),
        }
        match &self.media.proxy_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(*d);
            }
            None => encoder.bool(false),
        }

        // Integrity
        encoder.digest(self.integrity.metadata_digest);
        encoder.u8(self.integrity.continuity as u8);
        encoder.u8(self.integrity.decode as u8);
        match &self.integrity.firmware_fingerprint {
            Some(fp) => {
                encoder.bool(true);
                encoder.text(fp);
            }
            None => encoder.bool(false),
        }

        // Privacy
        match &self.privacy.mask_generation {
            Some(mg) => {
                encoder.bool(true);
                encoder.digest(*mg);
            }
            None => encoder.bool(false),
        }
        encoder.u8(self.privacy.redaction_state as u8);
        encoder.text(&self.privacy.retention_class);

        // Publication
        encoder.u8(self.publication.state as u8);
        encoder.digest(self.publication.root_digest);
        match self.publication.ledger_revision {
            Some(rev) => {
                encoder.bool(true);
                encoder.u64(rev);
            }
            None => encoder.bool(false),
        }

        // Identities
        self.source_identity.encode_canonical(encoder);
        self.device_identity.encode_canonical(encoder);
        self.adapter_identity.encode_canonical(encoder);
    }
}

impl CanonicalDecode for SensorCapsuleV1 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::decode_canonical_checked(decoder).map_err(|e| match e {
            CapsuleDecodeError::Contract(c) => c,
            _ => ContractError::InvalidIdentifier,
        })
    }
}

// Minimal deterministic JSON serializer helper
fn json_write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
}

// Minimal recursive-descent JSON parser
#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(i128),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_str(&self) -> Result<&str, CapsuleDecodeError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            _ => Err(CapsuleDecodeError::JsonError {
                detail: "expected string".to_string(),
            }),
        }
    }

    fn as_opt_str(&self) -> Option<Option<&str>> {
        match self {
            Self::Null => Some(None),
            Self::String(s) => Some(Some(s.as_str())),
            _ => None,
        }
    }

    fn as_bool(&self) -> Result<bool, CapsuleDecodeError> {
        match self {
            Self::Bool(b) => Ok(*b),
            _ => Err(CapsuleDecodeError::JsonError {
                detail: "expected boolean".to_string(),
            }),
        }
    }

    fn as_i128(&self) -> Result<i128, CapsuleDecodeError> {
        match self {
            Self::Number(n) => Ok(*n),
            _ => Err(CapsuleDecodeError::JsonError {
                detail: "expected number".to_string(),
            }),
        }
    }

    fn as_u64(&self) -> Result<u64, CapsuleDecodeError> {
        let n = self.as_i128()?;
        u64::try_from(n).map_err(|_| CapsuleDecodeError::JsonError {
            detail: "negative or overflowing u64".to_string(),
        })
    }

    fn as_u32(&self) -> Result<u32, CapsuleDecodeError> {
        let n = self.as_i128()?;
        u32::try_from(n).map_err(|_| CapsuleDecodeError::JsonError {
            detail: "negative or overflowing u32".to_string(),
        })
    }

    fn as_opt_u32(&self) -> Option<Option<u32>> {
        match self {
            Self::Null => Some(None),
            Self::Number(n) => u32::try_from(*n).ok().map(Some),
            _ => None,
        }
    }

    fn as_opt_u64(&self) -> Option<Option<u64>> {
        match self {
            Self::Null => Some(None),
            Self::Number(n) => u64::try_from(*n).ok().map(Some),
            _ => None,
        }
    }

    fn as_object(&self) -> Result<&[(String, JsonValue)], CapsuleDecodeError> {
        match self {
            Self::Object(m) => Ok(m.as_slice()),
            _ => Err(CapsuleDecodeError::JsonError {
                detail: "expected object".to_string(),
            }),
        }
    }
}

struct JsonParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            src: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len()
            && matches!(self.src[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        if self.pos < self.src.len() {
            Some(self.src[self.pos])
        } else {
            None
        }
    }

    fn ensure_finished(&mut self) -> Result<(), CapsuleDecodeError> {
        self.skip_whitespace();
        if self.pos < self.src.len() {
            Err(CapsuleDecodeError::TrailingBytes {
                count: self.src.len() - self.pos,
            })
        } else {
            Ok(())
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, CapsuleDecodeError> {
        let b = self.peek().ok_or(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(JsonValue::String),
            b't' | b'f' => self.parse_bool().map(JsonValue::Bool),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number().map(JsonValue::Number),
            _ => Err(CapsuleDecodeError::JsonError {
                detail: format!("unexpected character '{}'", b as char),
            }),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, CapsuleDecodeError> {
        self.pos += 1; // skip '{'
        let mut fields = Vec::new();
        self.skip_whitespace();
        if self.pos < self.src.len() && self.src[self.pos] == b'}' {
            self.pos += 1;
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_whitespace();
            if self.pos >= self.src.len() || self.src[self.pos] != b'"' {
                return Err(CapsuleDecodeError::JsonError {
                    detail: "expected object key string".to_string(),
                });
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.pos >= self.src.len() || self.src[self.pos] != b':' {
                return Err(CapsuleDecodeError::JsonError {
                    detail: "expected ':' after key".to_string(),
                });
            }
            self.pos += 1; // skip ':'
            let val = self.parse_value()?;
            fields.push((key, val));
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                });
            }
            if self.src[self.pos] == b',' {
                self.pos += 1;
                continue;
            }
            if self.src[self.pos] == b'}' {
                self.pos += 1;
                break;
            }
            return Err(CapsuleDecodeError::JsonError {
                detail: "expected ',' or '}' in object".to_string(),
            });
        }
        Ok(JsonValue::Object(fields))
    }

    fn parse_array(&mut self) -> Result<JsonValue, CapsuleDecodeError> {
        self.pos += 1; // skip '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.pos < self.src.len() && self.src[self.pos] == b']' {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let val = self.parse_value()?;
            items.push(val);
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(CapsuleDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                });
            }
            if self.src[self.pos] == b',' {
                self.pos += 1;
                continue;
            }
            if self.src[self.pos] == b']' {
                self.pos += 1;
                break;
            }
            return Err(CapsuleDecodeError::JsonError {
                detail: "expected ',' or ']' in array".to_string(),
            });
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, CapsuleDecodeError> {
        self.pos += 1; // skip opening quote
        let mut s = String::new();
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(s),
                b'\\' => {
                    if self.pos >= self.src.len() {
                        return Err(CapsuleDecodeError::Truncated {
                            expected_min: 1,
                            actual: 0,
                        });
                    }
                    let esc = self.src[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\x08'),
                        b'f' => s.push('\x0c'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.src.len() {
                                return Err(CapsuleDecodeError::Truncated {
                                    expected_min: 4,
                                    actual: self.src.len() - self.pos,
                                });
                            }
                            let hex_str = core::str::from_utf8(&self.src[self.pos..self.pos + 4])
                                .map_err(|_| CapsuleDecodeError::JsonError {
                                detail: "invalid unicode escape".to_string(),
                            })?;
                            self.pos += 4;
                            let codepoint = u16::from_str_radix(hex_str, 16).map_err(|_| {
                                CapsuleDecodeError::JsonError {
                                    detail: "invalid unicode hex digits".to_string(),
                                }
                            })?;
                            let ch = char::from_u32(codepoint as u32).unwrap_or('\u{FFFD}');
                            s.push(ch);
                        }
                        _ => {
                            return Err(CapsuleDecodeError::JsonError {
                                detail: format!("invalid escape \\\\{}", esc as char),
                            });
                        }
                    }
                }
                other => s.push(other as char),
            }
        }
        Err(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })
    }

    fn parse_bool(&mut self) -> Result<bool, CapsuleDecodeError> {
        if self.src[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.src[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(CapsuleDecodeError::JsonError {
                detail: "expected boolean".to_string(),
            })
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, CapsuleDecodeError> {
        if self.src[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(CapsuleDecodeError::JsonError {
                detail: "expected null".to_string(),
            })
        }
    }

    fn parse_number(&mut self) -> Result<i128, CapsuleDecodeError> {
        let start = self.pos;
        if self.pos < self.src.len() && self.src[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let slice = core::str::from_utf8(&self.src[start..self.pos]).map_err(|_| {
            CapsuleDecodeError::JsonError {
                detail: "invalid number utf-8".to_string(),
            }
        })?;
        slice
            .parse::<i128>()
            .map_err(|_| CapsuleDecodeError::JsonError {
                detail: format!("failed to parse integer '{slice}'"),
            })
    }
}
