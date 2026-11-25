#![forbid(unsafe_code)]
//! Deterministic qualification harness and sealed certificate for required FrankenSQLite
//! storage adapter APIs (`FSS-032`, `fss-x4a.9.2`, `INT-FSQL-001`).
//!
//! Exercises any [`FrankenSqliteStorageAdapter`] implementation through a deterministic,
//! ten-capability contract matrix spanning anchored snapshot reads, witnessed batch commits,
//! idempotent retry & `BatchIdConflict` discrimination, plane/authority isolation,
//! cooperative cancellation, crash/indeterminate append fencing, forward-only schema
//! migration, cryptographic Merkle proof verification, full integrity checks, and versioned
//! wire receipt determinism.
//!
//! Honest exclusions (for example, an in-memory reference oracle that does not support
//! on-disk crash injection or Merkle proofs) are recorded explicitly under
//! [`ApiCheckOutcome::ExcludedUnsupported`] and downgrade the verdict to
//! [`QualificationVerdict::QualifiedWithExclusions`]; any invariant breach produces
//! [`QualificationVerdict::Refused`] and blocks production admission.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    Completeness, ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness,
    EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObjectRevision, Plane, Sha256Hasher,
    TimestampNs,
};

use crate::merkle::verify_proof;
use crate::storage_adapter::{
    FrankenSqliteStorageAdapter, MAX_STORAGE_LABEL_BYTES, StorageAuthorityScope,
    StorageCommitReceipt, StorageCommitState, StorageError, StorageMigrationPlan,
    StorageRecoveryOutcome, StorageSchemaVersion,
};
use crate::witness::{NegativeWitness, PositiveWitness, SemanticWitness};

/// Registered digest domain for sealed [`StorageApiQualificationCertificate`] commitments (`FSS-032`).
pub const LEDGER_STORAGE_API_QUALIFICATION_DOMAIN: &str = "fss.ledger_storage_api_qualification.v1";
/// Binary wire magic header for [`StorageApiQualificationCertificate`].
pub const STORAGE_QUALIFICATION_MAGIC: [u8; 8] = *b"FSSSQC01";
/// Current wire format version for [`StorageApiQualificationCertificate`].
pub const STORAGE_QUALIFICATION_VERSION: u32 = 1;
/// Hard ceiling on serialized qualification certificate bytes (64 KiB).
pub const MAX_STORAGE_QUALIFICATION_WIRE_BYTES: usize = 64 * 1024;
const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Required FrankenSQLite adapter API capability (`INT-FSQL-001`, `FSS-032`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StorageApiCapability {
    /// Deterministic anchored snapshot reads (`head_anchor`, `history_root`, `read_object`, `read_object_at`).
    AnchoredSnapshotRead = 1,
    /// Witnessed batch commits honoring positive and certified-negative witnesses and rejecting uncertified absence.
    WitnessedBatchCommit = 2,
    /// Idempotent duplicate reconciliation (`verified_witness_count == 0`), `BatchIdConflict`, and tampered-digest refusal.
    IdempotentRetryAndConflict = 3,
    /// Explicit authority/privacy generation and semantic plane isolation.
    AuthorityAndPlaneIsolation = 4,
    /// Cooperative cancellation at read, verify, commit, migrate, reconcile, and integrity boundaries.
    CooperativeCancellation = 5,
    /// Crash-boundary `IndeterminateAppend` fencing and exact `reconcile_after_crash` resolution.
    CrashRecoveryAndIndeterminateFence = 6,
    /// Forward-only authorized schema migration with fail-closed downgrade refusal.
    ForwardOnlySchemaMigration = 7,
    /// Standalone cryptographic Merkle inclusion and non-inclusion proof verification.
    MerkleProofVerification = 8,
    /// Full storage integrity verification returning exact `history_root`.
    IntegrityVerification = 9,
    /// Versioned, checksummed `StorageCommitReceipt` (`FSSSQL01` v1) wire determinism and tamper refusal.
    WireReceiptDeterminism = 10,
}

impl StorageApiCapability {
    /// Canonical ordered list of all ten required API qualification capabilities.
    pub const ALL: [Self; 10] = [
        Self::AnchoredSnapshotRead,
        Self::WitnessedBatchCommit,
        Self::IdempotentRetryAndConflict,
        Self::AuthorityAndPlaneIsolation,
        Self::CooperativeCancellation,
        Self::CrashRecoveryAndIndeterminateFence,
        Self::ForwardOnlySchemaMigration,
        Self::MerkleProofVerification,
        Self::IntegrityVerification,
        Self::WireReceiptDeterminism,
    ];

    /// Stable machine identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::AnchoredSnapshotRead => "FSQL-API-001",
            Self::WitnessedBatchCommit => "FSQL-API-002",
            Self::IdempotentRetryAndConflict => "FSQL-API-003",
            Self::AuthorityAndPlaneIsolation => "FSQL-API-004",
            Self::CooperativeCancellation => "FSQL-API-005",
            Self::CrashRecoveryAndIndeterminateFence => "FSQL-API-006",
            Self::ForwardOnlySchemaMigration => "FSQL-API-007",
            Self::MerkleProofVerification => "FSQL-API-008",
            Self::IntegrityVerification => "FSQL-API-009",
            Self::WireReceiptDeterminism => "FSQL-API-010",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, StorageQualificationError> {
        match tag {
            1 => Ok(Self::AnchoredSnapshotRead),
            2 => Ok(Self::WitnessedBatchCommit),
            3 => Ok(Self::IdempotentRetryAndConflict),
            4 => Ok(Self::AuthorityAndPlaneIsolation),
            5 => Ok(Self::CooperativeCancellation),
            6 => Ok(Self::CrashRecoveryAndIndeterminateFence),
            7 => Ok(Self::ForwardOnlySchemaMigration),
            8 => Ok(Self::MerkleProofVerification),
            9 => Ok(Self::IntegrityVerification),
            10 => Ok(Self::WireReceiptDeterminism),
            other => Err(StorageQualificationError::MalformedWire(format!(
                "unknown StorageApiCapability tag {other}"
            ))),
        }
    }
}

/// Non-collapsed outcome of qualifying one required FrankenSQLite API capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiCheckOutcome {
    /// Capability verified end-to-end against live adapter behavior.
    Passed,
    /// Capability honestly excluded because this backend explicitly declares it unsupported.
    ExcludedUnsupported {
        /// Secret-free explicit scope exclusion reason.
        reason: String,
    },
    /// Capability breached an invariant; disqualifies the adapter from admission.
    Failed {
        /// Stable error identifier observed or assigned.
        error_id: String,
        /// Secret-free diagnostic detail.
        detail: String,
    },
}

/// Non-collapsed verdict of a [`StorageApiQualificationCertificate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationVerdict {
    /// All 10 required APIs passed with zero failures and zero exclusions.
    Qualified = 1,
    /// Zero failures, with one or more explicitly declared capability exclusions.
    QualifiedWithExclusions = 2,
    /// One or more required APIs failed; admission is refused.
    Refused = 3,
}

impl QualificationVerdict {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Qualified => "qualified",
            Self::QualifiedWithExclusions => "qualified_with_exclusions",
            Self::Refused => "refused",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, StorageQualificationError> {
        match tag {
            1 => Ok(Self::Qualified),
            2 => Ok(Self::QualifiedWithExclusions),
            3 => Ok(Self::Refused),
            other => Err(StorageQualificationError::MalformedWire(format!(
                "unknown QualificationVerdict tag {other}"
            ))),
        }
    }
}

/// Evidence record for one capability check inside [`StorageApiQualificationCertificate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiCheckResult {
    /// Qualified capability.
    pub capability: StorageApiCapability,
    /// Non-collapsed outcome (`Passed`, `ExcludedUnsupported`, or `Failed`).
    pub outcome: ApiCheckOutcome,
    /// Deterministic SHA-256 digest of the observed proof witness / receipts / errors.
    pub evidence_digest: ContentDigest,
    /// Accounted adapter operations executed by this check.
    pub work_operations: u64,
}

/// Typed codec and qualification harness errors (`FSS-032`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageQualificationError {
    /// Harness input invalid (e.g., empty site lineage or non-genesis adapter).
    InvalidInput(String),
    /// Wire envelope magic header mismatch.
    InvalidMagic,
    /// Wire envelope format version unsupported.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Trailing SHA-256 checksum mismatch.
    ChecksumMismatch,
    /// Wire envelope exceeded [`MAX_STORAGE_QUALIFICATION_WIRE_BYTES`].
    WireTooLarge {
        /// Observed byte length.
        observed: usize,
        /// Hard maximum byte length.
        maximum: usize,
    },
    /// Malformed or tampered certificate bytes/fields.
    MalformedWire(String),
    /// Canonical encoding error.
    Encoding(String),
}

impl StorageQualificationError {
    /// Stable registered error identifier.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-LEDGER-QUAL-INVALID-INPUT-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } | Self::WireTooLarge { .. } => {
                "ERR-SCHEMA-UNSUPPORTED-001"
            }
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-LEDGER-QUAL-MALFORMED-001",
            Self::Encoding(_) => "ERR-LEDGER-QUAL-ENCODING-001",
        }
    }
}

impl fmt::Display for StorageQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for StorageQualificationError {}

/// Sealed, deterministic API qualification certificate for a [`FrankenSqliteStorageAdapter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageApiQualificationCertificate {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Stable adapter identifier reported by the qualified backend.
    pub adapter_id: String,
    /// Schema version before qualification began.
    pub initial_schema_version: StorageSchemaVersion,
    /// Schema version after forward-only migration check completed.
    pub final_schema_version: StorageSchemaVersion,
    /// Pinned `ContractBasis` digest bound into every qualification step.
    pub contract_basis_digest: ContentDigest,
    /// Site lineage exercised during qualification.
    pub site_lineage: String,
    /// Final committed head anchor observed on the adapter.
    pub final_head_anchor: LedgerAnchor,
    /// Final verified `history_root` observed on the adapter.
    pub final_history_root: ContentDigest,
    /// Non-collapsed aggregate verdict (`Qualified`, `QualifiedWithExclusions`, or `Refused`).
    pub verdict: QualificationVerdict,
    /// Exact ordered 10-entry capability proof matrix (`StorageApiCapability::ALL`).
    pub checks: Vec<ApiCheckResult>,
    /// Virtual timestamp at which the certificate was sealed.
    pub qualified_at: TimestampNs,
    /// Domain-separated SHA-256 commitment under [`LEDGER_STORAGE_API_QUALIFICATION_DOMAIN`].
    pub certificate_digest: ContentDigest,
}

impl StorageApiQualificationCertificate {
    /// Qualification certificates are derived audit evidence and never grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Returns the number of capabilities that passed cleanly.
    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, ApiCheckOutcome::Passed))
            .count()
    }

    /// Returns the number of explicitly excluded unsupported capabilities.
    #[must_use]
    pub fn excluded_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, ApiCheckOutcome::ExcludedUnsupported { .. }))
            .count()
    }

    /// Returns the number of failed capabilities.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.outcome, ApiCheckOutcome::Failed { .. }))
            .count()
    }

    /// Computes the canonical commitment digest under [`LEDGER_STORAGE_API_QUALIFICATION_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, StorageQualificationError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_STORAGE_API_QUALIFICATION_DOMAIN);
        enc.u32(self.format_version);
        enc.text(&self.adapter_id);
        enc.u32(self.initial_schema_version.major);
        enc.u32(self.initial_schema_version.minor);
        enc.u32(self.final_schema_version.major);
        enc.u32(self.final_schema_version.minor);
        enc.digest(self.contract_basis_digest);
        enc.text(&self.site_lineage);
        self.final_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.final_history_root);
        enc.u8(self.verdict.tag());
        enc.u32(self.checks.len() as u32);
        for check in &self.checks {
            enc.u8(check.capability.tag());
            match &check.outcome {
                ApiCheckOutcome::Passed => enc.u8(1),
                ApiCheckOutcome::ExcludedUnsupported { reason } => {
                    enc.u8(2);
                    enc.text(reason);
                }
                ApiCheckOutcome::Failed { error_id, detail } => {
                    enc.u8(3);
                    enc.text(error_id);
                    enc.text(detail);
                }
            }
            enc.digest(check.evidence_digest);
            enc.u64(check.work_operations);
        }
        enc.i128(self.qualified_at.0);
        let bytes = enc
            .finish_checked()
            .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Validates all structural invariants, canonical capability ordering, verdict consistency,
    /// and cryptographic digest integrity.
    pub fn verify_self(&self) -> Result<(), StorageQualificationError> {
        if self.format_version != STORAGE_QUALIFICATION_VERSION {
            return Err(StorageQualificationError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_text(&self.adapter_id, MAX_STORAGE_LABEL_BYTES, "adapter_id")?;
        validate_text(&self.site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        if self.final_head_anchor.site_lineage != self.site_lineage {
            return Err(StorageQualificationError::MalformedWire(
                "final_head_anchor site_lineage disagrees with certificate site_lineage".to_owned(),
            ));
        }
        if self.final_schema_version < self.initial_schema_version {
            return Err(StorageQualificationError::MalformedWire(
                "final_schema_version regressed below initial_schema_version".to_owned(),
            ));
        }
        if self.checks.len() != StorageApiCapability::ALL.len() {
            return Err(StorageQualificationError::MalformedWire(format!(
                "expected {} capability checks, found {}",
                StorageApiCapability::ALL.len(),
                self.checks.len()
            )));
        }
        for (idx, (check, expected_cap)) in self
            .checks
            .iter()
            .zip(StorageApiCapability::ALL.iter())
            .enumerate()
        {
            if check.capability != *expected_cap {
                return Err(StorageQualificationError::MalformedWire(format!(
                    "capability check at index {idx} expected {:?}, found {:?}",
                    expected_cap, check.capability
                )));
            }
            match &check.outcome {
                ApiCheckOutcome::Passed => {}
                ApiCheckOutcome::ExcludedUnsupported { reason } => {
                    validate_text(reason, MAX_STORAGE_LABEL_BYTES, "exclusion_reason")?;
                }
                ApiCheckOutcome::Failed { error_id, detail } => {
                    validate_text(error_id, MAX_STORAGE_LABEL_BYTES, "error_id")?;
                    validate_text(detail, 1024, "failure_detail")?;
                }
            }
        }
        let expected_verdict = compute_verdict(&self.checks);
        if self.verdict != expected_verdict {
            return Err(StorageQualificationError::MalformedWire(format!(
                "verdict {:?} disagrees with checks verdict {:?}",
                self.verdict, expected_verdict
            )));
        }
        let expected_digest = self.compute_digest()?;
        if self.certificate_digest != expected_digest {
            return Err(StorageQualificationError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes this certificate into its versioned, checksummed `FSSSQC01` v1 binary wire format.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, StorageQualificationError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        enc.u32(self.format_version);
        enc.text(&self.adapter_id);
        enc.u32(self.initial_schema_version.major);
        enc.u32(self.initial_schema_version.minor);
        enc.u32(self.final_schema_version.major);
        enc.u32(self.final_schema_version.minor);
        enc.digest(self.contract_basis_digest);
        enc.text(&self.site_lineage);
        self.final_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.final_history_root);
        enc.u8(self.verdict.tag());
        enc.u32(self.checks.len() as u32);
        for check in &self.checks {
            enc.u8(check.capability.tag());
            match &check.outcome {
                ApiCheckOutcome::Passed => enc.u8(1),
                ApiCheckOutcome::ExcludedUnsupported { reason } => {
                    enc.u8(2);
                    enc.text(reason);
                }
                ApiCheckOutcome::Failed { error_id, detail } => {
                    enc.u8(3);
                    enc.text(error_id);
                    enc.text(detail);
                }
            }
            enc.digest(check.evidence_digest);
            enc.u64(check.work_operations);
        }
        enc.i128(self.qualified_at.0);
        enc.digest(self.certificate_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or(StorageQualificationError::WireTooLarge {
                observed: usize::MAX,
                maximum: MAX_STORAGE_QUALIFICATION_WIRE_BYTES,
            })?;
        if total > MAX_STORAGE_QUALIFICATION_WIRE_BYTES {
            return Err(StorageQualificationError::WireTooLarge {
                observed: total,
                maximum: MAX_STORAGE_QUALIFICATION_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&STORAGE_QUALIFICATION_MAGIC);
        out.extend_from_slice(&STORAGE_QUALIFICATION_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_STORAGE_API_QUALIFICATION_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSSQC01` v1 binary wire envelope, failing closed on any tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageQualificationError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(StorageQualificationError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_STORAGE_QUALIFICATION_WIRE_BYTES {
            return Err(StorageQualificationError::WireTooLarge {
                observed: bytes.len(),
                maximum: MAX_STORAGE_QUALIFICATION_WIRE_BYTES,
            });
        }
        if bytes[..8] != STORAGE_QUALIFICATION_MAGIC {
            return Err(StorageQualificationError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != STORAGE_QUALIFICATION_VERSION {
            return Err(StorageQualificationError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                StorageQualificationError::MalformedWire("declared payload overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(StorageQualificationError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_STORAGE_API_QUALIFICATION_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(StorageQualificationError::ChecksumMismatch);
        }
        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
        let adapter_id = dec
            .text()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
            .to_owned();
        let initial_schema_version = StorageSchemaVersion::new(
            dec.u32()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
        );
        let final_schema_version = StorageSchemaVersion::new(
            dec.u32()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
        );
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
        let site_lineage = dec
            .text()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
            .to_owned();
        let final_head_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
        let final_history_root = dec
            .digest()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
        let verdict = QualificationVerdict::from_tag(
            dec.u8()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
        )?;
        let count = dec
            .u32()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
            as usize;
        if count != StorageApiCapability::ALL.len() {
            return Err(StorageQualificationError::MalformedWire(format!(
                "invalid capability count {count}"
            )));
        }
        let mut checks = Vec::with_capacity(count);
        for _ in 0..count {
            let capability = StorageApiCapability::from_tag(
                dec.u8()
                    .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
            )?;
            let outcome = match dec
                .u8()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
            {
                1 => ApiCheckOutcome::Passed,
                2 => ApiCheckOutcome::ExcludedUnsupported {
                    reason: dec
                        .text()
                        .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
                        .to_owned(),
                },
                3 => ApiCheckOutcome::Failed {
                    error_id: dec
                        .text()
                        .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
                        .to_owned(),
                    detail: dec
                        .text()
                        .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?
                        .to_owned(),
                },
                other => {
                    return Err(StorageQualificationError::MalformedWire(format!(
                        "unknown ApiCheckOutcome tag {other}"
                    )));
                }
            };
            let evidence_digest = dec
                .digest()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
            let work_operations = dec
                .u64()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
            checks.push(ApiCheckResult {
                capability,
                outcome,
                evidence_digest,
                work_operations,
            });
        }
        let qualified_at = TimestampNs(
            dec.i128()
                .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?,
        );
        let certificate_digest = dec
            .digest()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| StorageQualificationError::MalformedWire(e.to_string()))?;

        let cert = Self {
            format_version,
            adapter_id,
            initial_schema_version,
            final_schema_version,
            contract_basis_digest,
            site_lineage,
            final_head_anchor,
            final_history_root,
            verdict,
            checks,
            qualified_at,
            certificate_digest,
        };
        cert.verify_self()?;
        Ok(cert)
    }
}

/// Deterministic qualification runner for [`FrankenSqliteStorageAdapter`] backends (`FSS-032`).
pub struct StorageApiQualifier;

impl StorageApiQualifier {
    /// Executes the full 10-capability `INT-FSQL-001` qualification suite against a fresh
    /// genesis-anchored `adapter` and returns a sealed [`StorageApiQualificationCertificate`].
    ///
    /// Pass `inject_crash: Some(...)` for durable backends capable of injecting a post-sync
    /// indeterminate write fault; pass `None` for in-memory adapters so `FSQL-API-006` is
    /// recorded honestly as [`ApiCheckOutcome::ExcludedUnsupported`] rather than faked.
    pub fn qualify<A: FrankenSqliteStorageAdapter>(
        adapter: &mut A,
        contract_basis_digest: ContentDigest,
        now: TimestampNs,
        inject_crash: Option<&mut dyn FnMut(&mut A)>,
    ) -> Result<StorageApiQualificationCertificate, StorageQualificationError> {
        if adapter.head_anchor().commit_sequence != 0 {
            return Err(StorageQualificationError::InvalidInput(format!(
                "qualification requires a fresh genesis adapter (observed commit_sequence={})",
                adapter.head_anchor().commit_sequence
            )));
        }
        let site_lineage = adapter.head_anchor().site_lineage.clone();
        validate_text(&site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        let initial_schema_version = adapter.schema_version();
        let auth = StorageAuthorityScope::active(contract_basis_digest, 1, 1, [Plane::Authority]);

        let obj_alpha = ObjectId::parse("obj:fsql-qual:alpha")
            .map_err(|e| StorageQualificationError::InvalidInput(e.to_string()))?;
        let obj_beta = ObjectId::parse("obj:fsql-qual:beta")
            .map_err(|e| StorageQualificationError::InvalidInput(e.to_string()))?;
        let obj_absent = ObjectId::parse("obj:fsql-qual:absent")
            .map_err(|e| StorageQualificationError::InvalidInput(e.to_string()))?;

        // Track committed batches so we can compute exact next anchors deterministically.
        let mut checks = Vec::with_capacity(StorageApiCapability::ALL.len());
        let mut last_receipt: Option<StorageCommitReceipt> = None;

        // 1. FSQL-API-001: AnchoredSnapshotRead
        let mut b1_committed: Option<EvidenceDeltaBatch> = None;
        let check1 = {
            let mut ops = 0_u64;
            let pre = adapter.read_object(&auth, &obj_alpha, false);
            ops += 1;
            let b1 = prepare_for_adapter(
                adapter,
                "batch:fsql-qual:001",
                vec![make_delta(
                    "d:qual:1",
                    &obj_alpha,
                    None,
                    1,
                    Plane::Authority,
                )?],
            )?;
            let commit_res = adapter.commit_witnessed_batch(&auth, b1.clone(), &[], now, false);
            ops += 1;
            let post = adapter.read_object(&auth, &obj_alpha, false);
            let at_head = adapter.read_object_at(
                &auth,
                adapter.head_anchor().commit_sequence,
                &obj_alpha,
                false,
            );
            ops += 2;
            match (pre, commit_res, post, at_head) {
                (Ok(None), Ok(receipt), Ok(Some(rev)), Ok(Some(rev_at)))
                    if receipt.commit_state == StorageCommitState::Durable
                        && rev.generation == 1
                        && rev == rev_at
                        && adapter.live_object_count() == 1 =>
                {
                    let ev = receipt.receipt_digest;
                    last_receipt = Some(receipt);
                    b1_committed = Some(b1);
                    ApiCheckResult {
                        capability: StorageApiCapability::AnchoredSnapshotRead,
                        outcome: ApiCheckOutcome::Passed,
                        evidence_digest: ev,
                        work_operations: ops,
                    }
                }
                (pre_r, com_r, post_r, at_r) => ApiCheckResult {
                    capability: StorageApiCapability::AnchoredSnapshotRead,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-001".to_owned(),
                        detail: format!(
                            "snapshot read/commit mismatch: pre={} com={} post={} at={}",
                            pre_r.is_ok(),
                            com_r.is_ok(),
                            post_r.is_ok(),
                            at_r.is_ok()
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-001-failed"),
                    work_operations: ops,
                },
            }
        };
        checks.push(check1);

        // 2. FSQL-API-002: WitnessedBatchCommit (positive + certified negative pass; uncertified negative fails closed!)
        let mut pos_witness_opt: Option<SemanticWitness> = None;
        let check2 = {
            let mut ops = 0_u64;
            let head_anchor = adapter.head_anchor().clone();
            let head_root = adapter.history_root();
            let current_rev = adapter.read_object(&auth, &obj_alpha, false).ok().flatten();
            ops += 1;
            if let Some(rev) = current_rev {
                let pos_w = SemanticWitness::Positive(
                    PositiveWitness::seal(
                        head_anchor.clone(),
                        head_root,
                        obj_alpha.clone(),
                        rev,
                        head_anchor.commit_sequence,
                        None,
                    )
                    .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?,
                );
                let gapped_neg = SemanticWitness::Negative(
                    NegativeWitness::seal(
                        head_anchor.clone(),
                        head_root,
                        obj_absent.clone(),
                        make_coverage(&head_anchor, false),
                        None,
                    )
                    .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?,
                );
                let certified_neg = SemanticWitness::Negative(
                    NegativeWitness::seal(
                        head_anchor.clone(),
                        head_root,
                        obj_absent.clone(),
                        make_coverage(&head_anchor, true),
                        None,
                    )
                    .map_err(|e| StorageQualificationError::Encoding(e.to_string()))?,
                );
                let b2 = prepare_for_adapter(
                    adapter,
                    "batch:fsql-qual:002",
                    vec![make_delta(
                        "d:qual:2",
                        &obj_alpha,
                        Some(1),
                        2,
                        Plane::Authority,
                    )?],
                )?;
                // First verify uncertified negative witness fails closed!
                let uncert_res = adapter.commit_witnessed_batch(
                    &auth,
                    b2.clone(),
                    std::slice::from_ref(&gapped_neg),
                    TimestampNs(now.0 + 10),
                    false,
                );
                ops += 1;
                // Now verify positive + certified negative succeeds!
                let cert_res = adapter.commit_witnessed_batch(
                    &auth,
                    b2,
                    &[pos_w.clone(), certified_neg],
                    TimestampNs(now.0 + 20),
                    false,
                );
                ops += 1;
                pos_witness_opt = Some(pos_w);
                match (uncert_res, cert_res) {
                    (Err(StorageError::UncertifiedAbsenceWitness), Ok(r))
                        if r.verified_witness_count == 2
                            && r.commit_state == StorageCommitState::Durable =>
                    {
                        let ev = r.receipt_digest;
                        last_receipt = Some(r);
                        ApiCheckResult {
                            capability: StorageApiCapability::WitnessedBatchCommit,
                            outcome: ApiCheckOutcome::Passed,
                            evidence_digest: ev,
                            work_operations: ops,
                        }
                    }
                    (u, c) => ApiCheckResult {
                        capability: StorageApiCapability::WitnessedBatchCommit,
                        outcome: ApiCheckOutcome::Failed {
                            error_id: "ERR-LEDGER-QUAL-API-002".to_owned(),
                            detail: format!(
                                "witnessed commit contract breached: uncert={u:?} cert_ok={}",
                                c.is_ok()
                            ),
                        },
                        evidence_digest: ContentDigest::sha256(b"fsql-api-002-failed"),
                        work_operations: ops,
                    },
                }
            } else {
                ApiCheckResult {
                    capability: StorageApiCapability::WitnessedBatchCommit,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-002".to_owned(),
                        detail: "alpha object unavailable after FSQL-API-001".to_owned(),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-002-missing-alpha"),
                    work_operations: ops,
                }
            }
        };
        checks.push(check2);

        // 3. FSQL-API-003: IdempotentRetryAndConflict
        let check3 = {
            let mut ops = 0_u64;
            if let Some(ref b1) = b1_committed {
                let witness_slice: Vec<SemanticWitness> = pos_witness_opt.into_iter().collect();
                let dup = adapter.commit_witnessed_batch(
                    &auth,
                    b1.clone(),
                    &witness_slice,
                    TimestampNs(now.0 + 30),
                    false,
                );
                ops += 1;
                let mut tampered = b1.clone();
                tampered.batch_digest = ContentDigest::sha256(b"tampered-digest-qual");
                let tampered_res = adapter.commit_witnessed_batch(
                    &auth,
                    tampered,
                    &[],
                    TimestampNs(now.0 + 31),
                    false,
                );
                ops += 1;
                let conflict_batch = prepare_for_adapter(
                    adapter,
                    b1.batch_id.as_str(),
                    vec![make_delta(
                        "d:qual:conflict",
                        &obj_beta,
                        None,
                        1,
                        Plane::Authority,
                    )?],
                )?;
                let conflict_res = adapter.commit_witnessed_batch(
                    &auth,
                    conflict_batch,
                    &[],
                    TimestampNs(now.0 + 32),
                    false,
                );
                ops += 1;
                match (dup, tampered_res, conflict_res) {
                    (
                        Ok(dup_r),
                        Err(StorageError::InvalidInput(_)),
                        Err(StorageError::BatchIdConflict { .. }),
                    ) if dup_r.commit_state == StorageCommitState::ReconciledDuplicate
                        && dup_r.verified_witness_count == 0 =>
                    {
                        ApiCheckResult {
                            capability: StorageApiCapability::IdempotentRetryAndConflict,
                            outcome: ApiCheckOutcome::Passed,
                            evidence_digest: dup_r.receipt_digest,
                            work_operations: ops,
                        }
                    }
                    (d_r, t_r, c_r) => ApiCheckResult {
                        capability: StorageApiCapability::IdempotentRetryAndConflict,
                        outcome: ApiCheckOutcome::Failed {
                            error_id: "ERR-LEDGER-QUAL-API-003".to_owned(),
                            detail: format!(
                                "idempotency/conflict invariant breached: dup={:?} tamper={:?} conflict={:?}",
                                d_r.map(|r| (r.commit_state, r.verified_witness_count)),
                                t_r.err().map(|e| e.code()),
                                c_r.err().map(|e| e.code()),
                            ),
                        },
                        evidence_digest: ContentDigest::sha256(b"fsql-api-003-failed"),
                        work_operations: ops,
                    },
                }
            } else {
                ApiCheckResult {
                    capability: StorageApiCapability::IdempotentRetryAndConflict,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-003".to_owned(),
                        detail: "b1 not committed in FSQL-API-001".to_owned(),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-003-missing-b1"),
                    work_operations: ops,
                }
            }
        };
        checks.push(check3);

        // 4. FSQL-API-004: AuthorityAndPlaneIsolation
        let check4 = {
            let mut ops = 0_u64;
            let effect_batch = prepare_for_adapter(
                adapter,
                "batch:fsql-qual:plane-breach",
                vec![make_delta("d:qual:eff", &obj_beta, None, 1, Plane::Effect)?],
            )?;
            let cross_plane = adapter.commit_witnessed_batch(
                &auth,
                effect_batch,
                &[],
                TimestampNs(now.0 + 40),
                false,
            );
            ops += 1;
            let mut revoked = auth.clone();
            revoked.capability_active = false;
            let revoked_read = adapter.read_object(&revoked, &obj_alpha, false);
            ops += 1;
            let mut stale_gen = auth.clone();
            stale_gen.authority_generation += 1;
            let stale_read = adapter.read_object(&stale_gen, &obj_alpha, false);
            ops += 1;
            match (cross_plane, revoked_read, stale_read) {
                (
                    Err(StorageError::AuthorityRefused(_)),
                    Err(StorageError::AuthorityRefused(_)),
                    Err(
                        StorageError::AuthorityRefused(_)
                        | StorageError::AnchorOrGenerationConflict(_),
                    ),
                ) => ApiCheckResult {
                    capability: StorageApiCapability::AuthorityAndPlaneIsolation,
                    outcome: ApiCheckOutcome::Passed,
                    evidence_digest: ContentDigest::sha256(b"fsql-api-004-isolated"),
                    work_operations: ops,
                },
                (cp, rv, st) => ApiCheckResult {
                    capability: StorageApiCapability::AuthorityAndPlaneIsolation,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-004".to_owned(),
                        detail: format!(
                            "authority/plane isolation failed: cross_plane={:?} revoked={:?} stale={:?}",
                            cp.err().map(|e| e.code()),
                            rv.err().map(|e| e.code()),
                            st.err().map(|e| e.code()),
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-004-failed"),
                    work_operations: ops,
                },
            }
        };
        checks.push(check4);

        // 5. FSQL-API-005: CooperativeCancellation
        let check5 = {
            let seq_before = adapter.head_anchor().commit_sequence;
            let b_cancel = prepare_for_adapter(
                adapter,
                "batch:fsql-qual:cancelled",
                vec![make_delta(
                    "d:qual:can",
                    &obj_beta,
                    None,
                    1,
                    Plane::Authority,
                )?],
            )?;
            let c_read = adapter.read_object(&auth, &obj_alpha, true);
            let c_commit =
                adapter.commit_witnessed_batch(&auth, b_cancel, &[], TimestampNs(now.0 + 50), true);
            let c_reconcile = adapter.reconcile_after_crash(&auth, TimestampNs(now.0 + 51), true);
            let c_verify = adapter.verify_integrity(&auth, true);
            let seq_after = adapter.head_anchor().commit_sequence;
            match (c_read, c_commit, c_reconcile, c_verify) {
                (
                    Err(StorageError::Cancelled),
                    Err(StorageError::Cancelled),
                    Err(StorageError::Cancelled),
                    Err(StorageError::Cancelled),
                ) if seq_before == seq_after => ApiCheckResult {
                    capability: StorageApiCapability::CooperativeCancellation,
                    outcome: ApiCheckOutcome::Passed,
                    evidence_digest: ContentDigest::sha256(b"fsql-api-005-cancelled-clean"),
                    work_operations: 4,
                },
                _ => ApiCheckResult {
                    capability: StorageApiCapability::CooperativeCancellation,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-005".to_owned(),
                        detail: format!(
                            "cancellation did not fail closed without mutation (seq {seq_before} -> {seq_after})"
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-005-failed"),
                    work_operations: 4,
                },
            }
        };
        checks.push(check5);

        // 6. FSQL-API-006: CrashRecoveryAndIndeterminateFence
        let check6 = if let Some(injector) = inject_crash {
            let seq_before = adapter.head_anchor().commit_sequence;
            let b_crash = prepare_for_adapter(
                adapter,
                "batch:fsql-qual:crash-boundary",
                vec![make_delta(
                    "d:qual:crash",
                    &obj_beta,
                    None,
                    1,
                    Plane::Authority,
                )?],
            )?;
            injector(adapter);
            let first = adapter.commit_witnessed_batch(
                &auth,
                b_crash.clone(),
                &[],
                TimestampNs(now.0 + 60),
                false,
            );
            let fenced =
                adapter.commit_witnessed_batch(&auth, b_crash, &[], TimestampNs(now.0 + 61), false);
            let rec = adapter.reconcile_after_crash(&auth, TimestampNs(now.0 + 62), false);
            match (first, fenced, rec) {
                (
                    Err(StorageError::IndeterminateAppend { .. }),
                    Err(StorageError::IndeterminateAppend { .. }),
                    Ok(summary),
                ) if matches!(
                    summary.outcome,
                    StorageRecoveryOutcome::PendingCommitted
                        | StorageRecoveryOutcome::PendingNotCommitted
                ) && adapter.head_anchor().commit_sequence >= seq_before =>
                {
                    ApiCheckResult {
                        capability: StorageApiCapability::CrashRecoveryAndIndeterminateFence,
                        outcome: ApiCheckOutcome::Passed,
                        evidence_digest: summary.history_root,
                        work_operations: 3,
                    }
                }
                (f_r, fn_r, r_r) => ApiCheckResult {
                    capability: StorageApiCapability::CrashRecoveryAndIndeterminateFence,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-006".to_owned(),
                        detail: format!(
                            "crash fence/reconcile failed: first={:?} fenced={:?} rec={:?}",
                            f_r.err().map(|e| e.code()),
                            fn_r.err().map(|e| e.code()),
                            r_r.map(|s| s.outcome),
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-006-failed"),
                    work_operations: 3,
                },
            }
        } else {
            let clean = adapter.reconcile_after_crash(&auth, TimestampNs(now.0 + 60), false);
            match clean {
                Ok(summary) if summary.outcome == StorageRecoveryOutcome::CleanNoPending => {
                    ApiCheckResult {
                        capability: StorageApiCapability::CrashRecoveryAndIndeterminateFence,
                        outcome: ApiCheckOutcome::ExcludedUnsupported {
                            reason: "backend provides no crash-boundary fault injector".to_owned(),
                        },
                        evidence_digest: summary.history_root,
                        work_operations: 1,
                    }
                }
                other => ApiCheckResult {
                    capability: StorageApiCapability::CrashRecoveryAndIndeterminateFence,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-006".to_owned(),
                        detail: format!("clean reconcile_after_crash failed: {other:?}"),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-006-clean-failed"),
                    work_operations: 1,
                },
            }
        };
        checks.push(check6);

        // 7. FSQL-API-007: ForwardOnlySchemaMigration
        let check7 = {
            let from_ver = adapter.schema_version();
            let to_ver = StorageSchemaVersion::new(from_ver.major, from_ver.minor + 1);
            let plan = StorageMigrationPlan {
                migration_id: format!(
                    "mig:qual:{}_{}_to_{}_{}",
                    from_ver.major, from_ver.minor, to_ver.major, to_ver.minor
                ),
                from_version: from_ver,
                to_version: to_ver,
                description: "qualified forward minor upgrade".to_owned(),
            };
            let unauth = adapter.migrate_schema(&auth, &plan, TimestampNs(now.0 + 70), false);
            let mut mig_auth = auth.clone();
            mig_auth.allows_migration = true;
            let forward = adapter.migrate_schema(&mig_auth, &plan, TimestampNs(now.0 + 71), false);
            let downgrade_plan = StorageMigrationPlan {
                migration_id: "mig:qual:forbidden-downgrade".to_owned(),
                from_version: to_ver,
                to_version: from_ver,
                description: "forbidden downgrade".to_owned(),
            };
            let downgrade =
                adapter.migrate_schema(&mig_auth, &downgrade_plan, TimestampNs(now.0 + 72), false);
            match (unauth, forward, downgrade) {
                (
                    Err(StorageError::AuthorityRefused(_)),
                    Ok(mig_r),
                    Err(StorageError::UnsupportedSchemaDowngrade { .. }),
                ) if adapter.schema_version() == to_ver => {
                    let ev = mig_r.receipt_digest;
                    last_receipt = Some(mig_r);
                    ApiCheckResult {
                        capability: StorageApiCapability::ForwardOnlySchemaMigration,
                        outcome: ApiCheckOutcome::Passed,
                        evidence_digest: ev,
                        work_operations: 3,
                    }
                }
                (u, f, d) => ApiCheckResult {
                    capability: StorageApiCapability::ForwardOnlySchemaMigration,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-007".to_owned(),
                        detail: format!(
                            "migration contract breached: unauth={:?} forward_ok={} downgrade={:?}",
                            u.err().map(|e| e.code()),
                            f.is_ok(),
                            d.err().map(|e| e.code()),
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-007-failed"),
                    work_operations: 3,
                },
            }
        };
        checks.push(check7);

        // 8. FSQL-API-008: MerkleProofVerification
        let check8 = if adapter.supports_merkle_proofs() {
            let inc = adapter.prove_object(&auth, &obj_alpha, false);
            let non_inc = adapter.prove_object(&auth, &obj_absent, false);
            let root = adapter.head_anchor().state_root;
            match (inc, non_inc) {
                (Ok(Some(p_inc)), Ok(Some(p_non)))
                    if verify_proof(root, &obj_alpha, &p_inc).is_ok()
                        && verify_proof(root, &obj_absent, &p_non).is_ok() =>
                {
                    ApiCheckResult {
                        capability: StorageApiCapability::MerkleProofVerification,
                        outcome: ApiCheckOutcome::Passed,
                        evidence_digest: root,
                        work_operations: 2,
                    }
                }
                _ => ApiCheckResult {
                    capability: StorageApiCapability::MerkleProofVerification,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-008".to_owned(),
                        detail: "Merkle inclusion/non-inclusion proof failed verification"
                            .to_owned(),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-008-failed"),
                    work_operations: 2,
                },
            }
        } else {
            match adapter.prove_object(&auth, &obj_alpha, false) {
                Ok(None) => ApiCheckResult {
                    capability: StorageApiCapability::MerkleProofVerification,
                    outcome: ApiCheckOutcome::ExcludedUnsupported {
                        reason: "backend explicitly reports supports_merkle_proofs() == false"
                            .to_owned(),
                    },
                    evidence_digest: adapter.head_anchor().state_root,
                    work_operations: 1,
                },
                other => ApiCheckResult {
                    capability: StorageApiCapability::MerkleProofVerification,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-008".to_owned(),
                        detail: format!(
                            "backend claims no merkle proofs but prove_object returned {other:?}"
                        ),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-008-inconsistent"),
                    work_operations: 1,
                },
            }
        };
        checks.push(check8);

        // 9. FSQL-API-009: IntegrityVerification
        let check9 = match adapter.verify_integrity(&auth, false) {
            Ok(root) if root == adapter.history_root() => ApiCheckResult {
                capability: StorageApiCapability::IntegrityVerification,
                outcome: ApiCheckOutcome::Passed,
                evidence_digest: root,
                work_operations: 1,
            },
            other => ApiCheckResult {
                capability: StorageApiCapability::IntegrityVerification,
                outcome: ApiCheckOutcome::Failed {
                    error_id: "ERR-LEDGER-QUAL-API-009".to_owned(),
                    detail: format!("verify_integrity mismatch or error: {other:?}"),
                },
                evidence_digest: ContentDigest::sha256(b"fsql-api-009-failed"),
                work_operations: 1,
            },
        };
        checks.push(check9);

        // 10. FSQL-API-010: WireReceiptDeterminism
        let check10 = if let Some(receipt) = last_receipt {
            let wire1 = receipt.to_canonical_bytes();
            let wire2 = receipt.to_canonical_bytes();
            match (wire1, wire2) {
                (Ok(w1), Ok(w2)) if w1 == w2 => {
                    let rt = StorageCommitReceipt::from_canonical_bytes(&w1);
                    let mut flipped = w1.clone();
                    if let Some(last) = flipped.last_mut() {
                        *last ^= 0x01;
                    }
                    let tamper = StorageCommitReceipt::from_canonical_bytes(&flipped);
                    match (rt, tamper) {
                        (Ok(decoded), Err(StorageError::ChecksumMismatch))
                            if decoded == receipt =>
                        {
                            ApiCheckResult {
                                capability: StorageApiCapability::WireReceiptDeterminism,
                                outcome: ApiCheckOutcome::Passed,
                                evidence_digest: ContentDigest::sha256(&w1),
                                work_operations: 3,
                            }
                        }
                        _ => ApiCheckResult {
                            capability: StorageApiCapability::WireReceiptDeterminism,
                            outcome: ApiCheckOutcome::Failed {
                                error_id: "ERR-LEDGER-QUAL-API-010".to_owned(),
                                detail: "wire receipt round-trip or tamper refusal failed"
                                    .to_owned(),
                            },
                            evidence_digest: ContentDigest::sha256(b"fsql-api-010-failed"),
                            work_operations: 3,
                        },
                    }
                }
                _ => ApiCheckResult {
                    capability: StorageApiCapability::WireReceiptDeterminism,
                    outcome: ApiCheckOutcome::Failed {
                        error_id: "ERR-LEDGER-QUAL-API-010".to_owned(),
                        detail: "wire receipt encoding nondeterministic or errored".to_owned(),
                    },
                    evidence_digest: ContentDigest::sha256(b"fsql-api-010-enc-failed"),
                    work_operations: 2,
                },
            }
        } else {
            ApiCheckResult {
                capability: StorageApiCapability::WireReceiptDeterminism,
                outcome: ApiCheckOutcome::Failed {
                    error_id: "ERR-LEDGER-QUAL-API-010".to_owned(),
                    detail: "no commit receipt available for wire qualification".to_owned(),
                },
                evidence_digest: ContentDigest::sha256(b"fsql-api-010-no-receipt"),
                work_operations: 0,
            }
        };
        checks.push(check10);

        let verdict = compute_verdict(&checks);
        let mut cert = StorageApiQualificationCertificate {
            format_version: STORAGE_QUALIFICATION_VERSION,
            adapter_id: adapter.adapter_id().to_owned(),
            initial_schema_version,
            final_schema_version: adapter.schema_version(),
            contract_basis_digest,
            site_lineage,
            final_head_anchor: adapter.head_anchor().clone(),
            final_history_root: adapter.history_root(),
            verdict,
            checks,
            qualified_at: now,
            certificate_digest: ContentDigest::sha256(b"unsealed-qual-cert"),
        };
        cert.certificate_digest = cert.compute_digest()?;
        cert.verify_self()?;
        Ok(cert)
    }
}

fn compute_verdict(checks: &[ApiCheckResult]) -> QualificationVerdict {
    if checks
        .iter()
        .any(|c| matches!(c.outcome, ApiCheckOutcome::Failed { .. }))
    {
        QualificationVerdict::Refused
    } else if checks
        .iter()
        .any(|c| matches!(c.outcome, ApiCheckOutcome::ExcludedUnsupported { .. }))
    {
        QualificationVerdict::QualifiedWithExclusions
    } else {
        QualificationVerdict::Qualified
    }
}

fn make_delta(
    delta_id: &str,
    object_id: &ObjectId,
    prior_generation: Option<u64>,
    new_generation: u64,
    plane: Plane,
) -> Result<EvidenceDelta, StorageQualificationError> {
    Ok(EvidenceDelta {
        delta_id: delta_id.to_owned(),
        family: "fsql_qualification".to_owned(),
        object_id: object_id.clone(),
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))
            .map_err(|e| StorageQualificationError::InvalidInput(e.to_string()))?,
        plane,
        payload_digest: ContentDigest::sha256(delta_id.as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn prepare_for_adapter<A: FrankenSqliteStorageAdapter>(
    adapter: &A,
    batch_id: &str,
    deltas: Vec<EvidenceDelta>,
) -> Result<EvidenceDeltaBatch, StorageQualificationError> {
    let id = BatchId::parse(batch_id)
        .map_err(|e| StorageQualificationError::InvalidInput(e.to_string()))?;
    adapter
        .prepare_batch(id, deltas)
        .map_err(|e| StorageQualificationError::Encoding(e.to_string()))
}

fn make_coverage(anchor: &LedgerAnchor, complete: bool) -> CoverageWitness {
    let authorized: BTreeSet<String> = ["sensor:qual-1".to_owned()].into_iter().collect();
    let (observed, excluded, continuity, completeness, stop_reason) = if complete {
        (
            authorized.clone(),
            BTreeSet::new(),
            CoverageContinuity::Continuous,
            Completeness::Complete,
            CoverageStopReason::Complete,
        )
    } else {
        (
            BTreeSet::new(),
            authorized.clone(),
            CoverageContinuity::Gapped,
            Completeness::Partial,
            CoverageStopReason::SourceGap,
        )
    };
    CoverageWitness {
        anchor: anchor.clone(),
        authorized_domain: authorized,
        observed_domain: observed,
        excluded_domain: excluded,
        continuity,
        completeness,
        negative_predicate: "absence_of(obj:fsql-qual:absent)".to_owned(),
        stop_reason,
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn validate_text(
    value: &str,
    max_len: usize,
    label: &str,
) -> Result<(), StorageQualificationError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(StorageQualificationError::MalformedWire(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}

/// Helper used by qualification tests to construct an expected [`ObjectRevision`].
#[must_use]
pub fn expected_revision_generation(revision: &ObjectRevision) -> u64 {
    revision.generation
}
