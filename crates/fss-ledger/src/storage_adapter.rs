#![forbid(unsafe_code)]
//! FrankenSQLite storage integration trait and reference/durable/Merkle adapters (`FSS-031`, `fss-x4a.9.1`).
//!
//! Defines the canonical, dependency-free storage-engine integration boundary that production
//! FrankenSQLite adapters MUST satisfy and prove observational equivalence against before
//! admission (`INT-FSQL-001`, `TEST-LEDGER-CRASH-001`, `GATE-040`):
//!
//! - **Explicit authority and cooperative cancellation (`StorageAuthorityScope`, `cancelled`):**
//!   every read, witness check, commit, schema migration, crash reconciliation, and integrity audit
//!   requires explicit active capability, privacy epoch, authority generation, contract basis, and
//!   semantic-plane authorization.
//! - **Non-collapsed durable commit & recovery states (`StorageCommitState`):** separates
//!   `Staged`, `Visible`, `Durable`, `ReconciledDuplicate`, `Indeterminate`, and `Corrupt` so
//!   indeterminate appends are never conflated with success or silently dropped.
//! - **Witnessed transaction admission (`commit_witnessed_batch`):** verifies all positive,
//!   negative, and hierarchical [`SemanticWitness`]es against the exact anchor and history root,
//!   refuses uncertified negative reads (`CoverageWitness::certifies_absence() == false`), enforces
//!   semantic-plane boundaries, and distinguishes idempotent duplicate `BatchId` retries
//!   (`ReconciledDuplicate`) from conflicting `BatchId` reuse (`BatchIdConflict`).
//! - **Versioned schema migrations (`StorageSchemaVersion`, `StorageMigrationPlan`):** explicitly
//!   refuses schema downgrades (`UnsupportedSchemaDowngrade`) and seals every commit or migration
//!   into a bounded checksummed [`StorageCommitReceipt`] (`FSSSQL01` v1, domain
//!   `fss.ledger_storage_adapter_receipt.v1`).
//! - **Three concrete verified adapters:** [`ReferenceOracleStorage`] (in-memory deterministic
//!   oracle), [`DurableJournalStorage`] (crash-safe append journal with real indeterminate-append
//!   reconciliation), and [`MerkleEpochStorage`] (v2 segmented Radix-Merkle storage with `O(log N)`
//!   inclusion/non-inclusion proofs).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObjectRevision, Plane, TimestampNs,
};

use crate::durable::{DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger};
use crate::epochs::{EpochLedgerError, MerkleEpochLedger};
use crate::error::JournalError;
use crate::journal::IncompleteTailPolicy;
use crate::merkle::MerkleProof;
use crate::oracle::{LedgerOracle, ObjectRead, OracleError};
use crate::witness::{NegativeWitness, PositiveWitness, SemanticWitness, WitnessError};

/// Registered digest domain for sealed [`StorageCommitReceipt`] commitments (`FSS-031`).
pub const LEDGER_STORAGE_ADAPTER_RECEIPT_DOMAIN: &str = "fss.ledger_storage_adapter_receipt.v1";
/// Binary wire header magic for serialized storage adapter receipts.
pub const STORAGE_RECEIPT_MAGIC: [u8; 8] = *b"FSSSQL01";
/// Supported durable format version for [`StorageCommitReceipt`].
pub const STORAGE_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on adapter/migration label UTF-8 bytes.
pub const MAX_STORAGE_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_STORAGE_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on semantic witnesses attached to one witnessed storage commit.
pub const MAX_STORAGE_COMMIT_WITNESSES: usize = 256;

/// Monotonic schema version descriptor for FrankenSQLite / canonical ledger storage engines.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StorageSchemaVersion {
    /// Major schema format generation (incompatible changes bump major; downgrades refused).
    pub major: u32,
    /// Minor additive schema revision within the same major generation.
    pub minor: u32,
}

impl StorageSchemaVersion {
    /// Reference v1 canonical journal/oracle schema (`1.0`).
    pub const V1_0: Self = Self { major: 1, minor: 0 };
    /// Additive v1.1 schema with witness/lineage index metadata (`1.1`).
    pub const V1_1: Self = Self { major: 1, minor: 1 };
    /// Segmented Radix-Merkle epoch storage schema (`2.0`).
    pub const V2_0: Self = Self { major: 2, minor: 0 };
    /// Additive v2.1 schema (`2.1`).
    pub const V2_1: Self = Self { major: 2, minor: 1 };
}

/// Explicit forward-only schema migration descriptor (`FSS-031`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageMigrationPlan {
    /// Stable migration identifier (e.g., `"mig:fsql:v1_0_to_v1_1"`).
    pub migration_id: String,
    /// Exact required starting schema version.
    pub from_version: StorageSchemaVersion,
    /// Target schema version (MUST satisfy `to_version > from_version`; downgrades refused).
    pub to_version: StorageSchemaVersion,
    /// Secret-free human/machine migration summary.
    pub description: String,
}

impl StorageMigrationPlan {
    /// Validates structural bounds and forward-only version monotonicity.
    pub fn validate(&self) -> Result<(), StorageError> {
        validate_label(&self.migration_id, MAX_STORAGE_LABEL_BYTES, "migration_id")?;
        validate_label(&self.description, MAX_STORAGE_LABEL_BYTES, "description")?;
        if self.to_version < self.from_version {
            return Err(StorageError::UnsupportedSchemaDowngrade {
                current: self.from_version,
                requested: self.to_version,
            });
        }
        if self.to_version == self.from_version {
            return Err(StorageError::InvalidInput(
                "migration target version must strictly advance schema_version".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Explicit authority context required for every storage adapter operation (`FSS-031`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageAuthorityScope {
    /// Pinned non-zero `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while storage read/write capability remains active.
    pub capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// Semantic planes authorized for delta writes through this handle.
    pub allowed_planes: BTreeSet<Plane>,
    /// Explicit authorization gate for schema migrations (`false` by default for normal writers).
    pub allows_migration: bool,
}

impl StorageAuthorityScope {
    /// Constructs an active read/write storage authority (`allows_migration = false`).
    #[must_use]
    pub fn active(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
        allowed_planes: impl IntoIterator<Item = Plane>,
    ) -> Self {
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            allowed_planes: allowed_planes.into_iter().collect(),
            allows_migration: false,
        }
    }

    /// Validates active capability, privacy, generation, non-zero contract basis, and planes.
    pub fn validate(&self) -> Result<(), StorageError> {
        if !self.capability_active || !self.privacy_active {
            return Err(StorageError::AuthorityRefused(
                "storage capability or privacy authorization revoked".to_owned(),
            ));
        }
        if self.contract_basis_digest.bytes().iter().all(|&b| b == 0) {
            return Err(StorageError::AuthorityRefused(
                "contract_basis_digest cannot be zero".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(StorageError::AuthorityRefused(format!(
                "stale authority generation {} != expected {}",
                self.authority_generation, self.expected_authority_generation
            )));
        }
        if self.allowed_planes.is_empty() {
            return Err(StorageError::AuthorityRefused(
                "storage authority must authorize at least one semantic plane".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Non-collapsed publication and durability state of a storage operation (`FSS-031`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageCommitState {
    /// Prepared and validated locally; not yet visible or durable.
    Staged = 1,
    /// Visible in memory/snapshot but durability barrier not yet confirmed.
    Visible = 2,
    /// Atomically persisted past the durability boundary.
    Durable = 3,
    /// Exact identical `BatchId` + digest retry reconciled idempotently without re-applying.
    ReconciledDuplicate = 4,
    /// Durability boundary interrupted ambiguously; MUST reconcile before further mutations.
    Indeterminate = 5,
    /// Storage corruption or external mutation detected; requires quarantine/repair.
    Corrupt = 6,
}

impl StorageCommitState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Visible => "visible",
            Self::Durable => "durable",
            Self::ReconciledDuplicate => "reconciled_duplicate",
            Self::Indeterminate => "indeterminate",
            Self::Corrupt => "corrupt",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Visible),
            3 => Ok(Self::Durable),
            4 => Ok(Self::ReconciledDuplicate),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::Corrupt),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Outcome of crash/indeterminate-append reconciliation (`reconcile_after_crash`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRecoveryOutcome {
    /// Storage had no pending indeterminate append; head verified clean.
    CleanNoPending,
    /// Pending indeterminate batch was confirmed durably committed in storage.
    PendingCommitted,
    /// Pending indeterminate batch did not reach durability and was safely discarded.
    PendingNotCommitted,
}

/// Structured summary returned by [`FrankenSqliteStorageAdapter::reconcile_after_crash`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageRecoverySummary {
    /// Adapter implementation identifier.
    pub adapter_id: String,
    /// Reconciliation classification.
    pub outcome: StorageRecoveryOutcome,
    /// Reconciled head anchor after recovery.
    pub head_anchor: LedgerAnchor,
    /// Reconciled canonical history root after recovery.
    pub history_root: ContentDigest,
    /// Reconciled timestamp.
    pub reconciled_at: TimestampNs,
}

/// Safe operator/agent recovery guidance for a refused storage adapter operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageGuidance {
    /// Re-authorize storage capability, privacy epoch, generation, migration privilege, or plane scope.
    ReauthorizeStorage,
    /// Re-anchor against current head and rebuild batch/witnesses cleanly.
    ReanchorAtHead,
    /// Obtain certified absence `CoverageWitness` before committing an absence-dependent batch.
    WaitForCertifiedCoverage,
    /// Allocate a fresh `BatchId`; never reuse a committed `BatchId` with different content.
    AllocateFreshBatchId,
    /// Run `reconcile_after_crash` before attempting any further mutations.
    ReconcileIndeterminateAppend,
    /// Upgrade reader/engine rather than downgrading storage schema versions.
    UpgradeInsteadOfDowngrade,
    /// Quarantine corrupt storage and run doctor/repair from a healthy replica.
    QuarantineAndRepairStorage,
    /// Cooperative cancellation observed; safe to retry cleanly from pinned anchor.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary storage receipt bytes.
    RejectCorruptReceipt,
}

/// Typed failure returned by [`FrankenSqliteStorageAdapter`] or [`StorageCommitReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// Capability, privacy, generation, migration privilege, or semantic-plane refusal.
    AuthorityRefused(String),
    /// Cooperative cancellation observed before mutating durable state.
    Cancelled,
    /// Invalid input label, empty batch, or witness count violation.
    InvalidInput(String),
    /// Semantic witness failed verification against canonical state.
    WitnessFailed(String),
    /// Negative read witness lacked certified absence coverage (`CoverageWitness`).
    UncertifiedAbsenceWitness,
    /// Batch basis anchor, successor anchor, or delta generation conflicted with committed state.
    AnchorOrGenerationConflict(String),
    /// Stable `BatchId` already committed with a different canonical digest.
    BatchIdConflict {
        /// Conflicting batch identity.
        batch_id: BatchId,
        /// Existing committed sequence.
        committed_sequence: u64,
    },
    /// Durability barrier interrupted ambiguously; must reconcile before further mutations.
    IndeterminateAppend {
        /// Sequence of the ambiguous append.
        sequence: u64,
        /// Secret-free diagnostic detail.
        detail: String,
    },
    /// Attempted schema version downgrade or incompatible starting version.
    UnsupportedSchemaDowngrade {
        /// Active storage schema version.
        current: StorageSchemaVersion,
        /// Requested target version.
        requested: StorageSchemaVersion,
    },
    /// Storage corruption, digest mismatch, or external mutation detected.
    CorruptionDetected(String),
    /// Sequence/object query out of range or unavailable in this backend.
    NotFound(String),
    /// Witness count or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary receipt lacked [`STORAGE_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl StorageError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-LEDGER-STORAGE-AUTHORITY-001",
            Self::Cancelled => "ERR-LEDGER-STORAGE-CANCELLED-001",
            Self::InvalidInput(_) => "ERR-LEDGER-STORAGE-INVALID-INPUT-001",
            Self::WitnessFailed(_) => "ERR-LEDGER-STORAGE-WITNESS-001",
            Self::UncertifiedAbsenceWitness => "ERR-LEDGER-STORAGE-UNCERTIFIED-ABSENCE-001",
            Self::AnchorOrGenerationConflict(_) => "ERR-LEDGER-STORAGE-CONFLICT-001",
            Self::BatchIdConflict { .. } => "ERR-LEDGER-STORAGE-BATCH-ID-CONFLICT-001",
            Self::IndeterminateAppend { .. } => "ERR-LEDGER-STORAGE-INDETERMINATE-001",
            Self::UnsupportedSchemaDowngrade { .. } => "ERR-LEDGER-STORAGE-DOWNGRADE-001",
            Self::CorruptionDetected(_) => "ERR-LEDGER-STORAGE-CORRUPT-001",
            Self::NotFound(_) => "ERR-LEDGER-STORAGE-NOT-FOUND-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-STORAGE-BOUNDS-001",
            Self::InvalidMagic => "ERR-LEDGER-STORAGE-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-STORAGE-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-STORAGE-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-STORAGE-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-LEDGER-STORAGE-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> StorageGuidance {
        match self {
            Self::AuthorityRefused(_) => StorageGuidance::ReauthorizeStorage,
            Self::Cancelled => StorageGuidance::RetryWhenReady,
            Self::InvalidInput(_)
            | Self::WitnessFailed(_)
            | Self::AnchorOrGenerationConflict(_)
            | Self::NotFound(_)
            | Self::BoundsExceeded { .. } => StorageGuidance::ReanchorAtHead,
            Self::UncertifiedAbsenceWitness => StorageGuidance::WaitForCertifiedCoverage,
            Self::BatchIdConflict { .. } => StorageGuidance::AllocateFreshBatchId,
            Self::IndeterminateAppend { .. } => StorageGuidance::ReconcileIndeterminateAppend,
            Self::UnsupportedSchemaDowngrade { .. } => StorageGuidance::UpgradeInsteadOfDowngrade,
            Self::CorruptionDetected(_) => StorageGuidance::QuarantineAndRepairStorage,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => StorageGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for StorageError {}

/// Sealed binary receipt emitted by a storage adapter commit or migration (`FSSSQL01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageCommitReceipt {
    /// Wire format version (`STORAGE_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Stable adapter implementation identity.
    pub adapter_id: String,
    /// Active storage schema version after this operation.
    pub schema_version: StorageSchemaVersion,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Committed canonical [`LedgerAnchor`].
    pub committed_anchor: LedgerAnchor,
    /// Canonical history-chain root after this operation.
    pub history_root: ContentDigest,
    /// Stable batch or migration identifier (`batch_id` or `migration_id`).
    pub operation_id: String,
    /// Canonical digest of the committed batch (or migration plan commitment).
    pub payload_digest: ContentDigest,
    /// Number of semantic witnesses verified before admission.
    pub verified_witness_count: u32,
    /// Non-collapsed commit/durability state (`Durable` or `ReconciledDuplicate`).
    pub commit_state: StorageCommitState,
    /// Authority generation verified during this operation.
    pub authority_generation: u64,
    /// Privacy policy epoch verified during this operation.
    pub privacy_epoch: u64,
    /// Deterministic sealing timestamp.
    pub sealed_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.ledger_storage_adapter_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl StorageCommitReceipt {
    /// Recomputes the domain-separated SHA-256 commitment (`fss.ledger_storage_adapter_receipt.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, StorageError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_STORAGE_ADAPTER_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| StorageError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural bounds, non-zero cryptographic commitments, terminal state, and checksum.
    pub fn verify_self(&self) -> Result<(), StorageError> {
        if self.format_version != STORAGE_RECEIPT_VERSION {
            return Err(StorageError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.adapter_id, MAX_STORAGE_LABEL_BYTES, "adapter_id")
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        validate_label(&self.operation_id, MAX_STORAGE_LABEL_BYTES, "operation_id")
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        if self.schema_version.major == 0 {
            return Err(StorageError::MalformedWire(
                "schema_version.major must be >= 1".to_owned(),
            ));
        }
        if (self.verified_witness_count as usize) > MAX_STORAGE_COMMIT_WITNESSES {
            return Err(StorageError::BoundsExceeded {
                observed: self.verified_witness_count as usize,
                maximum: MAX_STORAGE_COMMIT_WITNESSES,
            });
        }
        if !matches!(
            self.commit_state,
            StorageCommitState::Durable | StorageCommitState::ReconciledDuplicate
        ) {
            return Err(StorageError::MalformedWire(
                "sealed StorageCommitReceipt must carry Durable or ReconciledDuplicate state"
                    .to_owned(),
            ));
        }
        for (name, digest) in [
            ("contract_basis_digest", self.contract_basis_digest),
            ("history_root", self.history_root),
            ("payload_digest", self.payload_digest),
        ] {
            if digest.bytes().iter().all(|&b| b == 0) {
                return Err(StorageError::MalformedWire(format!(
                    "{name} cannot be zero"
                )));
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(StorageError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.adapter_id);
        enc.u32(self.schema_version.major);
        enc.u32(self.schema_version.minor);
        enc.digest(self.contract_basis_digest);
        self.committed_anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        enc.text(&self.operation_id);
        enc.digest(self.payload_digest);
        enc.u32(self.verified_witness_count);
        enc.u8(self.commit_state.tag());
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        self.sealed_at.encode_canonical(enc);
    }

    /// Encodes this receipt into bounded checksummed binary bytes (`FSSSQL01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, StorageError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| StorageError::Encoding(e.to_string()))?;
        let total = STORAGE_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_STORAGE_WIRE_BYTES {
            return Err(StorageError::BoundsExceeded {
                observed: total,
                maximum: MAX_STORAGE_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&STORAGE_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies binary [`StorageCommitReceipt`] bytes (`FSSSQL01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() > MAX_STORAGE_WIRE_BYTES {
            return Err(StorageError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_STORAGE_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != STORAGE_RECEIPT_MAGIC {
            return Err(StorageError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != STORAGE_RECEIPT_VERSION {
            return Err(StorageError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(StorageError::UnsupportedVersion {
                version: format_version,
            });
        }
        let adapter_id = dec
            .text()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?
            .to_owned();
        let major = dec
            .u32()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let minor = dec
            .u32()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let committed_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let history_root = dec
            .digest()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let operation_id = dec
            .text()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?
            .to_owned();
        let payload_digest = dec
            .digest()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let verified_witness_count = dec
            .u32()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let commit_state = StorageCommitState::from_tag(
            dec.u8()
                .map_err(|e| StorageError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let sealed_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| StorageError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            StorageError::MalformedWire("trailing bytes after storage commit receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            adapter_id,
            schema_version: StorageSchemaVersion { major, minor },
            contract_basis_digest,
            committed_anchor,
            history_root,
            operation_id,
            payload_digest,
            verified_witness_count,
            commit_state,
            authority_generation,
            privacy_epoch,
            sealed_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Canonical FrankenSQLite storage-engine integration trait (`FSS-031`, `INT-FSQL-001`).
///
/// Every storage backend (in-memory oracle, durable append journal, segmented Radix-Merkle epoch
/// store, or future FrankenSQLite native engine) implements this exact authority-scoped,
/// witness-enforced, crash-reconciling contract.
pub trait FrankenSqliteStorageAdapter {
    /// Stable machine identity of this storage engine adapter.
    fn adapter_id(&self) -> &'static str;

    /// Active durable schema version of this storage instance.
    fn schema_version(&self) -> StorageSchemaVersion;

    /// Latest committed canonical [`LedgerAnchor`].
    fn head_anchor(&self) -> &LedgerAnchor;

    /// Latest committed canonical history-chain root.
    fn history_root(&self) -> ContentDigest;

    /// Live object count at head.
    fn live_object_count(&self) -> u64;

    /// True iff this backend emits standalone `O(log N)` [`MerkleProof`]s.
    fn supports_merkle_proofs(&self) -> bool {
        false
    }

    /// Reads the current revision of `object_id` under explicit authority and cancellation.
    fn read_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError>;

    /// Reads the historical revision of `object_id` at exact commit `sequence`, when retained.
    fn read_object_at(
        &self,
        authority: &StorageAuthorityScope,
        sequence: u64,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError>;

    /// Generates a standalone Merkle inclusion or non-inclusion proof when supported.
    fn prove_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<MerkleProof>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let _ = object_id;
        Ok(None)
    }

    /// Verifies one [`SemanticWitness`] against canonical storage state under explicit authority.
    fn verify_witness(
        &self,
        authority: &StorageAuthorityScope,
        witness: &SemanticWitness,
        cancelled: bool,
    ) -> Result<(), StorageError>;

    /// Validates authority, semantic planes, witnesses (including certified absence!), and
    /// atomically commits one canonical [`EvidenceDeltaBatch`], distinguishing idempotent duplicate
    /// retries (`ReconciledDuplicate`) from conflicting `BatchId` reuse (`BatchIdConflict`).
    fn commit_witnessed_batch(
        &mut self,
        authority: &StorageAuthorityScope,
        batch: EvidenceDeltaBatch,
        witnesses: &[SemanticWitness],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError>;

    /// Applies a forward-only schema migration under explicit `allows_migration` authority,
    /// refusing schema downgrades cleanly.
    fn migrate_schema(
        &mut self,
        authority: &StorageAuthorityScope,
        plan: &StorageMigrationPlan,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError>;

    /// Reconciles any pending indeterminate append after a crash or I/O interruption.
    fn reconcile_after_crash(
        &mut self,
        authority: &StorageAuthorityScope,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageRecoverySummary, StorageError>;

    /// Verifies end-to-end storage cryptographic integrity and returns the verified storage root.
    fn verify_integrity(
        &mut self,
        authority: &StorageAuthorityScope,
        cancelled: bool,
    ) -> Result<ContentDigest, StorageError>;
}

/// Deterministic in-memory reference adapter wrapping [`LedgerOracle`] (`FSS-016` + `FSS-031`).
#[derive(Clone, Debug)]
pub struct ReferenceOracleStorage {
    oracle: LedgerOracle,
    schema_version: StorageSchemaVersion,
}

impl ReferenceOracleStorage {
    /// Creates a new reference storage adapter wrapping `oracle` at schema `1.0`.
    #[must_use]
    pub const fn new(oracle: LedgerOracle) -> Self {
        Self {
            oracle,
            schema_version: StorageSchemaVersion::V1_0,
        }
    }

    /// Exposes a read-only reference to the underlying canonical [`LedgerOracle`].
    #[must_use]
    pub const fn oracle(&self) -> &LedgerOracle {
        &self.oracle
    }
}

impl FrankenSqliteStorageAdapter for ReferenceOracleStorage {
    fn adapter_id(&self) -> &'static str {
        "fss-ledger:reference-oracle-storage:v1"
    }

    fn schema_version(&self) -> StorageSchemaVersion {
        self.schema_version
    }

    fn head_anchor(&self) -> &LedgerAnchor {
        self.oracle.head_anchor()
    }

    fn history_root(&self) -> ContentDigest {
        self.oracle.head_history_root()
    }

    fn live_object_count(&self) -> u64 {
        self.oracle.head_object_count() as u64
    }

    fn read_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        Ok(self.oracle.head_object(object_id).cloned())
    }

    fn read_object_at(
        &self,
        authority: &StorageAuthorityScope,
        sequence: u64,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let view = self
            .oracle
            .view_at(sequence)
            .map_err(|e| StorageError::NotFound(e.to_string()))?;
        Ok(match view.object(object_id) {
            ObjectRead::Present { revision, .. } => Some(revision.clone()),
            ObjectRead::AbsentAtAnchor { .. } => None,
        })
    }

    fn verify_witness(
        &self,
        authority: &StorageAuthorityScope,
        witness: &SemanticWitness,
        cancelled: bool,
    ) -> Result<(), StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        witness
            .verify_against_oracle(&self.oracle, false)
            .map_err(map_witness_error)
    }

    fn commit_witnessed_batch(
        &mut self,
        authority: &StorageAuthorityScope,
        batch: EvidenceDeltaBatch,
        witnesses: &[SemanticWitness],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        validate_batch_scope_and_witness_bounds(&batch, witnesses, authority)?;

        // Idempotent duplicate / BatchIdConflict check BEFORE mutating or failing stale head!
        if let Some(existing) = self.oracle.batches().find(|b| b.batch_id == batch.batch_id) {
            let offered_digest = batch.computed_digest();
            if existing.batch_digest == offered_digest {
                return seal_storage_receipt(
                    self.adapter_id(),
                    self.schema_version,
                    authority,
                    existing.new_anchor.clone(),
                    self.oracle
                        .history_root_at(existing.new_anchor.commit_sequence)
                        .unwrap_or_else(|| self.oracle.head_history_root()),
                    existing.batch_id.as_str(),
                    existing.batch_digest,
                    witnesses.len() as u32,
                    StorageCommitState::ReconciledDuplicate,
                    now,
                );
            }
            return Err(StorageError::BatchIdConflict {
                batch_id: batch.batch_id,
                committed_sequence: existing.new_anchor.commit_sequence,
            });
        }

        for w in witnesses {
            if w.anchor() != self.oracle.head_anchor()
                || w.history_root() != self.oracle.head_history_root()
            {
                return Err(StorageError::WitnessFailed(
                    "commit witness anchor/history_root disagrees with storage head".to_owned(),
                ));
            }
            w.verify_against_oracle(&self.oracle, false)
                .map_err(map_witness_error)?;
            require_certified_negative(w)?;
        }

        let op_id = batch.batch_id.as_str().to_owned();
        let receipt = self.oracle.append(batch).map_err(map_oracle_error)?;
        seal_storage_receipt(
            self.adapter_id(),
            self.schema_version,
            authority,
            receipt.anchor,
            receipt.history_root,
            &op_id,
            receipt.batch_digest,
            witnesses.len() as u32,
            StorageCommitState::Durable,
            now,
        )
    }

    fn migrate_schema(
        &mut self,
        authority: &StorageAuthorityScope,
        plan: &StorageMigrationPlan,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        apply_checked_migration(
            self.adapter_id(),
            &mut self.schema_version,
            self.oracle.head_anchor().clone(),
            self.oracle.head_history_root(),
            authority,
            plan,
            now,
            cancelled,
        )
    }

    fn reconcile_after_crash(
        &mut self,
        authority: &StorageAuthorityScope,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageRecoverySummary, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        Ok(StorageRecoverySummary {
            adapter_id: self.adapter_id().to_owned(),
            outcome: StorageRecoveryOutcome::CleanNoPending,
            head_anchor: self.oracle.head_anchor().clone(),
            history_root: self.oracle.head_history_root(),
            reconciled_at: now,
        })
    }

    fn verify_integrity(
        &mut self,
        authority: &StorageAuthorityScope,
        cancelled: bool,
    ) -> Result<ContentDigest, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        Ok(self.oracle.head_history_root())
    }
}

/// Crash-safe durable journal storage adapter wrapping [`DurableReferenceLedger`].
#[derive(Debug)]
pub struct DurableJournalStorage {
    durable: DurableReferenceLedger,
    schema_version: StorageSchemaVersion,
}

impl DurableJournalStorage {
    /// Wraps an opened [`DurableReferenceLedger`] at schema `1.0`.
    #[must_use]
    pub const fn new(durable: DurableReferenceLedger) -> Self {
        Self {
            durable,
            schema_version: StorageSchemaVersion::V1_0,
        }
    }

    /// Exposes a read-only reference to the underlying [`DurableReferenceLedger`].
    #[must_use]
    pub const fn durable(&self) -> &DurableReferenceLedger {
        &self.durable
    }

    /// Exposes a mutable reference to the underlying [`DurableReferenceLedger`] (e.g. for fault-injection tests).
    pub fn durable_mut(&mut self) -> &mut DurableReferenceLedger {
        &mut self.durable
    }
}

impl FrankenSqliteStorageAdapter for DurableJournalStorage {
    fn adapter_id(&self) -> &'static str {
        "fss-ledger:durable-journal-storage:v1"
    }

    fn schema_version(&self) -> StorageSchemaVersion {
        self.schema_version
    }

    fn head_anchor(&self) -> &LedgerAnchor {
        &self.durable.current().anchor
    }

    fn history_root(&self) -> ContentDigest {
        self.durable.head_history_root()
    }

    fn live_object_count(&self) -> u64 {
        self.durable.current().objects.len() as u64
    }

    fn read_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        Ok(self.durable.current().objects.get(object_id).cloned())
    }

    fn read_object_at(
        &self,
        authority: &StorageAuthorityScope,
        sequence: u64,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let head_seq = self.durable.current().anchor.commit_sequence;
        if sequence > head_seq {
            return Err(StorageError::NotFound(format!(
                "sequence {sequence} beyond head {head_seq}"
            )));
        }
        if sequence == head_seq {
            return Ok(self.durable.current().objects.get(object_id).cloned());
        }
        let mut replay =
            fss_core::ReferenceLedger::new(&self.durable.current().anchor.site_lineage);
        for batch in self.durable.batches() {
            if batch.new_anchor.commit_sequence > sequence {
                break;
            }
            replay
                .append(batch.clone())
                .map_err(|e| StorageError::CorruptionDetected(e.to_string()))?;
        }
        Ok(replay.current().objects.get(object_id).cloned())
    }

    fn verify_witness(
        &self,
        authority: &StorageAuthorityScope,
        witness: &SemanticWitness,
        cancelled: bool,
    ) -> Result<(), StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        verify_witness_against_head(
            witness,
            &self.durable.current().anchor,
            self.durable.head_history_root(),
            |id| self.durable.current().objects.get(id),
        )
    }

    fn commit_witnessed_batch(
        &mut self,
        authority: &StorageAuthorityScope,
        batch: EvidenceDeltaBatch,
        witnesses: &[SemanticWitness],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        if let Some(seq) = self.durable.pending_append_sequence() {
            return Err(StorageError::IndeterminateAppend {
                sequence: seq,
                detail: "pending indeterminate append requires reconcile_after_crash first"
                    .to_owned(),
            });
        }
        validate_batch_scope_and_witness_bounds(&batch, witnesses, authority)?;

        if let Some(existing) = self
            .durable
            .batches()
            .iter()
            .find(|b| b.batch_id == batch.batch_id)
        {
            let offered_digest = batch.computed_digest();
            if existing.batch_digest == offered_digest {
                let seq_root = history_root_through_sequence(
                    &self.durable.current().anchor.site_lineage,
                    self.durable.batches(),
                    existing.new_anchor.commit_sequence,
                )?;
                return seal_storage_receipt(
                    self.adapter_id(),
                    self.schema_version,
                    authority,
                    existing.new_anchor.clone(),
                    seq_root,
                    existing.batch_id.as_str(),
                    existing.batch_digest,
                    witnesses.len() as u32,
                    StorageCommitState::ReconciledDuplicate,
                    now,
                );
            }
            return Err(StorageError::BatchIdConflict {
                batch_id: batch.batch_id,
                committed_sequence: existing.new_anchor.commit_sequence,
            });
        }

        for w in witnesses {
            verify_witness_against_head(
                w,
                &self.durable.current().anchor,
                self.durable.head_history_root(),
                |id| self.durable.current().objects.get(id),
            )?;
            require_certified_negative(w)?;
        }

        let op_id = batch.batch_id.as_str().to_owned();
        let batch_digest = batch.batch_digest;
        self.durable.append(batch).map_err(map_durable_error)?;
        seal_storage_receipt(
            self.adapter_id(),
            self.schema_version,
            authority,
            self.durable.current().anchor.clone(),
            self.durable.head_history_root(),
            &op_id,
            batch_digest,
            witnesses.len() as u32,
            StorageCommitState::Durable,
            now,
        )
    }

    fn migrate_schema(
        &mut self,
        authority: &StorageAuthorityScope,
        plan: &StorageMigrationPlan,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        if let Some(seq) = self.durable.pending_append_sequence() {
            return Err(StorageError::IndeterminateAppend {
                sequence: seq,
                detail: "cannot migrate schema while indeterminate append is pending".to_owned(),
            });
        }
        apply_checked_migration(
            self.adapter_id(),
            &mut self.schema_version,
            self.durable.current().anchor.clone(),
            self.durable.head_history_root(),
            authority,
            plan,
            now,
            cancelled,
        )
    }

    fn reconcile_after_crash(
        &mut self,
        authority: &StorageAuthorityScope,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageRecoverySummary, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let outcome = if self.durable.pending_append_sequence().is_some() {
            match self
                .durable
                .reconcile_pending(IncompleteTailPolicy::Truncate)
                .map_err(map_durable_error)?
            {
                DurableAppendReconciliation::Committed { .. } => {
                    StorageRecoveryOutcome::PendingCommitted
                }
                DurableAppendReconciliation::NotCommitted { .. } => {
                    StorageRecoveryOutcome::PendingNotCommitted
                }
            }
        } else {
            StorageRecoveryOutcome::CleanNoPending
        };
        Ok(StorageRecoverySummary {
            adapter_id: self.adapter_id().to_owned(),
            outcome,
            head_anchor: self.durable.current().anchor.clone(),
            history_root: self.durable.head_history_root(),
            reconciled_at: now,
        })
    }

    fn verify_integrity(
        &mut self,
        authority: &StorageAuthorityScope,
        cancelled: bool,
    ) -> Result<ContentDigest, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        self.durable.verify_storage().map_err(map_durable_error)
    }
}

/// Segmented v2 Radix-Merkle storage adapter wrapping [`MerkleEpochLedger`].
#[derive(Debug)]
pub struct MerkleEpochStorage {
    ledger: MerkleEpochLedger,
    schema_version: StorageSchemaVersion,
    committed_ids: BTreeMap<BatchId, (LedgerAnchor, ContentDigest, ContentDigest)>,
}

impl MerkleEpochStorage {
    /// Wraps an opened [`MerkleEpochLedger`] at schema `2.0`.
    #[must_use]
    pub const fn new(ledger: MerkleEpochLedger) -> Self {
        Self {
            ledger,
            schema_version: StorageSchemaVersion::V2_0,
            committed_ids: BTreeMap::new(),
        }
    }

    /// Exposes a read-only reference to the underlying [`MerkleEpochLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &MerkleEpochLedger {
        &self.ledger
    }
}

impl FrankenSqliteStorageAdapter for MerkleEpochStorage {
    fn adapter_id(&self) -> &'static str {
        "fss-ledger:merkle-epoch-storage:v2"
    }

    fn schema_version(&self) -> StorageSchemaVersion {
        self.schema_version
    }

    fn head_anchor(&self) -> &LedgerAnchor {
        self.ledger.head_anchor()
    }

    fn history_root(&self) -> ContentDigest {
        self.ledger.history_root()
    }

    fn live_object_count(&self) -> u64 {
        self.ledger.live_object_count()
    }

    fn supports_merkle_proofs(&self) -> bool {
        true
    }

    fn read_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        Ok(self.ledger.get_object(object_id).cloned())
    }

    fn read_object_at(
        &self,
        authority: &StorageAuthorityScope,
        sequence: u64,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<ObjectRevision>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        if sequence == self.ledger.head_anchor().commit_sequence {
            return Ok(self.ledger.get_object(object_id).cloned());
        }
        Err(StorageError::NotFound(format!(
            "merkle epoch storage head is {}; historical sequence {sequence} requires epoch scan",
            self.ledger.head_anchor().commit_sequence
        )))
    }

    fn prove_object(
        &self,
        authority: &StorageAuthorityScope,
        object_id: &ObjectId,
        cancelled: bool,
    ) -> Result<Option<MerkleProof>, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        self.ledger
            .prove_object(object_id)
            .map(Some)
            .map_err(map_epoch_error)
    }

    fn verify_witness(
        &self,
        authority: &StorageAuthorityScope,
        witness: &SemanticWitness,
        cancelled: bool,
    ) -> Result<(), StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        verify_witness_against_head(
            witness,
            self.ledger.head_anchor(),
            self.ledger.history_root(),
            |id| self.ledger.get_object(id),
        )
    }

    fn commit_witnessed_batch(
        &mut self,
        authority: &StorageAuthorityScope,
        batch: EvidenceDeltaBatch,
        witnesses: &[SemanticWitness],
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        validate_batch_scope_and_witness_bounds(&batch, witnesses, authority)?;

        if let Some((prev_anchor, prev_hist, prev_digest)) = self.committed_ids.get(&batch.batch_id)
        {
            if *prev_digest == batch.computed_digest() {
                return seal_storage_receipt(
                    self.adapter_id(),
                    self.schema_version,
                    authority,
                    prev_anchor.clone(),
                    *prev_hist,
                    batch.batch_id.as_str(),
                    *prev_digest,
                    witnesses.len() as u32,
                    StorageCommitState::ReconciledDuplicate,
                    now,
                );
            }
            return Err(StorageError::BatchIdConflict {
                batch_id: batch.batch_id,
                committed_sequence: prev_anchor.commit_sequence,
            });
        }

        for w in witnesses {
            verify_witness_against_head(
                w,
                self.ledger.head_anchor(),
                self.ledger.history_root(),
                |id| self.ledger.get_object(id),
            )?;
            require_certified_negative(w)?;
        }

        let batch_id = batch.batch_id.clone();
        let receipt = self.ledger.append_batch(batch).map_err(map_epoch_error)?;
        self.committed_ids.insert(
            batch_id.clone(),
            (
                receipt.anchor.clone(),
                receipt.history_root,
                receipt.batch_digest,
            ),
        );
        seal_storage_receipt(
            self.adapter_id(),
            self.schema_version,
            authority,
            receipt.anchor,
            receipt.history_root,
            batch_id.as_str(),
            receipt.batch_digest,
            witnesses.len() as u32,
            StorageCommitState::Durable,
            now,
        )
    }

    fn migrate_schema(
        &mut self,
        authority: &StorageAuthorityScope,
        plan: &StorageMigrationPlan,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageCommitReceipt, StorageError> {
        apply_checked_migration(
            self.adapter_id(),
            &mut self.schema_version,
            self.ledger.head_anchor().clone(),
            self.ledger.history_root(),
            authority,
            plan,
            now,
            cancelled,
        )
    }

    fn reconcile_after_crash(
        &mut self,
        authority: &StorageAuthorityScope,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<StorageRecoverySummary, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let _ = self.ledger.verify_full_chain().map_err(map_epoch_error)?;
        Ok(StorageRecoverySummary {
            adapter_id: self.adapter_id().to_owned(),
            outcome: StorageRecoveryOutcome::CleanNoPending,
            head_anchor: self.ledger.head_anchor().clone(),
            history_root: self.ledger.history_root(),
            reconciled_at: now,
        })
    }

    fn verify_integrity(
        &mut self,
        authority: &StorageAuthorityScope,
        cancelled: bool,
    ) -> Result<ContentDigest, StorageError> {
        if cancelled {
            return Err(StorageError::Cancelled);
        }
        authority.validate()?;
        let report = self.ledger.verify_full_chain().map_err(map_epoch_error)?;
        Ok(report.history_root)
    }
}

fn validate_batch_scope_and_witness_bounds(
    batch: &EvidenceDeltaBatch,
    witnesses: &[SemanticWitness],
    authority: &StorageAuthorityScope,
) -> Result<(), StorageError> {
    if witnesses.len() > MAX_STORAGE_COMMIT_WITNESSES {
        return Err(StorageError::BoundsExceeded {
            observed: witnesses.len(),
            maximum: MAX_STORAGE_COMMIT_WITNESSES,
        });
    }
    if batch.deltas.is_empty() {
        return Err(StorageError::InvalidInput(
            "cannot commit empty EvidenceDeltaBatch".to_owned(),
        ));
    }
    for d in &batch.deltas {
        if !authority.allowed_planes.contains(&d.plane) {
            return Err(StorageError::AuthorityRefused(format!(
                "delta '{}' plane {:?} outside storage allowed_planes",
                d.delta_id, d.plane
            )));
        }
    }
    Ok(())
}

fn verify_witness_against_head<'a, F>(
    witness: &SemanticWitness,
    head_anchor: &LedgerAnchor,
    history_root: ContentDigest,
    lookup: F,
) -> Result<(), StorageError>
where
    F: Fn(&ObjectId) -> Option<&'a ObjectRevision> + Copy,
{
    witness
        .verify_self_invariants()
        .map_err(map_witness_error)?;
    if witness.anchor() != head_anchor || witness.history_root() != history_root {
        return Err(StorageError::WitnessFailed(
            "witness anchor or history_root disagrees with storage head".to_owned(),
        ));
    }
    match witness {
        SemanticWitness::Positive(PositiveWitness {
            object_id,
            revision,
            ..
        }) => match lookup(object_id) {
            Some(observed) if observed == revision => Ok(()),
            Some(_) => Err(StorageError::WitnessFailed(format!(
                "positive witness revision mismatch for '{}'",
                object_id.as_str()
            ))),
            None => Err(StorageError::WitnessFailed(format!(
                "positive witness object '{}' absent at head",
                object_id.as_str()
            ))),
        },
        SemanticWitness::Negative(NegativeWitness { object_id, .. }) => {
            if lookup(object_id).is_some() {
                return Err(StorageError::WitnessFailed(format!(
                    "negative witness object '{}' is present at head",
                    object_id.as_str()
                )));
            }
            Ok(())
        }
        SemanticWitness::Hierarchical(h) => {
            for child in &h.children {
                verify_witness_against_head(child, head_anchor, history_root, lookup)?;
            }
            Ok(())
        }
    }
}

fn require_certified_negative(witness: &SemanticWitness) -> Result<(), StorageError> {
    match witness {
        SemanticWitness::Positive(_) => Ok(()),
        SemanticWitness::Negative(NegativeWitness {
            certified,
            coverage,
            ..
        }) => {
            if *certified && coverage.certifies_absence() {
                Ok(())
            } else {
                Err(StorageError::UncertifiedAbsenceWitness)
            }
        }
        SemanticWitness::Hierarchical(h) => {
            for child in &h.children {
                require_certified_negative(child)?;
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_checked_migration(
    adapter_id: &'static str,
    current_version: &mut StorageSchemaVersion,
    head_anchor: LedgerAnchor,
    history_root: ContentDigest,
    authority: &StorageAuthorityScope,
    plan: &StorageMigrationPlan,
    now: TimestampNs,
    cancelled: bool,
) -> Result<StorageCommitReceipt, StorageError> {
    if cancelled {
        return Err(StorageError::Cancelled);
    }
    authority.validate()?;
    if !authority.allows_migration {
        return Err(StorageError::AuthorityRefused(
            "schema migration requires allows_migration == true".to_owned(),
        ));
    }
    if plan.to_version < *current_version {
        return Err(StorageError::UnsupportedSchemaDowngrade {
            current: *current_version,
            requested: plan.to_version,
        });
    }
    plan.validate()?;
    if plan.from_version != *current_version {
        return Err(StorageError::InvalidInput(format!(
            "migration from_version {:?} does not match active version {:?}",
            plan.from_version, *current_version
        )));
    }
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.ledger_storage_migration_plan.v1");
    enc.text(&plan.migration_id);
    enc.u32(plan.from_version.major);
    enc.u32(plan.from_version.minor);
    enc.u32(plan.to_version.major);
    enc.u32(plan.to_version.minor);
    enc.text(&plan.description);
    let plan_digest = ContentDigest::sha256(
        &enc.finish_checked()
            .map_err(|e| StorageError::Encoding(e.to_string()))?,
    );
    *current_version = plan.to_version;
    seal_storage_receipt(
        adapter_id,
        *current_version,
        authority,
        head_anchor,
        history_root,
        &plan.migration_id,
        plan_digest,
        0,
        StorageCommitState::Durable,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_storage_receipt(
    adapter_id: &str,
    schema_version: StorageSchemaVersion,
    authority: &StorageAuthorityScope,
    committed_anchor: LedgerAnchor,
    history_root: ContentDigest,
    operation_id: &str,
    payload_digest: ContentDigest,
    verified_witness_count: u32,
    commit_state: StorageCommitState,
    sealed_at: TimestampNs,
) -> Result<StorageCommitReceipt, StorageError> {
    let mut receipt = StorageCommitReceipt {
        format_version: STORAGE_RECEIPT_VERSION,
        adapter_id: adapter_id.to_owned(),
        schema_version,
        contract_basis_digest: authority.contract_basis_digest,
        committed_anchor,
        history_root,
        operation_id: operation_id.to_owned(),
        payload_digest,
        verified_witness_count,
        commit_state,
        authority_generation: authority.authority_generation,
        privacy_epoch: authority.privacy_epoch,
        sealed_at,
        receipt_digest: ContentDigest::sha256(b"unsealed-storage-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self()?;
    Ok(receipt)
}

fn map_witness_error(err: WitnessError) -> StorageError {
    match err {
        WitnessError::Cancelled => StorageError::Cancelled,
        WitnessError::AbsenceNotCertified => StorageError::UncertifiedAbsenceWitness,
        other => StorageError::WitnessFailed(other.to_string()),
    }
}

fn map_oracle_error(err: OracleError) -> StorageError {
    match err {
        OracleError::BatchIdConflict {
            batch_id,
            committed_sequence,
            ..
        } => StorageError::BatchIdConflict {
            batch_id,
            committed_sequence,
        },
        other => StorageError::AnchorOrGenerationConflict(other.to_string()),
    }
}

fn map_durable_error(err: DurableLedgerError) -> StorageError {
    match err {
        DurableLedgerError::BatchIdConflict {
            batch_id,
            committed_sequence,
            ..
        } => StorageError::BatchIdConflict {
            batch_id,
            committed_sequence,
        },
        DurableLedgerError::Journal(JournalError::AppendIndeterminate { sequence, .. }) => {
            StorageError::IndeterminateAppend {
                sequence,
                detail: "durable journal append interrupted ambiguously".to_owned(),
            }
        }
        DurableLedgerError::Journal(JournalError::ReconciliationRequired { sequence }) => {
            StorageError::IndeterminateAppend {
                sequence,
                detail: "pending append reconciliation required before further mutations"
                    .to_owned(),
            }
        }
        DurableLedgerError::Journal(j) => StorageError::CorruptionDetected(j.to_string()),
        other => StorageError::AnchorOrGenerationConflict(other.to_string()),
    }
}

fn map_epoch_error(err: EpochLedgerError) -> StorageError {
    StorageError::AnchorOrGenerationConflict(err.to_string())
}

fn history_root_through_sequence(
    site_lineage: &str,
    batches: &[EvidenceDeltaBatch],
    target_seq: u64,
) -> Result<ContentDigest, StorageError> {
    let genesis = LedgerAnchor::genesis(site_lineage);
    let mut root = crate::oracle::genesis_history_root(&genesis)
        .map_err(|e| StorageError::Encoding(e.to_string()))?;
    for b in batches {
        if b.new_anchor.commit_sequence > target_seq {
            break;
        }
        root = crate::oracle::successor_history_root(
            root,
            b.new_anchor.commit_sequence,
            b.batch_digest,
            &b.new_anchor,
        )
        .map_err(|e| StorageError::Encoding(e.to_string()))?;
    }
    Ok(root)
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > max_len {
        return Err(StorageError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(StorageError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
