#![forbid(unsafe_code)]
//! Versioned ledger schema catalog and crash-safe root-last v1 -> v2 durable migration engine
//! (`FSS-033`, `fss-x4a.9.3`, `INT-FSQL-001`, `INT-FFS-001`).
//!
//! - **Immutable Schema Catalog ([`LEDGER_SCHEMA_CATALOG`]):** Stable versioned rows (`1.0`, `1.1`,
//!   `2.0`, `2.1`) that are never renumbered. Forward upgrades require explicit migration authority
//!   (`allows_migration == true`); unknown versions and schema downgrades fail closed.
//! - **Staged, Root-Last On-Disk `v1 -> v2` Migration ([`LedgerSchemaMigrator`]):** Reads and
//!   cryptographically verifies a live on-disk v1 [`DurableReferenceLedger`], replays every
//!   canonical `EvidenceDeltaBatch` into an isolated staging [`MerkleEpochLedger`], verifies
//!   bit-exact equivalence of every live [`fss_core::ObjectRevision`] PLUS standalone Merkle
//!   inclusion proofs against the staged v2 `state_root`, writes a sealed checksummed
//!   [`LedgerMigrationReceipt`] (`FSSLMG01` v1), and publishes the target directory atomically
//!   root-last without ever mutating the original v1 custody journal.
//! - **Non-collapsed states & cooperative cancellation:** Distinguishes `Staged`, `Verified`,
//!   `Committed`, `AlreadyAtTarget`, `Aborted`, `Indeterminate`, and `DowngradeRefused`, and
//!   honors cancellation cleanly at `Preflight`, `Stage`, `Verify`, and `Commit` boundaries.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    LedgerAnchor, Sha256Hasher, TimestampNs,
};

use crate::durable::DurableReferenceLedger;
use crate::epochs::{EpochLedgerConfig, MerkleEpochLedger};
use crate::journal::IncompleteTailPolicy;
use crate::merkle::verify_proof;
use crate::storage_adapter::{
    MAX_STORAGE_LABEL_BYTES, StorageAuthorityScope, StorageSchemaVersion,
};

/// Registered digest domain for sealed [`LedgerMigrationReceipt`] commitments (`FSS-033`).
pub const LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN: &str = "fss.ledger_schema_migration_receipt.v1";
/// Binary wire magic header for [`LedgerMigrationReceipt`].
pub const LEDGER_MIGRATION_RECEIPT_MAGIC: [u8; 8] = *b"FSSLMG01";
/// Current wire format version for [`LedgerMigrationReceipt`].
pub const LEDGER_MIGRATION_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on serialized migration receipt wire bytes (64 KiB).
pub const MAX_LEDGER_MIGRATION_WIRE_BYTES: usize = 64 * 1024;
/// Relative receipt filename written inside migrated target root directories.
pub const MIGRATION_RECEIPT_FILENAME: &str = "MIGRATION_RECEIPT.fss";

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;
static STAGE_SEQ: AtomicU64 = AtomicU64::new(1);

/// Lifecycle state of a registered ledger schema generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaLifecycleState {
    /// Active production-admitted storage schema generation.
    Active,
    /// Historical schema supported for read-only verification and forward migration only.
    SupportedLegacyReadOnly,
    /// Retired schema tombstoned in the registry; never renumbered and never admissible as a target.
    Tombstoned,
}

/// Immutable catalog entry describing one registered ledger storage schema generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerSchemaEntry {
    /// Stable never-renumbered schema row identifier.
    pub schema_id: &'static str,
    /// Semantic `(major, minor)` version tuple.
    pub version: StorageSchemaVersion,
    /// Lifecycle classification.
    pub lifecycle: SchemaLifecycleState,
    /// On-disk format family label (`durable_journal_v1` or `merkle_epoch_v2`).
    pub format_family: &'static str,
    /// Compatibility and replay guarantee summary.
    pub compatibility_note: &'static str,
}

/// Canonical registered ledger schema catalog (`FSS-033`). Entries are append-only and never renumbered.
pub const LEDGER_SCHEMA_CATALOG: [LedgerSchemaEntry; 4] = [
    LedgerSchemaEntry {
        schema_id: "LEDGER-SCHEMA-V1-0",
        version: StorageSchemaVersion::V1_0,
        lifecycle: SchemaLifecycleState::SupportedLegacyReadOnly,
        format_family: "durable_journal_v1",
        compatibility_note: "Sequential CRC/SHA-256 append journal; readable for replay and forward v1->v2 migration",
    },
    LedgerSchemaEntry {
        schema_id: "LEDGER-SCHEMA-V1-1",
        version: StorageSchemaVersion::V1_1,
        lifecycle: SchemaLifecycleState::SupportedLegacyReadOnly,
        format_family: "durable_journal_v1",
        compatibility_note: "Additive witness/lineage index metadata over v1 journal; forward-compatible to v2.0",
    },
    LedgerSchemaEntry {
        schema_id: "LEDGER-SCHEMA-V2-0",
        version: StorageSchemaVersion::V2_0,
        lifecycle: SchemaLifecycleState::Active,
        format_family: "merkle_epoch_v2",
        compatibility_note: "Segmented Radix-Merkle epoch ledger with verified checkpoints and O(log N) proofs",
    },
    LedgerSchemaEntry {
        schema_id: "LEDGER-SCHEMA-V2-1",
        version: StorageSchemaVersion::V2_1,
        lifecycle: SchemaLifecycleState::Active,
        format_family: "merkle_epoch_v2",
        compatibility_note: "Additive archival sealed-epoch metadata over v2.0 Radix-Merkle storage",
    },
];

/// Stage boundary within a staged root-last ledger migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationStage {
    /// Source verification, authority validation, and idempotency check.
    Preflight = 1,
    /// Replaying canonical batches into the isolated staging v2 directory.
    Stage = 2,
    /// Differential equivalence verification and Merkle inclusion proofs over all live objects.
    Verify = 3,
    /// Sealing receipt and atomically publishing staging -> target root-last.
    Commit = 4,
}

/// Non-collapsed terminal or intermediate migration state (`FSS-033`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationOutcomeState {
    /// Batches replayed into staging only; not yet verified or published.
    Staged = 1,
    /// Staging differentially verified against source; not yet atomically published.
    Verified = 2,
    /// Staging atomically published root-last with verified durable receipt.
    Committed = 3,
    /// Target already contains an identical verified migration from the exact same source root.
    AlreadyAtTarget = 4,
    /// Migration aborted cleanly before publication (e.g., cancellation); source untouched.
    Aborted = 5,
    /// Migration cutover state cannot be proven without reconciliation.
    Indeterminate = 6,
    /// Downgrade was requested and refused fail-closed.
    DowngradeRefused = 7,
}

impl MigrationOutcomeState {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Committed => "committed",
            Self::AlreadyAtTarget => "already_at_target",
            Self::Aborted => "aborted",
            Self::Indeterminate => "indeterminate",
            Self::DowngradeRefused => "downgrade_refused",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, LedgerMigrationError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Committed),
            4 => Ok(Self::AlreadyAtTarget),
            5 => Ok(Self::Aborted),
            6 => Ok(Self::Indeterminate),
            7 => Ok(Self::DowngradeRefused),
            other => Err(LedgerMigrationError::MalformedWire(format!(
                "unknown MigrationOutcomeState tag {other}"
            ))),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused or interrupted migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationGuidance {
    /// Re-authorize with explicit `allows_migration == true` and current authority generation.
    ReauthorizeMigration,
    /// Upgrade reader/engine rather than attempting a forbidden schema downgrade.
    UpgradeInsteadOfDowngrade,
    /// Run source ledger doctor/reconciliation before attempting migration.
    ReconcileOrRepairSourceFirst,
    /// Retry cleanly from verified source; prior cancellation left source and target untouched.
    RetryCleanlyFromSource,
    /// Inspect conflicting target directory or choose a fresh target path.
    InspectTargetConflict,
    /// Reject corrupt migration receipt and verify storage directly.
    RejectCorruptReceipt,
}

/// Typed fail-closed error emitted by [`LedgerSchemaCatalog`] and [`LedgerSchemaMigrator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerMigrationError {
    /// Caller lacked explicit `allows_migration` authority, capability, privacy, or current generation.
    AuthorityRefused(String),
    /// Requested downgrade (`to_version < from_version`).
    DowngradeRefused {
        /// Active source schema version.
        from: StorageSchemaVersion,
        /// Forbidden lower target schema version.
        to: StorageSchemaVersion,
    },
    /// Unregistered schema version offered.
    UnsupportedSchemaVersion {
        /// Unregistered schema version.
        version: StorageSchemaVersion,
    },
    /// Target schema generation is tombstoned or read-only legacy and cannot be upgraded into.
    InvalidTargetLifecycle {
        /// Target schema version.
        version: StorageSchemaVersion,
        /// Lifecycle state preventing admission as target.
        lifecycle: SchemaLifecycleState,
    },
    /// Invalid input parameter or path.
    InvalidInput(String),
    /// Source v1 ledger failed integrity verification or has an unresolved incomplete tail.
    SourceCorruptOrPending(String),
    /// Target directory already exists with conflicting or unverified contents.
    TargetConflict(String),
    /// Differential verification detected a mismatch between source v1 and staged v2 state.
    EquivalenceMismatch(String),
    /// Cooperative cancellation observed cleanly at `stage` without publishing target.
    Cancelled {
        /// Exact boundary where cancellation stopped the migration.
        stage: MigrationStage,
    },
    /// Underlying filesystem or ledger I/O failure.
    Io(String),
    /// Wire receipt magic header mismatch.
    InvalidMagic,
    /// Wire receipt format version unsupported.
    UnsupportedWireVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Wire receipt trailing checksum or self-digest mismatch.
    ChecksumMismatch,
    /// Wire receipt exceeded [`MAX_LEDGER_MIGRATION_WIRE_BYTES`].
    WireTooLarge {
        /// Observed length in bytes.
        observed: usize,
        /// Configured hard limit.
        maximum: usize,
    },
    /// Malformed receipt fields or wire structure.
    MalformedWire(String),
}

impl LedgerMigrationError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-LEDGER-MIGRATION-AUTH-001",
            Self::DowngradeRefused { .. } => "ERR-LEDGER-MIGRATION-DOWNGRADE-001",
            Self::UnsupportedSchemaVersion { .. } | Self::InvalidTargetLifecycle { .. } => {
                "ERR-LEDGER-MIGRATION-VERSION-001"
            }
            Self::InvalidInput(_) => "ERR-LEDGER-MIGRATION-INPUT-001",
            Self::SourceCorruptOrPending(_) => "ERR-LEDGER-MIGRATION-SOURCE-001",
            Self::TargetConflict(_) => "ERR-LEDGER-MIGRATION-TARGET-CONFLICT-001",
            Self::EquivalenceMismatch(_) => "ERR-LEDGER-MIGRATION-EQUIV-001",
            Self::Cancelled { .. } => "ERR-LEDGER-MIGRATION-CANCELLED-001",
            Self::Io(_) => "ERR-LEDGER-MIGRATION-IO-001",
            Self::InvalidMagic
            | Self::UnsupportedWireVersion { .. }
            | Self::WireTooLarge { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-LEDGER-MIGRATION-MALFORMED-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> MigrationGuidance {
        match self {
            Self::AuthorityRefused(_) => MigrationGuidance::ReauthorizeMigration,
            Self::DowngradeRefused { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::InvalidTargetLifecycle { .. } => MigrationGuidance::UpgradeInsteadOfDowngrade,
            Self::SourceCorruptOrPending(_) | Self::EquivalenceMismatch(_) | Self::Io(_) => {
                MigrationGuidance::ReconcileOrRepairSourceFirst
            }
            Self::Cancelled { .. } => MigrationGuidance::RetryCleanlyFromSource,
            Self::TargetConflict(_) | Self::InvalidInput(_) => {
                MigrationGuidance::InspectTargetConflict
            }
            Self::InvalidMagic
            | Self::UnsupportedWireVersion { .. }
            | Self::ChecksumMismatch
            | Self::WireTooLarge { .. }
            | Self::MalformedWire(_) => MigrationGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for LedgerMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for LedgerMigrationError {}

/// Lookup and compatibility validator over [`LEDGER_SCHEMA_CATALOG`].
pub struct LedgerSchemaCatalog;

impl LedgerSchemaCatalog {
    /// Looks up a registered schema entry by `(major, minor)`.
    #[must_use]
    pub fn find(version: StorageSchemaVersion) -> Option<&'static LedgerSchemaEntry> {
        LEDGER_SCHEMA_CATALOG
            .iter()
            .find(|entry| entry.version == version)
    }

    /// Validates a requested schema transition `from -> to`.
    ///
    /// Returns `Ok(MigrationOutcomeState::AlreadyAtTarget)` when `from == to` and both are
    /// registered, `Ok(MigrationOutcomeState::Verified)` when `from < to` and `to` is `Active`,
    /// or fails closed on unknown versions, downgrades, or non-active targets.
    pub fn validate_transition(
        from: StorageSchemaVersion,
        to: StorageSchemaVersion,
    ) -> Result<MigrationOutcomeState, LedgerMigrationError> {
        let Some(_src) = Self::find(from) else {
            return Err(LedgerMigrationError::UnsupportedSchemaVersion { version: from });
        };
        let Some(dst) = Self::find(to) else {
            return Err(LedgerMigrationError::UnsupportedSchemaVersion { version: to });
        };
        if to < from {
            return Err(LedgerMigrationError::DowngradeRefused { from, to });
        }
        if to == from {
            return Ok(MigrationOutcomeState::AlreadyAtTarget);
        }
        if dst.lifecycle != SchemaLifecycleState::Active {
            return Err(LedgerMigrationError::InvalidTargetLifecycle {
                version: to,
                lifecycle: dst.lifecycle,
            });
        }
        Ok(MigrationOutcomeState::Verified)
    }
}

/// Sealed, checksummed durable receipt proving an audited ledger schema migration (`FSS-033`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerMigrationReceipt {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Stable migration identifier.
    pub migration_id: String,
    /// Source ledger schema version (`1.0` or `1.1`).
    pub from_version: StorageSchemaVersion,
    /// Target ledger schema version (`2.0` or `2.1`).
    pub to_version: StorageSchemaVersion,
    /// Pinned `ContractBasis` digest authorizing the migration.
    pub contract_basis_digest: ContentDigest,
    /// Site lineage migrated.
    pub site_lineage: String,
    /// Source v1 head anchor verified before migration.
    pub source_head_anchor: LedgerAnchor,
    /// Source v1 canonical `history_root`.
    pub source_history_root: ContentDigest,
    /// Target v2 head anchor verified after migration.
    pub target_head_anchor: LedgerAnchor,
    /// Target v2 canonical `history_root`.
    pub target_history_root: ContentDigest,
    /// Total canonical batches migrated.
    pub migrated_batch_count: u64,
    /// Total live objects differentially verified with Merkle inclusion proofs.
    pub verified_object_count: u64,
    /// Non-collapsed migration outcome (`Committed` or `AlreadyAtTarget`).
    pub outcome_state: MigrationOutcomeState,
    /// Authority generation pinned during migration.
    pub authority_generation: u64,
    /// Privacy epoch pinned during migration.
    pub privacy_epoch: u64,
    /// Virtual timestamp at which the receipt was sealed.
    pub migrated_at: TimestampNs,
    /// Domain-separated SHA-256 commitment under [`LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl LedgerMigrationReceipt {
    /// Migration receipts are custody evidence and never grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Computes the canonical commitment digest under [`LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, LedgerMigrationError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN);
        enc.u32(self.format_version);
        enc.text(&self.migration_id);
        enc.u32(self.from_version.major);
        enc.u32(self.from_version.minor);
        enc.u32(self.to_version.major);
        enc.u32(self.to_version.minor);
        enc.digest(self.contract_basis_digest);
        enc.text(&self.site_lineage);
        self.source_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.source_history_root);
        self.target_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.target_history_root);
        enc.u64(self.migrated_batch_count);
        enc.u64(self.verified_object_count);
        enc.u8(self.outcome_state.tag());
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.i128(self.migrated_at.0);
        let bytes = enc
            .finish_checked()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Validates all structural invariants, monotonic version transition, and digest integrity.
    pub fn verify_self(&self) -> Result<(), LedgerMigrationError> {
        if self.format_version != LEDGER_MIGRATION_RECEIPT_VERSION {
            return Err(LedgerMigrationError::UnsupportedWireVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.migration_id, MAX_STORAGE_LABEL_BYTES, "migration_id")?;
        validate_label(&self.site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        let _ = LedgerSchemaCatalog::validate_transition(self.from_version, self.to_version)?;
        if !matches!(
            self.outcome_state,
            MigrationOutcomeState::Committed | MigrationOutcomeState::AlreadyAtTarget
        ) {
            return Err(LedgerMigrationError::MalformedWire(
                "sealed migration receipt must be Committed or AlreadyAtTarget".to_owned(),
            ));
        }
        if self.source_head_anchor.commit_sequence != self.target_head_anchor.commit_sequence
            || self.source_head_anchor.site_lineage != self.site_lineage
            || self.target_head_anchor.site_lineage != self.site_lineage
            || self.migrated_batch_count != self.source_head_anchor.commit_sequence
        {
            return Err(LedgerMigrationError::EquivalenceMismatch(
                "source/target anchors disagree on sequence, batch count, or site lineage"
                    .to_owned(),
            ));
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(LedgerMigrationError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes this receipt into its versioned, checksummed `FSSLMG01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, LedgerMigrationError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        enc.u32(self.format_version);
        enc.text(&self.migration_id);
        enc.u32(self.from_version.major);
        enc.u32(self.from_version.minor);
        enc.u32(self.to_version.major);
        enc.u32(self.to_version.minor);
        enc.digest(self.contract_basis_digest);
        enc.text(&self.site_lineage);
        self.source_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.source_history_root);
        self.target_head_anchor.encode_canonical(&mut enc);
        enc.digest(self.target_history_root);
        enc.u64(self.migrated_batch_count);
        enc.u64(self.verified_object_count);
        enc.u8(self.outcome_state.tag());
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.i128(self.migrated_at.0);
        enc.digest(self.receipt_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or(LedgerMigrationError::WireTooLarge {
                observed: usize::MAX,
                maximum: MAX_LEDGER_MIGRATION_WIRE_BYTES,
            })?;
        if total > MAX_LEDGER_MIGRATION_WIRE_BYTES {
            return Err(LedgerMigrationError::WireTooLarge {
                observed: total,
                maximum: MAX_LEDGER_MIGRATION_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&LEDGER_MIGRATION_RECEIPT_MAGIC);
        out.extend_from_slice(&LEDGER_MIGRATION_RECEIPT_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSLMG01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LedgerMigrationError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(LedgerMigrationError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_LEDGER_MIGRATION_WIRE_BYTES {
            return Err(LedgerMigrationError::WireTooLarge {
                observed: bytes.len(),
                maximum: MAX_LEDGER_MIGRATION_WIRE_BYTES,
            });
        }
        if bytes[..8] != LEDGER_MIGRATION_RECEIPT_MAGIC {
            return Err(LedgerMigrationError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != LEDGER_MIGRATION_RECEIPT_VERSION {
            return Err(LedgerMigrationError::UnsupportedWireVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                LedgerMigrationError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(LedgerMigrationError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(LEDGER_SCHEMA_MIGRATION_RECEIPT_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(LedgerMigrationError::ChecksumMismatch);
        }
        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let migration_id = dec
            .text()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?
            .to_owned();
        let from_version = StorageSchemaVersion::new(
            dec.u32()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
        );
        let to_version = StorageSchemaVersion::new(
            dec.u32()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
        );
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let site_lineage = dec
            .text()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?
            .to_owned();
        let source_head_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let source_history_root = dec
            .digest()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let target_head_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let target_history_root = dec
            .digest()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let migrated_batch_count = dec
            .u64()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let verified_object_count = dec
            .u64()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let outcome_state = MigrationOutcomeState::from_tag(
            dec.u8()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
        )?;
        let authority_generation = dec
            .u64()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        let migrated_at = TimestampNs(
            dec.i128()
                .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?,
        );
        let receipt_digest = dec
            .digest()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| LedgerMigrationError::MalformedWire(e.to_string()))?;

        let receipt = Self {
            format_version,
            migration_id,
            from_version,
            to_version,
            contract_basis_digest,
            site_lineage,
            source_head_anchor,
            source_history_root,
            target_head_anchor,
            target_history_root,
            migrated_batch_count,
            verified_object_count,
            outcome_state,
            authority_generation,
            privacy_epoch,
            migrated_at,
            receipt_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Staged, root-last durable ledger schema migrator (`FSS-033`).
pub struct LedgerSchemaMigrator;

impl LedgerSchemaMigrator {
    /// Migrates a live on-disk v1 [`DurableReferenceLedger`] at `source_journal_path` into a
    /// verified, checkpointed v2 [`MerkleEpochLedger`] at `target_epochs_dir`.
    ///
    /// Guarantees:
    /// - Explicit `authority.allows_migration == true` and schema-catalog transition validation.
    /// - Source v1 journal is cryptographically verified before staging and is NEVER mutated.
    /// - All canonical batches replay into an isolated staging directory; every live object
    ///   revision AND its cryptographic Merkle inclusion proof are differentially verified against
    ///   v1 BEFORE atomic root-last publication.
    /// - Cooperative cancellation at any [`MigrationStage`] cleans up staging and leaves both
    ///   source and target untouched.
    /// - Re-running against an already-migrated target with identical `source_history_root`
    ///   verifies the existing target and returns `MigrationOutcomeState::AlreadyAtTarget`.
    #[allow(clippy::too_many_arguments)]
    pub fn migrate_v1_journal_to_v2_epochs(
        migration_id: &str,
        source_journal_path: &Path,
        target_epochs_dir: &Path,
        site_lineage: &str,
        authority: &StorageAuthorityScope,
        epoch_config: EpochLedgerConfig,
        now: TimestampNs,
        cancel_at: Option<MigrationStage>,
    ) -> Result<LedgerMigrationReceipt, LedgerMigrationError> {
        validate_label(migration_id, MAX_STORAGE_LABEL_BYTES, "migration_id")?;
        validate_label(site_lineage, MAX_STORAGE_LABEL_BYTES, "site_lineage")?;
        authority
            .validate()
            .map_err(|e| LedgerMigrationError::AuthorityRefused(e.to_string()))?;
        if !authority.allows_migration {
            return Err(LedgerMigrationError::AuthorityRefused(
                "ledger schema migration requires allows_migration == true".to_owned(),
            ));
        }
        let _ = LedgerSchemaCatalog::validate_transition(
            StorageSchemaVersion::V1_0,
            StorageSchemaVersion::V2_0,
        )?;
        if cancel_at == Some(MigrationStage::Preflight) {
            return Err(LedgerMigrationError::Cancelled {
                stage: MigrationStage::Preflight,
            });
        }
        if !source_journal_path.is_file() {
            return Err(LedgerMigrationError::SourceCorruptOrPending(format!(
                "source v1 journal '{}' does not exist",
                source_journal_path.display()
            )));
        }

        // 1. Preflight: verify source v1 journal cleanly (reject incomplete tails or corruption!).
        let mut source = DurableReferenceLedger::open(
            source_journal_path,
            site_lineage,
            IncompleteTailPolicy::Reject,
        )
        .map_err(|e| LedgerMigrationError::SourceCorruptOrPending(e.to_string()))?;
        if source.pending_append_sequence().is_some() {
            return Err(LedgerMigrationError::SourceCorruptOrPending(
                "source v1 ledger has an unresolved pending append".to_owned(),
            ));
        }
        let _ = source
            .verify_storage()
            .map_err(|e| LedgerMigrationError::SourceCorruptOrPending(e.to_string()))?;
        let source_head_anchor = source.current().anchor.clone();
        let source_history_root = source.head_history_root();

        // Idempotent replay check when target already exists.
        if target_epochs_dir.exists() {
            let receipt_path = target_epochs_dir.join(MIGRATION_RECEIPT_FILENAME);
            if !receipt_path.is_file() {
                return Err(LedgerMigrationError::TargetConflict(format!(
                    "target '{}' exists without a verified {}",
                    target_epochs_dir.display(),
                    MIGRATION_RECEIPT_FILENAME
                )));
            }
            let raw =
                fs::read(&receipt_path).map_err(|e| LedgerMigrationError::Io(e.to_string()))?;
            let existing = LedgerMigrationReceipt::from_canonical_bytes(&raw)?;
            if existing.site_lineage != site_lineage
                || existing.source_history_root != source_history_root
                || existing.source_head_anchor.commit_sequence != source_head_anchor.commit_sequence
            {
                return Err(LedgerMigrationError::TargetConflict(
                    "existing target migration receipt disagrees with offered source history"
                        .to_owned(),
                ));
            }
            // Verify live v2 target matches existing receipt!
            let target_v2 = MerkleEpochLedger::open(
                target_epochs_dir,
                site_lineage,
                epoch_config,
                IncompleteTailPolicy::Reject,
            )
            .map_err(|e| LedgerMigrationError::TargetConflict(e.to_string()))?;
            let report = target_v2
                .verify_full_chain()
                .map_err(|e| LedgerMigrationError::TargetConflict(e.to_string()))?;
            if report.history_root != existing.target_history_root
                || target_v2.head_anchor().state_root != existing.target_head_anchor.state_root
                || target_v2.head_anchor().commit_sequence
                    != existing.target_head_anchor.commit_sequence
                || target_v2.live_object_count() != existing.verified_object_count
            {
                return Err(LedgerMigrationError::TargetConflict(
                    "target v2 ledger state or history_root drifted from sealed migration receipt"
                        .to_owned(),
                ));
            }
            let mut idempotent = existing;
            idempotent.outcome_state = MigrationOutcomeState::AlreadyAtTarget;
            idempotent.migrated_at = now;
            idempotent.receipt_digest = idempotent.compute_digest()?;
            idempotent.verify_self()?;
            return Ok(idempotent);
        }

        // 2. Stage: isolate replay in sibling staging directory.
        if cancel_at == Some(MigrationStage::Stage) {
            return Err(LedgerMigrationError::Cancelled {
                stage: MigrationStage::Stage,
            });
        }
        let staging_dir = make_staging_path(target_epochs_dir)?;
        let stage_res = run_staged_v2_replay(
            migration_id,
            &source,
            &staging_dir,
            site_lineage,
            authority,
            epoch_config,
            now,
            cancel_at,
        );
        let receipt = match stage_res {
            Ok(receipt) => receipt,
            Err(err) => {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(err);
            }
        };

        // 4. Commit: write sealed receipt into staging, then atomically rename staging -> target (root-last!).
        if cancel_at == Some(MigrationStage::Commit) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(LedgerMigrationError::Cancelled {
                stage: MigrationStage::Commit,
            });
        }
        let receipt_bytes = receipt.to_canonical_bytes()?;
        let staging_receipt_path = staging_dir.join(MIGRATION_RECEIPT_FILENAME);
        if let Err(err) = fs::write(&staging_receipt_path, &receipt_bytes)
            .and_then(|()| fs::File::open(&staging_receipt_path).and_then(|file| file.sync_all()))
        {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(LedgerMigrationError::Io(err.to_string()));
        }
        if let Err(err) = fs::rename(&staging_dir, target_epochs_dir) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(LedgerMigrationError::Io(err.to_string()));
        }
        Ok(receipt)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_staged_v2_replay(
    migration_id: &str,
    source: &DurableReferenceLedger,
    staging_dir: &Path,
    site_lineage: &str,
    authority: &StorageAuthorityScope,
    epoch_config: EpochLedgerConfig,
    now: TimestampNs,
    cancel_at: Option<MigrationStage>,
) -> Result<LedgerMigrationReceipt, LedgerMigrationError> {
    let mut staged = MerkleEpochLedger::open(
        staging_dir,
        site_lineage,
        epoch_config,
        IncompleteTailPolicy::Reject,
    )
    .map_err(|e| LedgerMigrationError::Io(e.to_string()))?;

    let mut migrated_batch_count = 0_u64;
    for v1_batch in source.batches() {
        let v2_batch = staged
            .prepare_batch(
                v1_batch.batch_id.clone(),
                v1_batch.deltas.clone(),
                v1_batch.children.clone(),
            )
            .map_err(|e| LedgerMigrationError::EquivalenceMismatch(e.to_string()))?;
        let _ = staged
            .append_batch(v2_batch)
            .map_err(|e| LedgerMigrationError::Io(e.to_string()))?;
        migrated_batch_count = migrated_batch_count.saturating_add(1);
    }
    if migrated_batch_count > 0 {
        let _ = staged
            .force_checkpoint()
            .map_err(|e| LedgerMigrationError::Io(e.to_string()))?;
    }

    // 3. Verify: differential object equivalence + standalone Merkle inclusion proofs!
    if cancel_at == Some(MigrationStage::Verify) {
        return Err(LedgerMigrationError::Cancelled {
            stage: MigrationStage::Verify,
        });
    }
    let verify_report = staged
        .verify_full_chain()
        .map_err(|e| LedgerMigrationError::EquivalenceMismatch(e.to_string()))?;

    let source_objects = &source.current().objects;
    if staged.head_anchor().commit_sequence != source.current().anchor.commit_sequence
        || staged.live_object_count() as usize != source_objects.len()
    {
        return Err(LedgerMigrationError::EquivalenceMismatch(format!(
            "sequence/object count mismatch: v1=({}, {}) v2=({}, {})",
            source.current().anchor.commit_sequence,
            source_objects.len(),
            staged.head_anchor().commit_sequence,
            staged.live_object_count()
        )));
    }

    let v2_state_root = staged.head_anchor().state_root;
    let mut verified_object_count = 0_u64;
    for (object_id, v1_rev) in source_objects {
        let Some(v2_rev) = staged.get_object(object_id) else {
            return Err(LedgerMigrationError::EquivalenceMismatch(format!(
                "object '{}' missing in staged v2 ledger",
                object_id.as_str()
            )));
        };
        if v2_rev != v1_rev {
            return Err(LedgerMigrationError::EquivalenceMismatch(format!(
                "object '{}' revision mismatch between v1 and staged v2",
                object_id.as_str()
            )));
        }
        let proof = staged
            .prove_object(object_id)
            .map_err(|e| LedgerMigrationError::EquivalenceMismatch(e.to_string()))?;
        verify_proof(v2_state_root, object_id, &proof)
            .map_err(|e| LedgerMigrationError::EquivalenceMismatch(e.to_string()))?;
        verified_object_count = verified_object_count.saturating_add(1);
    }

    let target_head_anchor = staged.head_anchor().clone();
    let target_history_root = verify_report.history_root;
    drop(staged);

    let mut receipt = LedgerMigrationReceipt {
        format_version: LEDGER_MIGRATION_RECEIPT_VERSION,
        migration_id: migration_id.to_owned(),
        from_version: StorageSchemaVersion::V1_0,
        to_version: StorageSchemaVersion::V2_0,
        contract_basis_digest: authority.contract_basis_digest,
        site_lineage: site_lineage.to_owned(),
        source_head_anchor: source.current().anchor.clone(),
        source_history_root: source.head_history_root(),
        target_head_anchor,
        target_history_root,
        migrated_batch_count,
        verified_object_count,
        outcome_state: MigrationOutcomeState::Committed,
        authority_generation: authority.authority_generation,
        privacy_epoch: authority.privacy_epoch,
        migrated_at: now,
        receipt_digest: ContentDigest::sha256(b"unsealed-migration-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self()?;
    Ok(receipt)
}

fn make_staging_path(target_epochs_dir: &Path) -> Result<PathBuf, LedgerMigrationError> {
    let parent = target_epochs_dir.parent().ok_or_else(|| {
        LedgerMigrationError::InvalidInput("target_epochs_dir has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent).map_err(|e| LedgerMigrationError::Io(e.to_string()))?;
    let name = target_epochs_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            LedgerMigrationError::InvalidInput("target_epochs_dir has invalid filename".to_owned())
        })?;
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".{name}.staging.{}.{seq}", std::process::id())))
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), LedgerMigrationError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(LedgerMigrationError::InvalidInput(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}
