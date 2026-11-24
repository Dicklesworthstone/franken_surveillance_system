#![forbid(unsafe_code)]
//! Typed error taxonomy for the sealed packfile object store and virtual root catalog.

use std::error::Error;
use std::fmt;
use std::io;

use fss_core::{ContentDigest, ContractError, DigestAlgorithm};
use fss_object::ObjectError;
use fss_runtime::authority::AuthorityError;
use fss_vault::SecretError;

use crate::format::PackId;

/// Filesystem operation category associated with an I/O failure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackIoOperation {
    /// Creating store directories.
    CreateDir,
    /// Opening a file handle.
    Open,
    /// Acquiring the exclusive store lock.
    Lock,
    /// Querying file metadata.
    Metadata,
    /// Listing directory entries.
    ReadDir,
    /// Positional or sequential read.
    Read,
    /// Sequential write.
    Write,
    /// Syncing file contents or metadata to stable storage.
    SyncFile,
    /// Syncing parent directory entries to stable storage.
    SyncDir,
    /// Truncating an incomplete tail record during recovery or rollback.
    Truncate,
    /// Atomic rename of a snapshot or journal file.
    Rename,
    /// Removing a temporary file.
    Remove,
}

impl fmt::Display for PackIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CreateDir => "create_dir",
            Self::Open => "open",
            Self::Lock => "lock",
            Self::Metadata => "metadata",
            Self::ReadDir => "read_dir",
            Self::Read => "read",
            Self::Write => "write",
            Self::SyncFile => "sync_file",
            Self::SyncDir => "sync_dir",
            Self::Truncate => "truncate",
            Self::Rename => "rename",
            Self::Remove => "remove",
        })
    }
}

/// Resource dimension for a soft or hard quota check.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotaResource {
    /// Number of live roots in the virtual root catalog.
    LiveRoots,
    /// Cumulative logical payload bytes stored in the pack store.
    TotalPayloadBytes,
}

impl fmt::Display for QuotaResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LiveRoots => "live_roots",
            Self::TotalPayloadBytes => "total_payload_bytes",
        })
    }
}

/// Deterministic fault-injection cut point for crash-consistency tests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackCutPoint {
    /// Immediately after child objects are written and fsynced in the packfile, before
    /// appending the root publication frame to `catalog.fssr`.
    AfterPackSyncBeforeRootAppend,
    /// Immediately after a compacted staging pack (`*.pack.compact.tmp`) is written and fsynced,
    /// before renaming it to its final `.fssp` path or touching `PackIndex`.
    CompactionBeforeStagingRename,
    /// Immediately after the compacted `.fssp` pack is durably renamed on disk, before swapping
    /// `PackIndex` pointers or unlinking the old packfile.
    CompactionAfterNewPackBeforeIndexSwap,
    /// Immediately after `PackIndex` pointers are swapped and `pack-index.fssi` is persisted,
    /// before unlinking the old superseded packfile.
    CompactionAfterIndexSwapBeforeOldPackUnlink,
}

impl fmt::Display for PackCutPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AfterPackSyncBeforeRootAppend => "after_pack_sync_before_root_append",
            Self::CompactionBeforeStagingRename => "compaction_before_staging_rename",
            Self::CompactionAfterNewPackBeforeIndexSwap => {
                "compaction_after_new_pack_before_index_swap"
            }
            Self::CompactionAfterIndexSwapBeforeOldPackUnlink => {
                "compaction_after_index_swap_before_old_pack_unlink"
            }
        })
    }
}

/// Typed failures produced by packfile storage, indexing, root catalog, and media chunk operations.
#[derive(Debug)]
pub enum PackError {
    /// Configuration parameters failed validation.
    InvalidConfig {
        /// Human-readable reason for the invalid configuration value.
        detail: String,
    },
    /// Another process already holds the exclusive store lock.
    StoreLocked,
    /// Filesystem I/O failure during an explicit operation.
    Io {
        /// The filesystem operation that failed.
        operation: PackIoOperation,
        /// Underlying OS I/O error kind.
        kind: io::ErrorKind,
        /// Diagnostic message without exposing secrets.
        detail: String,
    },
    /// Consecutive `EINTR` interruptions exceeded the bounded retry ceiling.
    InterruptedRetryExhausted {
        /// Operation that hit the bounded retry limit.
        operation: PackIoOperation,
        /// Maximum attempts allowed.
        attempts: u32,
    },
    /// A non-SHA-256 digest algorithm was supplied where SHA-256 is required.
    UnsupportedDigestAlgorithm(DigestAlgorithm),
    /// A single object exceeded the configured per-object byte ceiling.
    ObjectTooLarge {
        /// Attempted payload byte length.
        length: u64,
        /// Configured maximum byte length.
        maximum: u64,
    },
    /// A read operation exceeded the configured per-read or cumulative byte limit.
    ReadLimitExceeded {
        /// Bytes already consumed (or 0 for single-read bound).
        current: u64,
        /// Additional bytes requested.
        requested: u64,
        /// Configured ceiling.
        maximum: u64,
    },
    /// Requested content digest is not present in the pack index.
    MissingObject(ContentDigest),
    /// A declared digest did not match the SHA-256 computed over the bytes.
    DigestMismatch {
        /// Expected content digest.
        expected: ContentDigest,
        /// Digest computed over observed bytes.
        actual: ContentDigest,
    },
    /// Castagnoli CRC32C verification failed on a framed record, journal entry, or chunk table.
    CrcMismatch {
        /// Expected CRC32C stored in the frame.
        expected: u32,
        /// CRC32C computed over observed bytes.
        actual: u32,
    },
    /// Packfile header, footer, or record framing is malformed or corrupt.
    CorruptPack {
        /// Pack identifier where corruption was detected.
        pack_id: PackId,
        /// Byte offset associated with the corruption.
        offset: u64,
        /// Detailed structural reason.
        detail: String,
    },
    /// Index snapshot file is malformed or failed checksum verification.
    CorruptIndex {
        /// Detailed reason.
        detail: String,
    },
    /// Virtual root catalog journal or snapshot is corrupt.
    CorruptCatalog {
        /// Detailed reason.
        detail: String,
    },
    /// Media chunk (`FSMC`) binary container is invalid or failed verification.
    InvalidMediaChunk {
        /// Detailed reason.
        detail: String,
    },
    /// Invalid root identifier or root record field.
    InvalidRootRecord {
        /// Detailed reason.
        detail: String,
    },
    /// Attempted to publish or supersede into a root identifier that already exists.
    RootAlreadyExists(String),
    /// Requested root identifier does not exist in the catalog.
    RootNotFound(String),
    /// Attempted to supersede a root that is not currently `Live`.
    RootNotLive(String),
    /// Attempted to tombstone a root that was already tombstoned with a different reason digest.
    TombstoneConflict {
        /// Conflicting root identifier.
        root_id: String,
        /// Existing tombstone reason digest.
        existing_reason: ContentDigest,
        /// Newly supplied conflicting reason digest.
        attempted_reason: ContentDigest,
    },
    /// A hard quota limit rejected the write or root publication.
    QuotaExceeded {
        /// Quota resource dimension.
        resource: QuotaResource,
        /// Current usage.
        current: u64,
        /// Requested increment.
        requested: u64,
        /// Configured hard limit.
        maximum: u64,
    },
    /// Arithmetic overflow in offset or accounting math.
    ArithmeticOverflow,
    /// Canonical encoding or decoding failed.
    Canonical(ContractError),
    /// Runtime authority check failed or scope was cancelled.
    Authority(AuthorityError),
    /// Explicit cancellation observed before committing mutation.
    Cancelled,
    /// Internal synchronization lock was poisoned by a panic elsewhere.
    LockPoisoned,
    /// Requested content digest was permanently deleted under a committed deletion tombstone
    /// (`ERR-EVIDENCE-DELETED-001`).
    EvidenceDeleted {
        /// Deleted content digest.
        digest: ContentDigest,
        /// Committed tombstone reason digest witnessing the deletion.
        reason_digest: ContentDigest,
    },
    /// Deployment reached `Critical` capacity and all remaining capacity is pinned by active holds,
    /// obligations, or events (`ERR-STORAGE-QUOTA-PINNED-001`).
    QuotaPinned {
        /// Bytes pinned by active holds, obligations, or events.
        pinned_bytes: u64,
        /// Configured total deployment byte cap.
        cap_bytes: u64,
    },
    /// Physical reclamation refused because an object lacks a verified committed deletion tombstone.
    UncommittedTombstone {
        /// Packfile containing the un-tombstoned dead object.
        pack_id: PackId,
        /// Object digest missing a durable deletion tombstone.
        digest: ContentDigest,
    },
    /// Supplied `TombstoneCommitProof` failed cryptographic or store verification.
    InvalidTombstoneProof {
        /// Detailed reason.
        detail: String,
    },
    /// Operation requires a sealed immutable packfile, but the target pack is still active.
    PackNotSealed(PackId),
    /// Concurrent readers holding pins on a retired epoch did not drain within the bounded timeout.
    ReaderEpochDrainTimeout {
        /// Retired reader epoch awaiting drain before unlink.
        retired_epoch: u64,
        /// Active readers still pinning `<= retired_epoch`.
        active_readers: u64,
    },
    /// Retention ring policy or candidate metadata failed validation.
    RetentionPolicyViolation {
        /// Detailed reason.
        detail: String,
    },
    /// Deterministic test cut point triggered.
    InjectedCrash(PackCutPoint),
    /// AEAD authentication, AAD binding, or KEK verification failed (`ERR-CRYPTO-AUTH-FAILED-001`).
    CryptoAuthFailed {
        /// Non-secret diagnostic reason.
        detail: String,
    },
    /// Target Data Encryption Key was permanently destroyed via cryptographic erasure
    /// (`ERR-CRYPTO-KEY-ERASED-001`).
    CryptoKeyErased {
        /// Hex-encoded 128-bit DEK identifier.
        dek_id: String,
        /// Non-secret erasure rationale recorded in the tombstone.
        reason: String,
    },
    /// Target Data Encryption Key does not exist in the key envelope catalog.
    CryptoKeyNotFound {
        /// Hex-encoded 128-bit DEK identifier.
        dek_id: String,
    },
    /// Encrypted frame, container, or key catalog binary structure is invalid or unsupported.
    CryptoFormat {
        /// Non-secret structural detail.
        detail: String,
    },
    /// Explicit entropy source failed or produced invalid randomness.
    CryptoEntropy {
        /// Non-secret diagnostic detail.
        detail: String,
    },
    /// Explicit secret-authority (`SecretAccessCx` / `SecretStore`) check failed.
    CryptoAuthority {
        /// Non-secret diagnostic detail.
        detail: String,
    },
    /// Cold-tier S3/R2/B2 transport, HTTP, SigV4, XML, or endpoint approval failure.
    ArchiveTransport {
        /// Payload-free, credential-free diagnostic detail.
        detail: String,
    },
    /// Cold-tier archive ciphertext, manifest, or restored plaintext integrity verification failed.
    ArchiveIntegrity {
        /// Non-secret diagnostic detail.
        detail: String,
    },
    /// Remote cold-tier object does not exist at the target endpoint (HTTP 404).
    ArchiveMissing {
        /// Opaque cold object key that was missing.
        object_key: String,
    },
}

impl PackError {
    /// Returns the registered stable machine error identifier when applicable.
    #[must_use]
    pub const fn stable_error_id(&self) -> Option<&'static str> {
        match self {
            Self::EvidenceDeleted { .. } => Some("ERR-EVIDENCE-DELETED-001"),
            Self::QuotaPinned { .. } => Some("ERR-STORAGE-QUOTA-PINNED-001"),
            Self::CryptoAuthFailed { .. } => Some("ERR-CRYPTO-AUTH-FAILED-001"),
            Self::CryptoKeyErased { .. } => Some("ERR-CRYPTO-KEY-ERASED-001"),
            _ => None,
        }
    }

    /// Wraps an `std::io::Error` with explicit operation context.
    #[must_use]
    pub fn io(operation: PackIoOperation, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            detail: error.to_string(),
        }
    }

    /// Maps a pack-store error into [`ObjectError`] for [`fss_object::VerifiedObjectCatalog`].
    #[must_use]
    pub fn to_object_error(&self, digest: ContentDigest) -> ObjectError {
        match self {
            Self::MissingObject(d) => ObjectError::Missing(*d),
            Self::DigestMismatch { .. }
            | Self::CrcMismatch { .. }
            | Self::CorruptPack { .. }
            | Self::CryptoAuthFailed { .. }
            | Self::CryptoFormat { .. }
            | Self::ArchiveIntegrity { .. } => ObjectError::Corrupt(digest),
            Self::ObjectTooLarge { length, maximum } => ObjectError::ObjectTooLarge {
                length: usize::try_from(*length).unwrap_or(usize::MAX),
                maximum: usize::try_from(*maximum).unwrap_or(usize::MAX),
            },
            _ => ObjectError::Unavailable(digest),
        }
    }
}

impl From<ContractError> for PackError {
    fn from(error: ContractError) -> Self {
        Self::Canonical(error)
    }
}

impl From<AuthorityError> for PackError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<SecretError> for PackError {
    fn from(error: SecretError) -> Self {
        match error {
            SecretError::Cancelled { .. } => Self::Cancelled,
            SecretError::AuthFailed => Self::CryptoAuthFailed {
                detail: "secret authority authentication failed".to_owned(),
            },
            SecretError::Tampered { detail } => Self::CryptoAuthFailed {
                detail: detail.to_owned(),
            },
            SecretError::BackendUnavailable { detail, .. } => Self::CryptoEntropy { detail },
            other => Self::CryptoAuthority {
                detail: other.to_string(),
            },
        }
    }
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { detail } => write!(formatter, "invalid pack config: {detail}"),
            Self::StoreLocked => formatter.write_str("pack store lock is already held"),
            Self::Io {
                operation,
                kind,
                detail,
            } => write!(
                formatter,
                "pack I/O error during {operation} ({kind:?}): {detail}"
            ),
            Self::InterruptedRetryExhausted {
                operation,
                attempts,
            } => write!(
                formatter,
                "pack I/O {operation} interrupted {attempts} consecutive times"
            ),
            Self::UnsupportedDigestAlgorithm(alg) => {
                write!(
                    formatter,
                    "unsupported digest algorithm for pack store: {alg}"
                )
            }
            Self::ObjectTooLarge { length, maximum } => {
                write!(formatter, "object size {length} exceeds maximum {maximum}")
            }
            Self::ReadLimitExceeded {
                current,
                requested,
                maximum,
            } => write!(
                formatter,
                "read budget exceeded: {current} + {requested} > {maximum}"
            ),
            Self::MissingObject(digest) => {
                write!(formatter, "object not found in pack store: {digest}")
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "content digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::CrcMismatch { expected, actual } => {
                write!(
                    formatter,
                    "CRC32C mismatch: expected 0x{expected:08x}, actual 0x{actual:08x}"
                )
            }
            Self::CorruptPack {
                pack_id,
                offset,
                detail,
            } => write!(
                formatter,
                "corrupt pack {pack_id} at offset {offset}: {detail}"
            ),
            Self::CorruptIndex { detail } => write!(formatter, "corrupt pack index: {detail}"),
            Self::CorruptCatalog { detail } => write!(formatter, "corrupt root catalog: {detail}"),
            Self::InvalidMediaChunk { detail } => {
                write!(formatter, "invalid media chunk: {detail}")
            }
            Self::InvalidRootRecord { detail } => {
                write!(formatter, "invalid root record: {detail}")
            }
            Self::RootAlreadyExists(id) => write!(formatter, "root id already exists: {id}"),
            Self::RootNotFound(id) => write!(formatter, "root id not found: {id}"),
            Self::RootNotLive(id) => write!(formatter, "root id is not live: {id}"),
            Self::TombstoneConflict {
                root_id,
                existing_reason,
                attempted_reason,
            } => write!(
                formatter,
                "tombstone conflict for root {root_id}: existing {existing_reason}, attempted {attempted_reason}"
            ),
            Self::QuotaExceeded {
                resource,
                current,
                requested,
                maximum,
            } => write!(
                formatter,
                "hard quota exceeded for {resource}: {current} + {requested} > {maximum}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("pack offset or accounting overflow"),
            Self::Canonical(err) => write!(formatter, "canonical codec error: {err}"),
            Self::Authority(err) => write!(formatter, "runtime authority error: {err}"),
            Self::Cancelled => formatter.write_str("pack operation cancelled"),
            Self::LockPoisoned => formatter.write_str("internal synchronization lock poisoned"),
            Self::EvidenceDeleted {
                digest,
                reason_digest,
            } => write!(
                formatter,
                "ERR-EVIDENCE-DELETED-001: object {digest} permanently deleted under tombstone {reason_digest}"
            ),
            Self::QuotaPinned {
                pinned_bytes,
                cap_bytes,
            } => write!(
                formatter,
                "ERR-STORAGE-QUOTA-PINNED-001: {pinned_bytes} pinned bytes exhaust deployment cap {cap_bytes}"
            ),
            Self::UncommittedTombstone { pack_id, digest } => write!(
                formatter,
                "cannot physically reclaim object {digest} from pack {pack_id} without a committed deletion tombstone"
            ),
            Self::InvalidTombstoneProof { detail } => {
                write!(formatter, "invalid tombstone commit proof: {detail}")
            }
            Self::PackNotSealed(pack_id) => {
                write!(formatter, "pack {pack_id} is active and not sealed")
            }
            Self::ReaderEpochDrainTimeout {
                retired_epoch,
                active_readers,
            } => write!(
                formatter,
                "reader epoch {retired_epoch} still has {active_readers} active reader(s); refusing pack unlink"
            ),
            Self::RetentionPolicyViolation { detail } => {
                write!(formatter, "retention policy violation: {detail}")
            }
            Self::InjectedCrash(cut) => write!(formatter, "injected crash at cut point {cut}"),
            Self::CryptoAuthFailed { detail } => {
                write!(formatter, "ERR-CRYPTO-AUTH-FAILED-001: {detail}")
            }
            Self::CryptoKeyErased { dek_id, reason } => write!(
                formatter,
                "ERR-CRYPTO-KEY-ERASED-001: DEK {dek_id} cryptographically erased ({reason})"
            ),
            Self::CryptoKeyNotFound { dek_id } => {
                write!(formatter, "DEK {dek_id} not found in key envelope catalog")
            }
            Self::CryptoFormat { detail } => {
                write!(
                    formatter,
                    "invalid encrypted pack or catalog format: {detail}"
                )
            }
            Self::CryptoEntropy { detail } => {
                write!(formatter, "cryptographic entropy failure: {detail}")
            }
            Self::CryptoAuthority { detail } => {
                write!(
                    formatter,
                    "cryptographic secret authority refused: {detail}"
                )
            }
            Self::ArchiveTransport { detail } => {
                write!(formatter, "cold archive transport failure: {detail}")
            }
            Self::ArchiveIntegrity { detail } => {
                write!(formatter, "cold archive integrity failure: {detail}")
            }
            Self::ArchiveMissing { object_key } => {
                write!(formatter, "cold archive object not found: {object_key}")
            }
        }
    }
}

impl Error for PackError {}
