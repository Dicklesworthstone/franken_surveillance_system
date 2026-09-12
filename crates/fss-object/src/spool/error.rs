//! Typed failure taxonomy for the content-addressed staging spool.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;

use fss_core::{ContentDigest, DigestAlgorithm};

/// Why the bytes held under one object name cannot be trusted as that object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorruptionKind {
    /// Fewer bytes are present than the envelope header (or the header itself) requires.
    Truncated {
        /// Byte length the envelope requires.
        expected_len: u64,
        /// Byte length observed.
        actual_len: u64,
    },
    /// More bytes are present than the envelope declares.
    TrailingBytes {
        /// Byte length the envelope requires.
        expected_len: u64,
        /// Byte length observed, capped at the bounded read length.
        actual_len: u64,
    },
    /// The file does not start with the spool envelope magic: it was not written by the spool.
    ForeignFile,
    /// The entry at the object name is a directory, symlink, or other non-regular file.
    NotRegularFile,
    /// The envelope names a format version this implementation does not read.
    UnsupportedFormatVersion(u16),
    /// The envelope names a digest algorithm tag this implementation does not read.
    UnsupportedAlgorithmTag(u16),
    /// The envelope records a different digest than the file name claims.
    NameDigestMismatch {
        /// Digest recorded inside the envelope header.
        recorded: ContentDigest,
    },
    /// The envelope declares a payload larger than the configured per-object bound.
    DeclaredLengthExceedsLimit {
        /// Declared payload length.
        declared: u64,
        /// Configured maximum payload length.
        maximum: u64,
    },
    /// The payload bytes hash to a different digest than their name.
    ContentDigestMismatch {
        /// Digest actually computed over the stored payload.
        computed: ContentDigest,
    },
    /// An indexed object file disappeared from the spool.
    Vanished,
}

impl fmt::Display for CorruptionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "truncated: {actual_len} bytes present, {expected_len} required"
            ),
            Self::TrailingBytes {
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "trailing bytes: at least {actual_len} bytes present, {expected_len} declared"
            ),
            Self::ForeignFile => formatter.write_str("foreign file without spool envelope magic"),
            Self::NotRegularFile => formatter.write_str("entry is not a regular file"),
            Self::UnsupportedFormatVersion(version) => {
                write!(formatter, "unsupported spool format version {version}")
            }
            Self::UnsupportedAlgorithmTag(tag) => {
                write!(formatter, "unsupported spool digest algorithm tag {tag}")
            }
            Self::NameDigestMismatch { recorded } => {
                write!(formatter, "envelope records digest {recorded}")
            }
            Self::DeclaredLengthExceedsLimit { declared, maximum } => write!(
                formatter,
                "declared payload length {declared} exceeds maximum {maximum}"
            ),
            Self::ContentDigestMismatch { computed } => {
                write!(formatter, "payload hashes to {computed}")
            }
            Self::Vanished => formatter.write_str("indexed object file vanished"),
        }
    }
}

/// Instrumented crash points inside one `stage` call, used by fault-injection tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagePhase {
    /// The staging file is written and fsynced but not yet renamed into the object directory.
    AfterStagingWrite,
    /// The staging file is renamed but the directories are not yet fsynced or indexed.
    AfterRename,
}

impl fmt::Display for StagePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AfterStagingWrite => "after_staging_write",
            Self::AfterRename => "after_rename",
        })
    }
}

/// Filesystem operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolIoOperation {
    /// Creating the spool root or one of its directories.
    CreateDirectory,
    /// Opening the spool lock file.
    OpenLock,
    /// Acquiring the exclusive spool lock.
    Lock,
    /// Listing a spool directory.
    ScanDirectory,
    /// Inspecting entry metadata without following symlinks.
    Inspect,
    /// Reading an object or staging file.
    ReadObject,
    /// Creating a fresh staging file.
    CreateStaging,
    /// Writing and fsyncing a staging file.
    WriteStaging,
    /// Renaming a staging file into the object directory.
    Rename,
    /// Fsyncing a spool directory.
    SyncDirectory,
    /// Removing an orphaned staging file.
    RemoveStaging,
}

impl fmt::Display for SpoolIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CreateDirectory => "create_directory",
            Self::OpenLock => "open_lock",
            Self::Lock => "lock",
            Self::ScanDirectory => "scan_directory",
            Self::Inspect => "inspect",
            Self::ReadObject => "read_object",
            Self::CreateStaging => "create_staging",
            Self::WriteStaging => "write_staging",
            Self::Rename => "rename",
            Self::SyncDirectory => "sync_directory",
            Self::RemoveStaging => "remove_staging",
        })
    }
}

/// A configured spool bound that cannot be honored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolLimitViolation {
    /// The per-object bound exceeds the crate-wide object format maximum.
    ObjectBoundAboveFormatMaximum {
        /// Requested per-object bound.
        requested: usize,
        /// Crate-wide maximum object length.
        maximum: usize,
    },
    /// The directory scan bound could not even list the admitted object count.
    ScanBoundBelowObjectBound {
        /// Requested scan bound.
        max_scan_entries: usize,
        /// Requested object-count bound.
        max_objects: usize,
    },
}

impl fmt::Display for SpoolLimitViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectBoundAboveFormatMaximum { requested, maximum } => write!(
                formatter,
                "per-object bound {requested} exceeds format maximum {maximum}"
            ),
            Self::ScanBoundBelowObjectBound {
                max_scan_entries,
                max_objects,
            } => write!(
                formatter,
                "scan bound {max_scan_entries} is below object bound {max_objects}"
            ),
        }
    }
}

/// Failures from staging, verifying, reading, or recovering the on-disk spool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpoolError {
    /// Configured limits are inconsistent.
    InvalidLimits(SpoolLimitViolation),
    /// A spool directory or lock path is missing, a symlink, or the wrong file type.
    InvalidLayout {
        /// Offending path.
        path: PathBuf,
    },
    /// Another open spool holds the exclusive lock on this root.
    Locked {
        /// Lock file path.
        path: PathBuf,
    },
    /// A spool directory holds more entries than the scan bound admits.
    EntryLimit {
        /// Directory being scanned.
        directory: PathBuf,
        /// Maximum admitted entries.
        maximum: usize,
    },
    /// The declared digest uses an algorithm the spool does not key objects by.
    UnsupportedAlgorithm(DigestAlgorithm),
    /// One payload exceeds the per-object bound.
    ObjectTooLarge {
        /// Attempted payload length.
        length: usize,
        /// Maximum admitted payload length.
        maximum: usize,
    },
    /// The payload does not hash to the digest the caller declared.
    DigestMismatch {
        /// Digest declared by the caller.
        declared: ContentDigest,
        /// Digest computed over the payload.
        computed: ContentDigest,
    },
    /// Adding a new unique object would exceed the object-count bound.
    ObjectCountLimit {
        /// Current indexed object count.
        current: usize,
        /// Maximum admitted object count.
        maximum: usize,
    },
    /// Adding a new unique object would exceed the byte quota.
    ByteQuotaExceeded {
        /// Bytes currently charged (objects, corrupt entries, orphaned staging files).
        current: u64,
        /// Additional payload bytes requested.
        requested: u64,
        /// Maximum admitted bytes.
        maximum: u64,
    },
    /// No object with this digest is indexed in the spool.
    Missing(ContentDigest),
    /// The bytes held under this digest cannot be trusted.
    Corrupt {
        /// Object digest.
        digest: ContentDigest,
        /// Classified corruption.
        kind: CorruptionKind,
    },
    /// Different bytes verified under the same SHA-256 digest.
    DigestCollision(ContentDigest),
    /// An entry exists at an object path the spool did not index; it is never overwritten.
    UnindexedEntry {
        /// Offending path.
        path: PathBuf,
    },
    /// The staging file failed read-back verification before rename; nothing was published.
    IngestReadback {
        /// Object digest.
        digest: ContentDigest,
        /// Classified read-back failure.
        kind: CorruptionKind,
    },
    /// Every bounded staging name for this digest is already taken.
    StagingNamesExhausted {
        /// Object digest.
        digest: ContentDigest,
        /// Number of names tried.
        attempts: u32,
    },
    /// The object was renamed into place but the directory fsync failed. Its durability is
    /// indeterminate; this instance is poisoned and must be reopened to reconcile.
    StageIndeterminate {
        /// Object digest.
        digest: ContentDigest,
        /// Failed operation.
        operation: SpoolIoOperation,
        /// I/O failure kind.
        kind: io::ErrorKind,
    },
    /// A fault-injection crash point fired; this instance is poisoned as if the process died.
    InjectedCrash {
        /// Crash point that fired.
        phase: StagePhase,
    },
    /// This instance observed a crash or indeterminate outcome and must be reopened.
    Poisoned,
    /// Byte accounting would overflow `u64`.
    AccountingOverflow,
    /// A filesystem operation failed.
    Io {
        /// Failed operation.
        operation: SpoolIoOperation,
        /// Path being operated on.
        path: PathBuf,
        /// I/O failure kind.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(violation) => {
                write!(formatter, "invalid spool limits: {violation}")
            }
            Self::InvalidLayout { path } => {
                write!(formatter, "invalid spool layout at {}", path.display())
            }
            Self::Locked { path } => {
                write!(
                    formatter,
                    "spool is locked by another owner: {}",
                    path.display()
                )
            }
            Self::EntryLimit { directory, maximum } => write!(
                formatter,
                "spool directory {} exceeds {maximum} entries",
                directory.display()
            ),
            Self::UnsupportedAlgorithm(algorithm) => write!(
                formatter,
                "spool keys objects by sha256, not {}",
                algorithm.as_str()
            ),
            Self::ObjectTooLarge { length, maximum } => {
                write!(formatter, "object size {length} exceeds maximum {maximum}")
            }
            Self::DigestMismatch { declared, computed } => write!(
                formatter,
                "payload hashes to {computed}, not declared {declared}"
            ),
            Self::ObjectCountLimit { current, maximum } => {
                write!(
                    formatter,
                    "object count {current} reached maximum {maximum}"
                )
            }
            Self::ByteQuotaExceeded {
                current,
                requested,
                maximum,
            } => write!(
                formatter,
                "spool bytes {current} + {requested} exceed quota {maximum}"
            ),
            Self::Missing(digest) => write!(formatter, "object is not in the spool: {digest}"),
            Self::Corrupt { digest, kind } => {
                write!(formatter, "spooled object {digest} is corrupt: {kind}")
            }
            Self::DigestCollision(digest) => {
                write!(formatter, "different bytes verified under digest {digest}")
            }
            Self::UnindexedEntry { path } => write!(
                formatter,
                "unindexed entry occupies object path {}",
                path.display()
            ),
            Self::IngestReadback { digest, kind } => write!(
                formatter,
                "staging read-back for {digest} failed before rename: {kind}"
            ),
            Self::StagingNamesExhausted { digest, attempts } => write!(
                formatter,
                "all {attempts} staging names for {digest} are taken"
            ),
            Self::StageIndeterminate {
                digest,
                operation,
                kind,
            } => write!(
                formatter,
                "stage of {digest} is indeterminate after {operation} failed: {kind}"
            ),
            Self::InjectedCrash { phase } => write!(formatter, "injected crash {phase}"),
            Self::Poisoned => {
                formatter.write_str("spool instance is poisoned; reopen to reconcile")
            }
            Self::AccountingOverflow => formatter.write_str("spool byte accounting overflow"),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "spool {operation} failed at {}: {kind}",
                path.display()
            ),
        }
    }
}

impl Error for SpoolError {}
