//! Typed failures for root-last local manifest publication.
//!
//! Every variant maps to one registered stable identity in `registries/ERRORS.md` and one safe
//! next action. No failure before the root rename leaves a root visible; failures at or after the
//! rename are reported as indeterminate or crashed rather than guessed.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;

use fss_core::{ContentDigest, ContractError};
use fss_object::{ObjectError, SpoolError};

use super::{PublishCutPoint, SlotName};

/// Every stable error identity a local publication failure can carry.
pub const LOCAL_PUBLICATION_ERROR_CODES: &[&str] = &[
    "ERR-PUBLICATION-PARTIAL-001",
    "ERR-PUBLICATION-LOCAL-INVALID-CONFIG-001",
    "ERR-PUBLICATION-LOCAL-SLOT-INVALID-001",
    "ERR-PUBLICATION-LOCAL-BOUND-001",
    "ERR-PUBLICATION-LOCAL-CAPACITY-001",
    "ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001",
    "ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001",
    "ERR-PUBLICATION-LOCAL-UNAVAILABLE-001",
    "ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001",
    "ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001",
    "ERR-PUBLICATION-LOCAL-ORPHAN-TEMP-001",
    "ERR-PUBLICATION-LOCAL-MANIFEST-MISMATCH-001",
    "ERR-PUBLICATION-LOCAL-SPOOL-001",
    "ERR-PUBLICATION-LOCAL-IO-001",
    "ERR-PUBLICATION-LOCAL-LOCKED-001",
    "ERR-PUBLICATION-LOCAL-LAYOUT-001",
    "ERR-PUBLICATION-LOCAL-INDETERMINATE-001",
    "ERR-PUBLICATION-LOCAL-INJECTED-CRASH-001",
    "ERR-PUBLICATION-LOCAL-CANCELLED-001",
    "ERR-PUBLICATION-LOCAL-POISONED-001",
    "ERR-PUBLICATION-LOCAL-DELETION-AUTHORITY-001",
    "ERR-PUBLICATION-LOCAL-TOMBSTONE-CONFLICT-001",
    "ERR-PUBLICATION-LOCAL-TOMBSTONE-REACHABLE-001",
    "ERR-PUBLICATION-LOCAL-CORRUPT-TOMBSTONE-001",
    "ERR-PUBLICATION-LOCAL-ENCODING-001",
];

/// Why a slot name is outside the slot grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotViolation {
    /// The slot name is empty.
    Empty,
    /// The slot name exceeds [`super::MAX_SLOT_NAME_BYTES`].
    TooLong {
        /// Byte length of the rejected name.
        length: usize,
        /// Maximum admitted byte length.
        maximum: usize,
    },
    /// A byte is outside `[a-z0-9]` (first byte) or `[a-z0-9_-]` (later bytes).
    InvalidByte {
        /// Byte offset of the first rejected byte.
        index: usize,
    },
}

impl fmt::Display for SlotViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("slot name is empty"),
            Self::TooLong { length, maximum } => {
                write!(
                    formatter,
                    "slot name has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidByte { index } => {
                write!(
                    formatter,
                    "slot name byte {index} is outside the slot grammar"
                )
            }
        }
    }
}

impl Error for SlotViolation {}

/// A configured publication bound that cannot be honored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalLimitViolation {
    /// A root, child, or tombstone bound is zero.
    ZeroBound,
    /// The root bound exceeds [`super::MAX_LOCAL_ROOTS`].
    RootBoundAboveMaximum {
        /// Requested bound.
        requested: usize,
        /// Maximum admitted bound.
        maximum: usize,
    },
    /// The child bound exceeds [`fss_object::MAX_MANIFEST_CHILDREN`].
    ChildBoundAboveFormatMaximum {
        /// Requested bound.
        requested: usize,
        /// Manifest format maximum.
        maximum: usize,
    },
    /// The tombstone bound exceeds [`super::MAX_LOCAL_TOMBSTONES`].
    TombstoneBoundAboveMaximum {
        /// Requested bound.
        requested: usize,
        /// Maximum admitted bound.
        maximum: usize,
    },
    /// The directory scan bound cannot list the admitted root or tombstone count.
    ScanBoundBelowEntryBound {
        /// Requested scan bound.
        max_scan_entries: usize,
        /// Larger of the root and tombstone bounds.
        required: usize,
    },
}

impl fmt::Display for LocalLimitViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBound => {
                formatter.write_str("root, child, and tombstone bounds must be >= 1")
            }
            Self::RootBoundAboveMaximum { requested, maximum } => {
                write!(
                    formatter,
                    "root bound {requested} exceeds maximum {maximum}"
                )
            }
            Self::ChildBoundAboveFormatMaximum { requested, maximum } => write!(
                formatter,
                "child bound {requested} exceeds manifest format maximum {maximum}"
            ),
            Self::TombstoneBoundAboveMaximum { requested, maximum } => {
                write!(
                    formatter,
                    "tombstone bound {requested} exceeds maximum {maximum}"
                )
            }
            Self::ScanBoundBelowEntryBound {
                max_scan_entries,
                required,
            } => write!(
                formatter,
                "scan bound {max_scan_entries} is below entry bound {required}"
            ),
        }
    }
}

/// Which reference of a publication or tombstone request was checked.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReferenceRole {
    /// A direct child object named by the manifest.
    Child,
    /// The manifest's typed metadata object.
    Metadata,
    /// The canonical manifest body object whose digest is the root.
    ManifestBody,
    /// The deletion authority witness of a tombstone record.
    DeletionWitness,
    /// An object reached through a child that is itself the root of a visible slot.
    Descendant,
}

/// Why a referenced object blocks publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockReason {
    /// No object with this digest is in the spool.
    Missing,
    /// The object is staged but has not been re-read and rehashed in this session.
    NotVerified,
    /// The object's bytes failed digest verification.
    Corrupt,
    /// A durable local tombstone names the object.
    Tombstoned,
    /// Custody could not be determined (I/O failure or poisoned spool).
    Unavailable,
    /// Any other custody failure, preserved verbatim.
    Other(ObjectError),
}

impl From<ObjectError> for BlockReason {
    fn from(value: ObjectError) -> Self {
        match value {
            ObjectError::Missing(_) => Self::Missing,
            ObjectError::NotVerified(_) => Self::NotVerified,
            ObjectError::Corrupt(_) => Self::Corrupt,
            ObjectError::Tombstoned(_) => Self::Tombstoned,
            ObjectError::Unavailable(_) => Self::Unavailable,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("missing"),
            Self::NotVerified => formatter.write_str("not verified"),
            Self::Corrupt => formatter.write_str("corrupt"),
            Self::Tombstoned => formatter.write_str("tombstoned"),
            Self::Unavailable => formatter.write_str("custody unavailable"),
            Self::Other(error) => write!(formatter, "{error}"),
        }
    }
}

/// Which bounded resource is exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityResource {
    /// Visible roots.
    Roots,
    /// Durable tombstones.
    Tombstones,
}

/// Filesystem operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalIoOperation {
    /// Creating a publication directory.
    CreateDirectory,
    /// Opening the lock file.
    OpenLock,
    /// Acquiring the exclusive lock.
    Lock,
    /// Listing a directory.
    ScanDirectory,
    /// Inspecting entry metadata without following symlinks.
    Inspect,
    /// Reading a root or tombstone record.
    ReadRecord,
    /// Creating a temporary record.
    CreateTemp,
    /// Writing and fsyncing a temporary record.
    WriteTemp,
    /// Renaming a temporary record into place.
    Rename,
    /// Fsyncing a publication directory.
    SyncDirectory,
    /// Removing a temporary record.
    RemoveTemp,
}

impl fmt::Display for LocalIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CreateDirectory => "create_directory",
            Self::OpenLock => "open_lock",
            Self::Lock => "lock",
            Self::ScanDirectory => "scan_directory",
            Self::Inspect => "inspect",
            Self::ReadRecord => "read_record",
            Self::CreateTemp => "create_temp",
            Self::WriteTemp => "write_temp",
            Self::Rename => "rename",
            Self::SyncDirectory => "sync_directory",
            Self::RemoveTemp => "remove_temp",
        })
    }
}

/// Safe next action for a rejected publication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPublicationGuidance {
    /// Stage and verify the named reference, then retry; the retry is idempotent.
    StageAndVerifyReferences,
    /// Repair or restage the named custody, or quarantine the broken record.
    RepairCustody,
    /// The input is malformed or conflicts with durable state; do not retry as-is.
    RejectInput,
    /// Repair the configured limits.
    RepairConfiguration,
    /// A capacity bound is reached; archive or rotate first.
    ArchiveOrRotate,
    /// Discard classified orphaned temporary records, then retry.
    DiscardOrphans,
    /// This instance must be dropped and the root reopened to reconcile.
    ReopenAndReconcile,
    /// Nothing became visible; retry when resumed.
    RetryIdempotently,
    /// Another owner holds the lock; wait for it to close.
    WaitForOwner,
    /// Storage failed before any visibility change; repair storage, then retry.
    RepairStorage,
    /// Supply a verified deletion authority witness.
    SupplyDeletionAuthority,
    /// Deletion of a visible closure belongs to the deletion-closure owner.
    RunDeletionClosure,
}

/// Failure of a root-last local publication, tombstone, or reopen operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalPublicationError {
    /// Configured limits are inconsistent.
    InvalidLimits(LocalLimitViolation),
    /// A slot name is outside the slot grammar.
    InvalidSlot {
        /// Classified violation.
        violation: SlotViolation,
    },
    /// The manifest names more direct children than the configured bound.
    ManifestChildBound {
        /// Direct children, including the metadata object.
        count: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A publication directory holds more entries than the scan bound admits.
    EntryLimit {
        /// Directory being scanned.
        directory: PathBuf,
        /// Maximum admitted entries.
        maximum: usize,
    },
    /// An encoded or on-disk record exceeds its size bound.
    RecordTooLarge {
        /// Observed length.
        length: u64,
        /// Maximum admitted length.
        maximum: u64,
    },
    /// A configured root or tombstone capacity is exhausted.
    Capacity {
        /// Exhausted resource.
        resource: CapacityResource,
        /// Current count.
        current: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A referenced object cannot be proven verified and durable; nothing became visible.
    ReferenceBlocked {
        /// The blocking object.
        object: ContentDigest,
        /// Its role in the request.
        role: ReferenceRole,
        /// Why it blocks.
        reason: BlockReason,
    },
    /// The slot already holds a different visible root.
    SlotConflict {
        /// Requested slot.
        slot: SlotName,
        /// Root already visible in the slot.
        existing: ContentDigest,
        /// Root the caller asked to publish.
        requested: ContentDigest,
    },
    /// The slot holds a root record that failed verification on reopen or re-read.
    BrokenSlot {
        /// Affected slot.
        slot: SlotName,
    },
    /// An orphaned temporary record occupies the path this operation needs.
    OrphanedTemp {
        /// Path relative to the publication root.
        path: PathBuf,
    },
    /// The manifest root does not match its canonical body or its staged read-back.
    ManifestMismatch {
        /// Declared manifest root.
        root: ContentDigest,
    },
    /// The staging spool refused an operation.
    Spool(SpoolError),
    /// A filesystem operation failed before any visibility change.
    Io {
        /// Failed operation.
        operation: LocalIoOperation,
        /// Absolute path being operated on.
        path: PathBuf,
        /// I/O failure kind.
        kind: io::ErrorKind,
    },
    /// Another open publisher holds the exclusive lock.
    Locked {
        /// Absolute lock file path.
        path: PathBuf,
    },
    /// A publication directory, lock, or record path has the wrong type or is occupied.
    InvalidLayout {
        /// Absolute offending path.
        path: PathBuf,
    },
    /// A record was renamed into place but its directory fsync failed; durability is unknown.
    Indeterminate {
        /// Absolute path of the renamed record.
        path: PathBuf,
        /// I/O failure kind.
        kind: io::ErrorKind,
    },
    /// A fault-injection cut point fired; this instance behaves as a dead process.
    InjectedCrash {
        /// Cut point that fired.
        point: PublishCutPoint,
    },
    /// The caller cancelled before the root rename; nothing became visible.
    Cancelled {
        /// Cut point at which cancellation was observed.
        point: PublishCutPoint,
    },
    /// This instance observed a crash or indeterminate outcome and must be reopened.
    Poisoned,
    /// A tombstone record carries no deletion authority witness.
    MissingDeletionAuthority {
        /// Object the tombstone names.
        object: ContentDigest,
    },
    /// A different tombstone record is already durable for this object.
    TombstoneConflict {
        /// Object the tombstone names.
        object: ContentDigest,
    },
    /// The object is reachable from a visible root; local tombstoning would silently unpublish.
    TombstoneBlockedByVisibleRoot {
        /// Object the tombstone names.
        object: ContentDigest,
        /// First slot (in slot order) whose closure reaches it.
        slot: SlotName,
    },
    /// A durable tombstone record failed verification on open; the open fails closed.
    CorruptTombstone {
        /// Path relative to the publication root.
        path: PathBuf,
    },
    /// Canonical encoding exceeded an encoder bound.
    Encoding(ContractError),
}

impl LocalPublicationError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits(_) => "ERR-PUBLICATION-LOCAL-INVALID-CONFIG-001",
            Self::InvalidSlot { .. } => "ERR-PUBLICATION-LOCAL-SLOT-INVALID-001",
            Self::ManifestChildBound { .. }
            | Self::EntryLimit { .. }
            | Self::RecordTooLarge { .. } => "ERR-PUBLICATION-LOCAL-BOUND-001",
            Self::Capacity { .. } => "ERR-PUBLICATION-LOCAL-CAPACITY-001",
            Self::ReferenceBlocked { reason, .. } => match reason {
                BlockReason::Missing | BlockReason::NotVerified => "ERR-PUBLICATION-PARTIAL-001",
                BlockReason::Corrupt => "ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001",
                BlockReason::Tombstoned => "ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001",
                BlockReason::Unavailable | BlockReason::Other(_) => {
                    "ERR-PUBLICATION-LOCAL-UNAVAILABLE-001"
                }
            },
            Self::SlotConflict { .. } => "ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001",
            Self::BrokenSlot { .. } => "ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001",
            Self::OrphanedTemp { .. } => "ERR-PUBLICATION-LOCAL-ORPHAN-TEMP-001",
            Self::ManifestMismatch { .. } => "ERR-PUBLICATION-LOCAL-MANIFEST-MISMATCH-001",
            Self::Spool(_) => "ERR-PUBLICATION-LOCAL-SPOOL-001",
            Self::Io { .. } => "ERR-PUBLICATION-LOCAL-IO-001",
            Self::Locked { .. } => "ERR-PUBLICATION-LOCAL-LOCKED-001",
            Self::InvalidLayout { .. } => "ERR-PUBLICATION-LOCAL-LAYOUT-001",
            Self::Indeterminate { .. } => "ERR-PUBLICATION-LOCAL-INDETERMINATE-001",
            Self::InjectedCrash { .. } => "ERR-PUBLICATION-LOCAL-INJECTED-CRASH-001",
            Self::Cancelled { .. } => "ERR-PUBLICATION-LOCAL-CANCELLED-001",
            Self::Poisoned => "ERR-PUBLICATION-LOCAL-POISONED-001",
            Self::MissingDeletionAuthority { .. } => "ERR-PUBLICATION-LOCAL-DELETION-AUTHORITY-001",
            Self::TombstoneConflict { .. } => "ERR-PUBLICATION-LOCAL-TOMBSTONE-CONFLICT-001",
            Self::TombstoneBlockedByVisibleRoot { .. } => {
                "ERR-PUBLICATION-LOCAL-TOMBSTONE-REACHABLE-001"
            }
            Self::CorruptTombstone { .. } => "ERR-PUBLICATION-LOCAL-CORRUPT-TOMBSTONE-001",
            Self::Encoding(_) => "ERR-PUBLICATION-LOCAL-ENCODING-001",
        }
    }

    /// Safe next action for this failure.
    #[must_use]
    pub const fn guidance(&self) -> LocalPublicationGuidance {
        match self {
            Self::InvalidLimits(_) => LocalPublicationGuidance::RepairConfiguration,
            Self::InvalidSlot { .. }
            | Self::ManifestChildBound { .. }
            | Self::RecordTooLarge { .. }
            | Self::SlotConflict { .. }
            | Self::ManifestMismatch { .. }
            | Self::TombstoneConflict { .. }
            | Self::Encoding(_) => LocalPublicationGuidance::RejectInput,
            Self::Capacity { .. } => LocalPublicationGuidance::ArchiveOrRotate,
            Self::ReferenceBlocked { reason, .. } => match reason {
                BlockReason::Missing | BlockReason::NotVerified => {
                    LocalPublicationGuidance::StageAndVerifyReferences
                }
                BlockReason::Corrupt => LocalPublicationGuidance::RepairCustody,
                BlockReason::Tombstoned => LocalPublicationGuidance::RejectInput,
                BlockReason::Unavailable | BlockReason::Other(_) => {
                    LocalPublicationGuidance::ReopenAndReconcile
                }
            },
            Self::BrokenSlot { .. } | Self::CorruptTombstone { .. } => {
                LocalPublicationGuidance::RepairCustody
            }
            Self::OrphanedTemp { .. } => LocalPublicationGuidance::DiscardOrphans,
            Self::Spool(error) => match error {
                SpoolError::InjectedCrash { .. }
                | SpoolError::StageIndeterminate { .. }
                | SpoolError::Poisoned => LocalPublicationGuidance::ReopenAndReconcile,
                SpoolError::Locked { .. } => LocalPublicationGuidance::WaitForOwner,
                _ => LocalPublicationGuidance::RepairStorage,
            },
            Self::Io { .. } | Self::InvalidLayout { .. } | Self::EntryLimit { .. } => {
                LocalPublicationGuidance::RepairStorage
            }
            Self::Locked { .. } => LocalPublicationGuidance::WaitForOwner,
            Self::Indeterminate { .. } | Self::InjectedCrash { .. } | Self::Poisoned => {
                LocalPublicationGuidance::ReopenAndReconcile
            }
            Self::Cancelled { .. } => LocalPublicationGuidance::RetryIdempotently,
            Self::MissingDeletionAuthority { .. } => {
                LocalPublicationGuidance::SupplyDeletionAuthority
            }
            Self::TombstoneBlockedByVisibleRoot { .. } => {
                LocalPublicationGuidance::RunDeletionClosure
            }
        }
    }
}

impl fmt::Display for LocalPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.code())?;
        match self {
            Self::InvalidLimits(violation) => write!(formatter, "invalid limits: {violation}"),
            Self::InvalidSlot { violation } => write!(formatter, "invalid slot: {violation}"),
            Self::ManifestChildBound { count, maximum } => write!(
                formatter,
                "manifest names {count} children; maximum is {maximum}"
            ),
            Self::EntryLimit { directory, maximum } => write!(
                formatter,
                "directory {} exceeds {maximum} entries",
                directory.display()
            ),
            Self::RecordTooLarge { length, maximum } => {
                write!(formatter, "record length {length} exceeds {maximum}")
            }
            Self::Capacity {
                resource,
                current,
                maximum,
            } => write!(
                formatter,
                "{resource:?} capacity exhausted: {current} of {maximum}"
            ),
            Self::ReferenceBlocked {
                object,
                role,
                reason,
            } => write!(
                formatter,
                "{role:?} reference {object} blocks publication: {reason}"
            ),
            Self::SlotConflict {
                slot,
                existing,
                requested,
            } => write!(
                formatter,
                "slot {slot} already holds root {existing}; refused {requested}"
            ),
            Self::BrokenSlot { slot } => {
                write!(formatter, "slot {slot} holds a broken root record")
            }
            Self::OrphanedTemp { path } => {
                write!(formatter, "orphaned temporary record {}", path.display())
            }
            Self::ManifestMismatch { root } => {
                write!(formatter, "manifest body does not match root {root}")
            }
            Self::Spool(error) => write!(formatter, "spool: {error}"),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "{operation} failed at {}: {kind}",
                path.display()
            ),
            Self::Locked { path } => {
                write!(formatter, "locked by another owner: {}", path.display())
            }
            Self::InvalidLayout { path } => {
                write!(formatter, "invalid layout at {}", path.display())
            }
            Self::Indeterminate { path, kind } => write!(
                formatter,
                "record {} renamed but directory fsync failed: {kind}",
                path.display()
            ),
            Self::InjectedCrash { point } => write!(formatter, "injected crash {point}"),
            Self::Cancelled { point } => write!(formatter, "cancelled {point}"),
            Self::Poisoned => formatter.write_str("publisher is poisoned; reopen to reconcile"),
            Self::MissingDeletionAuthority { object } => {
                write!(formatter, "tombstone for {object} lacks a deletion witness")
            }
            Self::TombstoneConflict { object } => {
                write!(formatter, "a different tombstone is durable for {object}")
            }
            Self::TombstoneBlockedByVisibleRoot { object, slot } => {
                write!(formatter, "{object} is reachable from visible slot {slot}")
            }
            Self::CorruptTombstone { path } => {
                write!(formatter, "corrupt tombstone record {}", path.display())
            }
            Self::Encoding(error) => write!(formatter, "canonical encoding failed: {error}"),
        }
    }
}

impl Error for LocalPublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spool(error) => Some(error),
            Self::InvalidSlot { violation } => Some(violation),
            _ => None,
        }
    }
}

impl From<SlotViolation> for LocalPublicationError {
    fn from(violation: SlotViolation) -> Self {
        Self::InvalidSlot { violation }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fss_core::{ContentDigest, ContractError};
    use fss_object::{ObjectError, SpoolError};

    use super::{
        BlockReason, CapacityResource, LOCAL_PUBLICATION_ERROR_CODES, LocalIoOperation,
        LocalLimitViolation, LocalPublicationError, ReferenceRole, SlotViolation,
    };
    use crate::local::{PublishCutPoint, SlotName};

    #[test]
    fn every_variant_code_is_listed_exactly_once() -> Result<(), SlotViolation> {
        let digest = ContentDigest::sha256(b"x");
        let slot = SlotName::parse("slot")?;
        let blocked = |reason| LocalPublicationError::ReferenceBlocked {
            object: digest,
            role: ReferenceRole::Child,
            reason,
        };
        let errors = vec![
            LocalPublicationError::InvalidLimits(LocalLimitViolation::ZeroBound),
            LocalPublicationError::InvalidSlot {
                violation: SlotViolation::Empty,
            },
            LocalPublicationError::ManifestChildBound {
                count: 2,
                maximum: 1,
            },
            LocalPublicationError::EntryLimit {
                directory: PathBuf::from("roots"),
                maximum: 1,
            },
            LocalPublicationError::RecordTooLarge {
                length: 2,
                maximum: 1,
            },
            LocalPublicationError::Capacity {
                resource: CapacityResource::Roots,
                current: 1,
                maximum: 1,
            },
            blocked(BlockReason::Missing),
            blocked(BlockReason::NotVerified),
            blocked(BlockReason::Corrupt),
            blocked(BlockReason::Tombstoned),
            blocked(BlockReason::Unavailable),
            blocked(BlockReason::Other(ObjectError::InvalidManifestKind)),
            LocalPublicationError::SlotConflict {
                slot: slot.clone(),
                existing: digest,
                requested: digest,
            },
            LocalPublicationError::BrokenSlot { slot: slot.clone() },
            LocalPublicationError::OrphanedTemp {
                path: PathBuf::from("roots/slot.root.tmp"),
            },
            LocalPublicationError::ManifestMismatch { root: digest },
            LocalPublicationError::Spool(SpoolError::Poisoned),
            LocalPublicationError::Io {
                operation: LocalIoOperation::Rename,
                path: PathBuf::from("roots"),
                kind: std::io::ErrorKind::Other,
            },
            LocalPublicationError::Locked {
                path: PathBuf::from("LOCK"),
            },
            LocalPublicationError::InvalidLayout {
                path: PathBuf::from("roots"),
            },
            LocalPublicationError::Indeterminate {
                path: PathBuf::from("roots/slot.root"),
                kind: std::io::ErrorKind::Other,
            },
            LocalPublicationError::InjectedCrash {
                point: PublishCutPoint::AfterRootRename,
            },
            LocalPublicationError::Cancelled {
                point: PublishCutPoint::AfterChildrenVerified,
            },
            LocalPublicationError::Poisoned,
            LocalPublicationError::MissingDeletionAuthority { object: digest },
            LocalPublicationError::TombstoneConflict { object: digest },
            LocalPublicationError::TombstoneBlockedByVisibleRoot {
                object: digest,
                slot,
            },
            LocalPublicationError::CorruptTombstone {
                path: PathBuf::from("tombstones/x.tomb"),
            },
            LocalPublicationError::Encoding(ContractError::InvalidIdentifier),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in &errors {
            assert!(
                LOCAL_PUBLICATION_ERROR_CODES.contains(&error.code()),
                "{} is not listed",
                error.code()
            );
            assert!(error.to_string().starts_with(error.code()));
            seen.insert(error.code());
        }
        assert_eq!(seen.len(), LOCAL_PUBLICATION_ERROR_CODES.len());
        Ok(())
    }
}
