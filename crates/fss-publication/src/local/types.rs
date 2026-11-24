#![forbid(unsafe_code)]
//! Public types, limits, receipts, recovery reports, and I/O scope boundary for local publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolIo, SpoolLimits, SpoolRecoveryReport};

use super::{
    BlockReason, LocalLimitViolation, LocalPublicationError, ReferenceRole, SlotName, WriterState,
};

/// Lock file under the publication root.
pub const LOCAL_LOCK_FILE: &str = "LOCK";
/// Staging spool directory under the publication root.
pub const LOCAL_SPOOL_DIR: &str = "spool";
/// Root record directory under the publication root.
pub const LOCAL_ROOTS_DIR: &str = "roots";
/// Tombstone record directory under the publication root.
pub const LOCAL_TOMBSTONES_DIR: &str = "tombstones";
/// Suffix of a visible root record.
pub const ROOT_RECORD_SUFFIX: &str = ".root";
/// Suffix of a durable tombstone record.
pub const TOMBSTONE_RECORD_SUFFIX: &str = ".tomb";
/// Suffix appended to a record name while it is being written.
pub const ROOT_TEMP_SUFFIX: &str = ".tmp";
/// Suffix appended to a root record name to mark the slot's root visibility indeterminate.
pub const ROOT_INDETERMINATE_SUFFIX: &str = ".indeterminate";
/// Ceiling on the configurable number of visible roots.
pub const MAX_LOCAL_ROOTS: usize = 65_536;
/// Ceiling on the configurable number of durable tombstones.
pub const MAX_LOCAL_TOMBSTONES: usize = 65_536;

pub(super) const TOP_LEVEL_SCAN_BOUND: usize = 16;

/// Resource bounds for one local publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPublicationLimits {
    /// Maximum visible roots (slots).
    pub max_roots: usize,
    /// Maximum direct children per manifest, including the metadata object.
    pub max_children: usize,
    /// Maximum durable tombstones.
    pub max_tombstones: usize,
    /// Maximum entries listed from the roots or tombstones directory on open.
    pub max_scan_entries: usize,
    /// Bounds of the owned staging spool.
    pub spool: SpoolLimits,
}

impl LocalPublicationLimits {
    /// Creates explicit bounds. They are validated by [`super::LocalRootPublisher::open`].
    #[must_use]
    pub const fn new(
        max_roots: usize,
        max_children: usize,
        max_tombstones: usize,
        max_scan_entries: usize,
        spool: SpoolLimits,
    ) -> Self {
        Self {
            max_roots,
            max_children,
            max_tombstones,
            max_scan_entries,
            spool,
        }
    }

    /// Checks that the bounds are nonzero, below their ceilings, and mutually consistent.
    pub fn validate(self) -> Result<Self, LocalPublicationError> {
        let invalid = LocalPublicationError::InvalidLimits;
        if self.max_roots == 0 || self.max_children == 0 || self.max_tombstones == 0 {
            return Err(invalid(LocalLimitViolation::ZeroBound));
        }
        if self.max_roots > MAX_LOCAL_ROOTS {
            return Err(invalid(LocalLimitViolation::RootBoundAboveMaximum {
                requested: self.max_roots,
                maximum: MAX_LOCAL_ROOTS,
            }));
        }
        if self.max_children > MAX_MANIFEST_CHILDREN {
            return Err(invalid(LocalLimitViolation::ChildBoundAboveFormatMaximum {
                requested: self.max_children,
                maximum: MAX_MANIFEST_CHILDREN,
            }));
        }
        if self.max_tombstones > MAX_LOCAL_TOMBSTONES {
            return Err(invalid(LocalLimitViolation::TombstoneBoundAboveMaximum {
                requested: self.max_tombstones,
                maximum: MAX_LOCAL_TOMBSTONES,
            }));
        }
        let required = self.max_roots.max(self.max_tombstones);
        if self.max_scan_entries < required {
            return Err(invalid(LocalLimitViolation::ScanBoundBelowEntryBound {
                max_scan_entries: self.max_scan_entries,
                required,
            }));
        }
        self.spool
            .validate()
            .map_err(LocalPublicationError::Spool)?;
        Ok(self)
    }
}

/// Crash and cancellation cut points of one publication, in protocol order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PublishCutPoint {
    /// Every reference is proven; the manifest body has not been written.
    AfterChildrenVerified,
    /// The manifest body is staged and verified; no root record exists.
    AfterManifestBody,
    /// The temporary root record is written and fsynced; it has not been renamed.
    AfterRootTempWrite,
    /// The root record was renamed into place; the directory has not been fsynced.
    AfterRootRename,
}

impl fmt::Display for PublishCutPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AfterChildrenVerified => "after_children_verified",
            Self::AfterManifestBody => "after_manifest_body",
            Self::AfterRootTempWrite => "after_root_temp_write",
            Self::AfterRootRename => "after_root_rename",
        })
    }
}

/// Filesystem operation of the root commit at which [`InjectedIoFault`] returns an error.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoFaultPoint {
    /// The rename of `<slot>.root.tmp` to `<slot>.root`. The rename is not performed, so nothing
    /// becomes visible; the publisher removes the temporary record and returns
    /// [`LocalPublicationError::Io`] with [`super::LocalIoOperation::Rename`].
    RootRename,
    /// The roots-directory fsync after the rename. The rename has been performed, so the root is
    /// `Visible` but never `Durable`; the publisher is poisoned and returns
    /// [`LocalPublicationError::Indeterminate`].
    RootDirectorySync,
}

/// A one-shot I/O error for one root-commit operation, for failure-path tests only.
///
/// It can be armed only by [`super::LocalRootPublisher::open_with_injected_io_fault`]. It fires on
/// the first publish call that reaches its [`IoFaultPoint`] and is then disarmed; publish calls
/// that fail or return earlier leave it armed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InjectedIoFault {
    /// Operation that fails.
    pub point: IoFaultPoint,
    /// Error kind the failed operation reports.
    pub kind: io::ErrorKind,
}

impl InjectedIoFault {
    /// A fault that makes the operation at `point` fail with `kind`.
    #[must_use]
    pub const fn new(point: IoFaultPoint, kind: io::ErrorKind) -> Self {
        Self { point, kind }
    }
}

/// Caller-owned cancellation probe, consulted only at cut points before the root rename.
pub trait PublishCancellation {
    /// Returns true when the publication must stop at `point`.
    fn cancel_requested(&self, point: PublishCutPoint) -> bool;
}

/// A cancellation token that never cancels publication.
pub struct NeverCancel;

impl PublishCancellation for NeverCancel {
    fn cancel_requested(&self, _point: PublishCutPoint) -> bool {
        false
    }
}

/// Local publication state of one root. Ordered: `Staged < Visible < Durable`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocalPublicationState {
    /// The manifest body is in the spool; no root record names it.
    Staged,
    /// The root record was renamed into place; its directory fsync has not been observed.
    Visible,
    /// The root record's directory fsync succeeded after the rename.
    Durable,
}

/// A publication-lattice rung this crate never proves.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClaimStatus {
    /// No evidence for this rung exists; it must not be inferred from local durability.
    NotClaimed,
    /// Evidence for this rung exists.
    Claimed,
}

/// Every rung of the staged → visible → durable → replicated → protected → retrievable lattice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicationClaims {
    /// Proven local state.
    pub local: LocalPublicationState,
    /// Remote replication; never proven here.
    pub replicated: ClaimStatus,
    /// Erasure/repair protection; never proven here.
    pub protected: ClaimStatus,
    /// Retrieval-sample proof; never proven here.
    pub retrievable: ClaimStatus,
}

impl PublicationClaims {
    /// Constructs claims with explicit status for every rung.
    #[must_use]
    pub const fn new(
        local: LocalPublicationState,
        replicated: ClaimStatus,
        protected: ClaimStatus,
        retrievable: ClaimStatus,
    ) -> Self {
        Self {
            local,
            replicated,
            protected,
            retrievable,
        }
    }

    /// Constructs claims with local durability only and all remote rungs unclaimed.
    #[must_use]
    pub const fn local_only(local: LocalPublicationState) -> Self {
        Self {
            local,
            replicated: ClaimStatus::NotClaimed,
            protected: ClaimStatus::NotClaimed,
            retrievable: ClaimStatus::NotClaimed,
        }
    }
}

/// Whether a publish call made a new root visible.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublishOutcome {
    /// A new root record was renamed into place.
    Published,
    /// The identical root was already visible; nothing was written.
    AlreadyPublished,
}

/// One observed transition of a publish call, in order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicationTransition {
    /// Every reference was proven verified and not tombstoned.
    ChildrenVerified,
    /// The manifest body was staged, verified, and decoded from the spool.
    ManifestBodyStaged,
    /// The temporary root record was written, fsynced, and read back.
    RootTempWritten,
    /// The root record was renamed into place.
    RootRenamed,
    /// The roots directory was fsynced.
    RootDirectorySynced,
    /// An already-visible identical root and its closure were re-verified.
    ExistingRootReverified,
}

/// Receipt of a successful publish call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPublicationReceipt {
    /// Slot that holds the root.
    pub slot: SlotName,
    /// Manifest root.
    pub root: ContentDigest,
    /// SHA-256 of the exact on-disk root record bytes.
    pub record_digest: ContentDigest,
    /// Direct children, including metadata.
    pub child_count: usize,
    /// Unique objects in the root's closure, including the manifest body.
    pub closure_object_count: usize,
    /// Whether this call made the root visible.
    pub outcome: PublishOutcome,
    /// Proven and unclaimed lattice rungs.
    pub claims: PublicationClaims,
    /// Observed transitions, in order.
    pub transitions: Vec<PublicationTransition>,
}

/// A root this publisher reports as visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibleRoot {
    /// Slot that holds the root.
    pub slot: SlotName,
    /// Manifest root.
    pub root: ContentDigest,
    /// SHA-256 of the exact on-disk root record bytes.
    pub record_digest: ContentDigest,
    /// Direct children, including metadata.
    pub child_count: usize,
    /// `Visible` or `Durable`; never upgraded without an observed directory fsync.
    pub state: LocalPublicationState,
}

/// Why a root record found on open was not admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokenRootReason {
    /// The record path is not a regular file.
    NotRegularFile,
    /// The record exceeds [`super::MAX_ROOT_RECORD_BYTES`].
    RecordTooLarge,
    /// The record framing, domain tag, or field encoding is invalid.
    Undecodable,
    /// The trailer checksum does not match the record body.
    ChecksumMismatch,
    /// The record declares a format version this build does not read.
    UnsupportedVersion {
        /// Declared version.
        version: u64,
    },
    /// The slot inside the record differs from the slot named by the file.
    SlotMismatch,
    /// The manifest body object does not decode to a manifest with this root.
    ManifestUndecodable,
    /// The recorded child count differs from the manifest's.
    ChildCountMismatch {
        /// Count stored in the record.
        recorded: u64,
        /// Count in the manifest body.
        actual: usize,
    },
    /// The manifest names more children than the configured bound.
    ChildBoundExceeded {
        /// Count in the manifest body.
        count: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A referenced object is missing, corrupt, or tombstoned.
    ReferenceBlocked {
        /// The blocking object.
        object: ContentDigest,
        /// Its role.
        role: ReferenceRole,
        /// Why it blocks.
        reason: BlockReason,
    },
    /// A durable marker records that a root rename of this slot was reported failed and its
    /// rollback failed, so whether a root became visible is unknown.
    VisibilityIndeterminate {
        /// Whether a root record for the slot exists on disk.
        record_present: bool,
    },
}

impl fmt::Display for BrokenRootReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegularFile => formatter.write_str("root record is not a regular file"),
            Self::RecordTooLarge => formatter.write_str("root record exceeds its size bound"),
            Self::Undecodable => formatter.write_str("root record is undecodable"),
            Self::ChecksumMismatch => formatter.write_str("root record checksum mismatch"),
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported root record version {version}")
            }
            Self::SlotMismatch => formatter.write_str("root record names a different slot"),
            Self::ManifestUndecodable => formatter.write_str("manifest body is undecodable"),
            Self::ChildCountMismatch { recorded, actual } => write!(
                formatter,
                "root record child count {recorded} differs from manifest count {actual}"
            ),
            Self::ChildBoundExceeded { count, maximum } => write!(
                formatter,
                "manifest names {count} children; maximum is {maximum}"
            ),
            Self::ReferenceBlocked {
                object,
                role,
                reason,
            } => write!(formatter, "{role:?} reference {object} is {reason}"),
            Self::VisibilityIndeterminate { record_present } => write!(
                formatter,
                "root visibility is indeterminate (record present: {record_present})"
            ),
        }
    }
}

impl std::error::Error for BrokenRootReason {}

/// Root record found on open and not admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokenRoot {
    /// Path relative to the publication root.
    pub path: PathBuf,
    /// Classification.
    pub reason: BrokenRootReason,
}

/// Deterministic classification of everything observed on open. All lists are sorted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalRecoveryReport {
    /// Classification reported by the owned staging spool.
    pub spool: SpoolRecoveryReport,
    /// Root records admitted after full closure verification and a directory fsync.
    pub roots: Vec<VisibleRoot>,
    /// Root records that failed verification and were not admitted.
    pub broken_roots: Vec<BrokenRoot>,
    /// Temporary records left by interrupted operations, relative to the publication root.
    pub orphaned_temps: Vec<PathBuf>,
    /// Spool objects not reachable from any admitted root. Not a deletion instruction.
    pub unreferenced_objects: Vec<ContentDigest>,
    /// Objects named by durable tombstones.
    pub tombstones: Vec<ContentDigest>,
    /// Entries outside the layout contract; never read, admitted, or deleted.
    pub foreign: Vec<PathBuf>,
}

impl LocalRecoveryReport {
    /// True when nothing but admitted roots, reachable objects, and tombstones was observed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.spool.is_clean()
            && self.broken_roots.is_empty()
            && self.orphaned_temps.is_empty()
            && self.unreferenced_objects.is_empty()
            && self.foreign.is_empty()
    }
}

/// Non-mutating inspection of a local publication root: what [`super::LocalRootPublisher::open`]
/// would classify, observed without locks, directory creation, fsync, or repair.
///
/// `report` is built by the same classifier the open runs. Its documented differences from the
/// open's [`LocalRecoveryReport`] are the extra fields below: roots stay
/// [`LocalPublicationState::Visible`] because inspection never fsyncs (`durability_not_resynced`),
/// root temp files the open would delete stay listed in `redundant_temps`, and a spool without
/// holds is reported as `holds_migration_pending` instead of being migrated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInspection {
    /// Classification by the open's classifier; admitted roots are `Visible`, never `Durable`.
    pub report: LocalRecoveryReport,
    /// Root temp files that open would delete because their target record already exists.
    pub redundant_temps: Vec<PathBuf>,
    /// True when roots were admitted from records observed on disk whose directory was not
    /// fsynced by this inspection; their durability basis is the observation, not an fsync.
    pub durability_not_resynced: bool,
    /// Whether the underlying spool predates holds; open would migrate it.
    pub holds_migration_pending: bool,
    /// Whether the root, `roots/`, `tombstones/`, or a spool directory is missing; open would
    /// create it empty.
    pub missing_layout: bool,
    /// Whether the spool's recovered index exceeds its bounds; open would fail with
    /// [`fss_object::SpoolError::RecoveredOverCapacity`].
    pub spool_over_capacity: bool,
    /// Concurrently observed writer state.
    pub writer_state: WriterState,
    /// Maps each admitted slot to its closure of object digests.
    pub root_closures: BTreeMap<SlotName, BTreeSet<ContentDigest>>,
    /// Broken slots that failed verification.
    pub broken_slots: BTreeSet<SlotName>,
    /// Whether the snapshot may already be stale: a writer or shared holder was observed, or the
    /// writer state could not be determined.
    pub possibly_stale: bool,
    /// Whether modifications are possibly in flight due to an active writer or pending temporary
    /// files.
    pub possibly_in_flight: bool,
}

impl LocalInspection {
    /// True only when nothing but admitted roots, reachable objects, and tombstones was observed,
    /// the layout is complete, nothing is pending, and no writer was observed by a probe that
    /// actually ran (`not_observed` or `not_held`). Any unknown, shared, held, unprobed, or
    /// lock-file-missing writer state is never clean.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.report.is_clean()
            && self.redundant_temps.is_empty()
            && !self.holds_migration_pending
            && !self.missing_layout
            && !self.spool_over_capacity
            && !self.possibly_stale
            && !self.possibly_in_flight
            && self.writer_state.is_clear()
    }

    /// Returns the visible root for a slot, if admitted.
    #[must_use]
    pub fn root(&self, slot: &SlotName) -> Option<&VisibleRoot> {
        self.report.roots.iter().find(|r| &r.slot == slot)
    }

    /// Iterates over all admitted visible roots.
    pub fn visible_roots(&self) -> impl Iterator<Item = &VisibleRoot> {
        self.report.roots.iter()
    }

    /// Returns the closure of object digests reachable from a root slot.
    #[must_use]
    pub fn root_closure(&self, slot: &SlotName) -> Option<&BTreeSet<ContentDigest>> {
        self.root_closures.get(slot)
    }

    /// Iterates over slots that failed verification.
    pub fn broken_slots(&self) -> impl Iterator<Item = &SlotName> {
        self.broken_slots.iter()
    }

    /// Returns true if a slot failed verification.
    #[must_use]
    pub fn is_broken_slot(&self, slot: &SlotName) -> bool {
        self.broken_slots.contains(slot)
    }
}

/// Result of recording a tombstone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TombstoneOutcome {
    /// A new tombstone record was made durable.
    Recorded,
    /// The identical record was already durable; nothing was written.
    AlreadyRecorded,
}

#[derive(Clone, Debug)]
pub(super) struct RootEntry {
    pub(super) visible: VisibleRoot,
    /// Direct children of the root's manifest, including metadata.
    pub(super) children: Vec<ContentDigest>,
}

/// A current, root-scoped production filesystem capability.
///
/// Unlike the test-only I/O injection constructor, a scoped open requires an explicit policy
/// boundary before and after recovery. Implementations must gate every [`SpoolIo`] operation
/// against the same immutable root, current authority, and nonrenewable resource accounts. A
/// denial or budget refusal must remain latched, including when a recovery classifier catches
/// the underlying I/O error. Releasing an already-held lock must remain possible after denial.
pub trait ScopedPublicationIo: SpoolIo {
    /// Verify the exact requested root, current authority and any previously latched refusal.
    /// This method must not grant a new root, reset allowances, or clear a prior refusal.
    fn check_scope(&self, root: &Path) -> io::Result<()>;
}
