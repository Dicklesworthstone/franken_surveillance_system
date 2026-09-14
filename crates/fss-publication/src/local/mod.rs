//! Root-last local manifest publication over the content-addressed staging spool (FSS-018).
//!
//! # Layout
//!
//! ```text
//! <root>/LOCK                          exclusive owner lock, held for the publisher's lifetime
//! <root>/spool/                        fss_object::StagingSpool (children and manifest bodies)
//! <root>/roots/<slot>.root             one visible root record per slot
//! <root>/roots/<slot>.root.tmp         in-flight root record, never visible
//! <root>/roots/<slot>.root.indeterminate  durable marker: the slot's root visibility is unknown
//! <root>/tombstones/<alg>-<hex>.tomb   one durable tombstone per object digest
//! ```
//!
//! # Publication lattice
//!
//! [`LocalPublicationState`] distinguishes `Staged` (the manifest body is in the spool but no
//! root record names it), `Visible` (the root record was renamed into place but the directory
//! fsync that makes the rename durable has not been observed), and `Durable` (the directory fsync
//! succeeded). Replication, protection, and retrievability are outside this crate's authority and
//! every receipt reports them as [`ClaimStatus::NotClaimed`]. Committing a durable root's
//! reachability to the canonical ledger is the job of [`crate::LedgeredRootPublisher`].
//!
//! # Protocol
//!
//! 1. Prove every direct child (including metadata), and every descendant reached through a child
//!    that is itself a visible root, is not tombstoned and is `Verified` in the spool: its bytes
//!    were fsynced before indexing and were re-read and rehashed from disk now.
//! 2. Stage and verify the canonical manifest body in the spool, then re-read and decode it.
//! 3. Write the root record to `<slot>.root.tmp`, fsync it, and read it back.
//! 4. Re-prove every reference immediately before the commit point.
//! 5. Rename the record to `<slot>.root` (the commit point; the root is now `Visible`).
//! 6. Fsync the roots directory (the root is now `Durable`).
//!
//! A rename reported failed may still have taken effect. The publisher then removes
//! `<slot>.root` (the slot had no record before the rename) and fsyncs the roots directory;
//! `NotFound` proves the rename did not take effect. If that rollback fails, the root may be
//! visible or may reappear after a crash: the publisher durably records
//! `<slot>.root.indeterminate`, poisons itself, and returns
//! [`LocalPublicationError::RootVisibilityIndeterminate`] with the rename, rollback, and marker
//! outcomes. Such a slot is never reported as a plain rename failure.
//!
//! A crash or cancellation at any cut point before step 5 leaves nothing visible. Cancellation is
//! never consulted after the rename. Manifest descent is bottom-up as in
//! [`fss_object::InMemoryObjectStore`]: a child that is itself the root of a visible slot is
//! descended into, transitively, for verification, closure counts, and tombstone reachability;
//! any other child is an opaque leaf whose bytes are never trial-parsed as a manifest.
//!
//! # Reopen
//!
//! [`LocalRootPublisher::open`] re-verifies every root record, its manifest body, and every child
//! before admitting it, fsyncs the roots directory, and only then reports roots as `Durable`.
//! Records that fail are reported as [`BrokenRoot`] and never admitted. A slot with an
//! indeterminate marker is reported as [`BrokenRootReason::VisibilityIndeterminate`], and its
//! record, if any, is never admitted. Objects not reachable from
//! any admitted root are reported as `unreferenced_objects`; temporary records are reported as
//! `orphaned_temps`. Nothing found on open is deleted implicitly.
//!
//! Filesystem access is scoped by the root path passed to `open`, matching `fss-object`'s spool
//! and `fss-ledger`'s journal. No `Cx` capability is threaded yet. Every filesystem call the
//! publisher makes, and every call its owned spool makes, goes through one
//! [`fss_object::SpoolIo`] capability; [`LocalRootPublisher::open`] uses
//! [`fss_object::HostSpoolIo`], which performs exactly the host `std::fs` call.
//!
//! # Fault injection
//!
//! Three test seams exist, and none is reachable through [`LocalRootPublisher::open`].
//! [`LocalRootPublisher::inject_crash_at`] arms a crash at a [`PublishCutPoint`]: the call returns
//! [`LocalPublicationError::InjectedCrash`] and the instance behaves as a dead process.
//! [`LocalRootPublisher::open_with_injected_io_fault`] is the only way to arm an
//! [`InjectedIoFault`]: the root rename or the roots-directory fsync after it returns the
//! configured [`io::ErrorKind`] instead of touching the filesystem, and the publisher then takes
//! exactly the error path a real failure of that operation takes. The fault is one-shot, and no
//! method arms one on an already open instance. [`LocalRootPublisher::open_with_io`] replaces
//! the host capability for the publisher and its spool together, so a test can count, fail, or
//! interrupt every filesystem call of open, staging, publication, and recovery in one order.

mod error;
mod record;
mod writer;

pub use writer::*;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{CanonicalEncode, ContentDigest, TombstoneRecord};
use fss_object::{
    HostSpoolIo, MAX_INTERRUPTED_ATTEMPTS, MAX_MANIFEST_CHILDREN, ObjectManifest, SpoolError,
    SpoolInspection, SpoolIo, SpoolLimits, SpoolObjectState, SpoolRecoveryReport, StagingSpool,
    VerifiedObjectCatalog,
};

pub use error::{
    BlockReason, CapacityResource, LOCAL_PUBLICATION_ERROR_CODES, LocalIoOperation,
    LocalLimitViolation, LocalPublicationError, LocalPublicationGuidance, ReferenceRole,
    SlotViolation,
};
pub use record::{
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_TOMBSTONE_RECORD_DOMAIN,
    MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, MAX_TOMBSTONE_RECORD_BYTES, SlotName,
    root_record_bytes, tombstone_record_bytes,
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

const TOP_LEVEL_SCAN_BOUND: usize = 16;

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
    /// Creates explicit bounds. They are validated by [`LocalRootPublisher::open`].
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
    /// [`LocalPublicationError::Io`] with [`LocalIoOperation::Rename`].
    RootRename,
    /// The roots-directory fsync after the rename. The rename has been performed, so the root is
    /// `Visible` but never `Durable`; the publisher is poisoned and returns
    /// [`LocalPublicationError::Indeterminate`].
    RootDirectorySync,
}

/// A one-shot I/O error for one root-commit operation, for failure-path tests only.
///
/// It can be armed only by [`LocalRootPublisher::open_with_injected_io_fault`]. It fires on the
/// first publish call that reaches its [`IoFaultPoint`] and is then disarmed; publish calls that
/// fail or return earlier leave it armed.
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
    /// The record exceeds [`MAX_ROOT_RECORD_BYTES`].
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

/// Non-mutating inspection of a local publication root: what [`LocalRootPublisher::open`] would
/// classify, observed without locks, directory creation, fsync, or repair.
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
struct RootEntry {
    visible: VisibleRoot,
    /// Direct children of the root's manifest, including metadata.
    children: Vec<ContentDigest>,
}

/// Exclusive owner of one root-last local publication directory.
#[derive(Debug)]
pub struct LocalRootPublisher {
    io: Arc<dyn SpoolIo>,
    root: PathBuf,
    roots_dir: PathBuf,
    tombstones_dir: PathBuf,
    _lock: File,
    limits: LocalPublicationLimits,
    spool: StagingSpool,
    visible: BTreeMap<SlotName, RootEntry>,
    staged: BTreeMap<SlotName, RootEntry>,
    broken_slots: BTreeSet<SlotName>,
    orphan_temps: BTreeSet<PathBuf>,
    tombstones: BTreeMap<ContentDigest, TombstoneRecord>,
    recovery: LocalRecoveryReport,
    injected_crash: Option<PublishCutPoint>,
    injected_io_fault: Option<InjectedIoFault>,
    poisoned: bool,
}

impl LocalRootPublisher {
    /// Opens the publication directory at `root`, recovering any visible roots and tombstones.
    ///
    /// Acquires an exclusive advisory lock on `<root>/LOCK`. Every root record is
    /// re-verified with its manifest body and children before admission; broken ones are reported
    /// and never admitted. Admitted roots are reported `Durable` only after this call fsyncs the
    /// roots directory.
    pub fn open(
        root: impl AsRef<Path>,
        limits: LocalPublicationLimits,
    ) -> Result<Self, LocalPublicationError> {
        Self::open_through(root.as_ref(), limits, Arc::new(HostSpoolIo))
    }

    /// Test-only constructor: [`Self::open`] with every filesystem call routed through `io`.
    ///
    /// The same capability is handed to the owned [`StagingSpool`], so one `io` value observes
    /// every call of open, recovery, staging, publication, tombstoning, and cleanup, in the order
    /// they are made. [`Self::open`] passes [`HostSpoolIo`], which performs exactly the host
    /// `std::fs` call. Use it to count, fail, or interrupt filesystem calls in failure-path tests,
    /// never in production configuration.
    pub fn open_with_io(
        root: impl AsRef<Path>,
        limits: LocalPublicationLimits,
        io: Arc<dyn SpoolIo>,
    ) -> Result<Self, LocalPublicationError> {
        Self::open_through(root.as_ref(), limits, io)
    }

    fn open_through(
        root: &Path,
        limits: LocalPublicationLimits,
        io: Arc<dyn SpoolIo>,
    ) -> Result<Self, LocalPublicationError> {
        let limits = limits.validate()?;
        let root = root.to_path_buf();
        io.create_dir_all(&root)
            .map_err(|error| io_error(LocalIoOperation::CreateDirectory, &root, &error))?;
        let metadata = io
            .symlink_metadata(&root)
            .map_err(|error| io_error(LocalIoOperation::Inspect, &root, &error))?;
        if !metadata.file_type().is_dir() {
            return Err(LocalPublicationError::InvalidLayout { path: root });
        }
        let lock = acquire_lock(io.as_ref(), &root)?;
        let roots_dir = root.join(LOCAL_ROOTS_DIR);
        let tombstones_dir = root.join(LOCAL_TOMBSTONES_DIR);
        ensure_subdirectory(io.as_ref(), &roots_dir)?;
        ensure_subdirectory(io.as_ref(), &tombstones_dir)?;
        let spool =
            StagingSpool::open_with_io(root.join(LOCAL_SPOOL_DIR), limits.spool, Arc::clone(&io))
                .map_err(LocalPublicationError::Spool)?;
        io.sync_directory(&root)
            .map_err(|error| io_error(LocalIoOperation::SyncDirectory, &root, &error))?;

        let mut publisher = Self {
            io,
            root,
            roots_dir,
            tombstones_dir,
            _lock: lock,
            limits,
            spool,
            visible: BTreeMap::new(),
            staged: BTreeMap::new(),
            broken_slots: BTreeSet::new(),
            orphan_temps: BTreeSet::new(),
            tombstones: BTreeMap::new(),
            recovery: LocalRecoveryReport::default(),
            injected_crash: None,
            injected_io_fault: None,
            poisoned: false,
        };
        publisher.recover()?;
        Ok(publisher)
    }

    /// Test-only constructor: [`Self::open`], then arms one [`InjectedIoFault`].
    ///
    /// This is the only way to arm an I/O fault; [`Self::open`] never does, and no method arms
    /// one later. The fault makes the root rename or the roots-directory fsync of the first
    /// publish call that reaches it fail with the configured error kind, without performing that
    /// operation, and the publisher then follows the same error path as a real failure. Use it to
    /// test failure paths, never in production configuration.
    pub fn open_with_injected_io_fault(
        root: impl AsRef<Path>,
        limits: LocalPublicationLimits,
        fault: InjectedIoFault,
    ) -> Result<Self, LocalPublicationError> {
        let mut publisher = Self::open(root, limits)?;
        publisher.injected_io_fault = Some(fault);
        Ok(publisher)
    }

    /// Publication root directory.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root
    }

    /// Configured bounds.
    #[must_use]
    pub const fn limits(&self) -> LocalPublicationLimits {
        self.limits
    }

    /// Read access to the owned staging spool.
    #[must_use]
    pub const fn spool(&self) -> &StagingSpool {
        &self.spool
    }

    /// Classification of everything observed when this instance opened.
    #[must_use]
    pub const fn recovery_report(&self) -> &LocalRecoveryReport {
        &self.recovery
    }

    /// True after a crash or indeterminate outcome; every mutating call then fails.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// True when `slot` holds a root record that failed verification on open, or its root
    /// visibility is indeterminate; publication into it is refused.
    #[must_use]
    pub fn is_broken_slot(&self, slot: &SlotName) -> bool {
        self.broken_slots.contains(slot)
    }

    /// Every slot [`Self::is_broken_slot`] reports, in slot order.
    pub fn broken_slots(&self) -> impl Iterator<Item = &SlotName> {
        self.broken_slots.iter()
    }

    /// The root this instance reports visible in `slot`, if any.
    ///
    /// Remains readable on a poisoned instance so a crash after the rename is reported as
    /// `Visible` rather than hidden or upgraded. If a manifest has been staged for `slot`
    /// but not yet renamed, reports [`LocalPublicationState::Staged`].
    #[must_use]
    pub fn root(&self, slot: &SlotName) -> Option<&VisibleRoot> {
        self.visible
            .get(slot)
            .or_else(|| self.staged.get(slot))
            .map(|entry| &entry.visible)
    }

    /// Every visible root, in slot order.
    pub fn visible_roots(&self) -> impl Iterator<Item = &VisibleRoot> {
        self.visible.values().map(|entry| &entry.visible)
    }

    /// Every object digest with a durable tombstone recorded in this instance, in digest order.
    pub fn tombstones(&self) -> impl Iterator<Item = &ContentDigest> {
        self.tombstones.keys()
    }

    /// Every object reachable from the root visible in `slot`, including the manifest body.
    ///
    /// Descent follows the publication rule: a reached object that is itself the root of a visible
    /// slot is descended into; any other object is an opaque leaf.
    #[must_use]
    pub fn root_closure(&self, slot: &SlotName) -> Option<BTreeSet<ContentDigest>> {
        self.visible
            .get(slot)
            .map(|entry| self.closure(entry.visible.root, &entry.children))
    }

    /// Stages `manifest` body for `slot` without publishing it to disk as a root record.
    ///
    /// The manifest is verified and decodes from the spool, and every reference is verified.
    /// The slot's root state becomes observable as [`LocalPublicationState::Staged`].
    pub fn stage_manifest(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<ContentDigest, LocalPublicationError> {
        self.require_live()?;
        let root = manifest.root();
        if manifest.computed_root() != root {
            return Err(LocalPublicationError::ManifestMismatch { root });
        }
        if let Some(entry) = self.visible.get(slot) {
            return Err(LocalPublicationError::SlotConflict {
                slot: slot.clone(),
                existing: entry.visible.root,
                requested: root,
            });
        }
        let child_count = manifest.children().len();
        if child_count > self.limits.max_children {
            return Err(LocalPublicationError::ManifestChildBound {
                count: child_count,
                maximum: self.limits.max_children,
            });
        }
        self.require_references(manifest)?;
        self.stage_manifest_body(manifest)?;
        self.staged.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot: slot.clone(),
                    root,
                    record_digest: ContentDigest::sha256(b""),
                    child_count,
                    state: LocalPublicationState::Staged,
                },
                children: manifest.children().to_vec(),
            },
        );
        Ok(root)
    }

    /// Stages `bytes` in the spool and verifies them, returning their content digest.
    ///
    /// Staging is custody, not publication: a tombstoned digest may still be staged, but it can
    /// never be published.
    pub fn stage_object(&mut self, bytes: &[u8]) -> Result<ContentDigest, LocalPublicationError> {
        self.require_live()?;
        let receipt = self
            .spool
            .stage_bytes(bytes)
            .map_err(|error| self.spool_error(error))?;
        self.spool
            .verify(receipt.digest)
            .map_err(|error| self.spool_error(error))?;
        Ok(receipt.digest)
    }

    /// Re-reads and rehashes one spool object and marks it `Verified`.
    pub fn verify_object(&mut self, digest: ContentDigest) -> Result<(), LocalPublicationError> {
        self.require_live()?;
        self.spool
            .verify(digest)
            .map_err(|error| self.spool_error(error))?;
        Ok(())
    }

    /// Publishes `manifest` into `slot` root-last. See [`Self::publish_cancellable`].
    pub fn publish(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        self.publish_cancellable(slot, manifest, &NeverCancel)
    }

    /// Publishes `manifest` into `slot` root-last, consulting `cancel` before the rename.
    ///
    /// Republishing the identical root is idempotent and writes nothing. A different root for a
    /// visible slot is [`LocalPublicationError::SlotConflict`]. A missing, unverified, corrupt, or
    /// tombstoned reference fails with [`LocalPublicationError::ReferenceBlocked`] naming it, and
    /// nothing becomes visible.
    pub fn publish_cancellable(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        cancel: &dyn PublishCancellation,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        self.require_live()?;
        let root = manifest.root();
        if manifest.computed_root() != root {
            return Err(LocalPublicationError::ManifestMismatch { root });
        }
        if let Some(entry) = self.visible.get(slot) {
            if entry.visible.root != root {
                return Err(LocalPublicationError::SlotConflict {
                    slot: slot.clone(),
                    existing: entry.visible.root,
                    requested: root,
                });
            }
            return self.reverify_existing(slot, manifest);
        }
        if self.broken_slots.contains(slot) {
            return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() });
        }
        let child_count = manifest.children().len();
        if child_count > self.limits.max_children {
            return Err(LocalPublicationError::ManifestChildBound {
                count: child_count,
                maximum: self.limits.max_children,
            });
        }
        if self.visible.len() >= self.limits.max_roots {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Roots,
                current: self.visible.len(),
                maximum: self.limits.max_roots,
            });
        }
        let root_name = format!("{slot}{ROOT_RECORD_SUFFIX}");
        let temp_relative =
            Path::new(LOCAL_ROOTS_DIR).join(format!("{root_name}{ROOT_TEMP_SUFFIX}"));
        if self.orphan_temps.contains(&temp_relative) {
            return Err(LocalPublicationError::OrphanedTemp {
                path: temp_relative,
            });
        }
        let mut transitions = Vec::with_capacity(5);

        // 1. Every reference is verified, durable, and not tombstoned.
        self.require_references(manifest)?;
        transitions.push(PublicationTransition::ChildrenVerified);
        self.cut(PublishCutPoint::AfterChildrenVerified, cancel, None)?;

        // 2. The canonical manifest body is staged, verified, and decodes to this manifest.
        self.stage_manifest_body(manifest)?;
        transitions.push(PublicationTransition::ManifestBodyStaged);
        self.cut(PublishCutPoint::AfterManifestBody, cancel, None)?;

        // 3. The root record is written to a temporary name, fsynced, and read back.
        let record = root_record_bytes(slot, root, child_count)?;
        let temp_path = self.root.join(&temp_relative);
        let target_path = self.roots_dir.join(&root_name);
        self.write_temp(&temp_relative, &temp_path, &record)?;
        transitions.push(PublicationTransition::RootTempWritten);
        self.cut(
            PublishCutPoint::AfterRootTempWrite,
            cancel,
            Some((&temp_relative, &temp_path)),
        )?;

        // 4. Re-prove custody immediately before the commit point.
        if let Err(error) = self.require_references(manifest).and_then(|()| {
            self.spool.require_verified(root).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: root,
                    role: ReferenceRole::ManifestBody,
                    reason: error.into(),
                }
            })
        }) {
            let cleanup = self.remove_temp(&temp_relative, &temp_path);
            return Err(Self::fail_with_cleanup(error, cleanup));
        }
        match self.io.symlink_metadata(&target_path) {
            Ok(_) => {
                let original = LocalPublicationError::InvalidLayout { path: target_path };
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                let original = io_error(LocalIoOperation::Inspect, &target_path, &error);
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
        }

        // 5. Commit point: the hard link makes the root visible atomically without clobbering.
        // If a file was created at target_path between inspection and commit (TOCTOU race),
        // hard_link fails with io::ErrorKind::AlreadyExists and never clobbers target_path.
        let linked = match self.take_io_fault(IoFaultPoint::RootRename) {
            Some(kind) => Err(io::Error::from(kind)),
            None => self.io.hard_link(&temp_path, &target_path),
        };
        if let Err(error) = linked {
            if error.kind() == io::ErrorKind::AlreadyExists {
                let original = LocalPublicationError::InvalidLayout { path: target_path };
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            return Err(self.roll_back_failed_rename(
                slot,
                (&temp_relative, &temp_path),
                &target_path,
                &record,
                error.kind(),
            ));
        }

        // The target is now atomically visible. Remove the temporary link.
        match self.io.remove_file(&temp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                self.orphan_temps.insert(temp_relative.to_path_buf());
            }
        }
        self.staged.remove(slot);
        transitions.push(PublicationTransition::RootRenamed);
        let closure_object_count = self.closure(root, manifest.children()).len();
        let record_digest = ContentDigest::sha256(&record);
        self.visible.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot: slot.clone(),
                    root,
                    record_digest,
                    child_count,
                    state: LocalPublicationState::Visible,
                },
                children: manifest.children().to_vec(),
            },
        );
        self.cut(PublishCutPoint::AfterRootRename, cancel, None)?;

        // 6. The directory fsync makes the rename durable.
        let synced = match self.take_io_fault(IoFaultPoint::RootDirectorySync) {
            Some(kind) => Err(io::Error::from(kind)),
            None => self.io.sync_directory(&self.roots_dir),
        };
        if let Err(error) = synced {
            self.poisoned = true;
            return Err(LocalPublicationError::Indeterminate {
                path: target_path,
                kind: error.kind(),
            });
        }
        if let Some(entry) = self.visible.get_mut(slot) {
            entry.visible.state = LocalPublicationState::Durable;
        }
        transitions.push(PublicationTransition::RootDirectorySynced);
        Ok(LocalPublicationReceipt {
            slot: slot.clone(),
            root,
            record_digest,
            child_count,
            closure_object_count,
            outcome: PublishOutcome::Published,
            claims: PublicationClaims::local_only(LocalPublicationState::Durable),
            transitions,
        })
    }

    /// Makes a tombstone for `record.payload_digest` durable; it blocks every later publication
    /// that references the object.
    ///
    /// Requires a deletion authority witness verified in the spool. Tombstoning an object
    /// reachable from a visible root is refused: removing a visible closure is the deletion-closure
    /// owner's effect, not a silent local unpublish. Spool bytes are retained; releasing them is
    /// not claimed.
    pub fn record_tombstone(
        &mut self,
        record: TombstoneRecord,
    ) -> Result<TombstoneOutcome, LocalPublicationError> {
        self.require_live()?;
        let object = record.payload_digest;
        if let Some(existing) = self.tombstones.get(&object) {
            if existing == &record {
                return Ok(TombstoneOutcome::AlreadyRecorded);
            }
            return Err(LocalPublicationError::TombstoneConflict { object });
        }
        let witness = record
            .witness_digest
            .ok_or(LocalPublicationError::MissingDeletionAuthority { object })?;
        self.spool.require_verified(witness).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: witness,
                role: ReferenceRole::DeletionWitness,
                reason: error.into(),
            }
        })?;
        if let Some(entry) = self.visible.values().find(|entry| {
            self.closure(entry.visible.root, &entry.children)
                .contains(&object)
        }) {
            return Err(LocalPublicationError::TombstoneBlockedByVisibleRoot {
                object,
                slot: entry.visible.slot.clone(),
            });
        }
        if self.tombstones.len() >= self.limits.max_tombstones {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Tombstones,
                current: self.tombstones.len(),
                maximum: self.limits.max_tombstones,
            });
        }
        let bytes = record::tombstone_record_bytes(&record)?;
        let name = format!("{}{TOMBSTONE_RECORD_SUFFIX}", digest_file_stem(object));
        let temp_relative =
            Path::new(LOCAL_TOMBSTONES_DIR).join(format!("{name}{ROOT_TEMP_SUFFIX}"));
        if self.orphan_temps.contains(&temp_relative) {
            return Err(LocalPublicationError::OrphanedTemp {
                path: temp_relative,
            });
        }
        let temp_path = self.root.join(&temp_relative);
        let target_path = self.tombstones_dir.join(&name);
        self.write_temp(&temp_relative, &temp_path, &bytes)?;
        match self.io.symlink_metadata(&target_path) {
            Ok(_) => {
                let original = LocalPublicationError::InvalidLayout { path: target_path };
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                let original = io_error(LocalIoOperation::Inspect, &target_path, &error);
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
        }
        if let Err(error) = self.io.rename(&temp_path, &target_path) {
            return Err(self.roll_back_failed_tombstone_rename(
                &object,
                (&temp_relative, &temp_path),
                &target_path,
                &bytes,
                error.kind(),
            ));
        }
        if let Err(error) = self.io.sync_directory(&self.tombstones_dir) {
            self.poisoned = true;
            let rollback = match self.io.remove_file(&target_path) {
                Ok(()) => self.io.sync_directory(&self.tombstones_dir).is_ok(),
                Err(_) => false,
            };
            if !rollback {
                let marker_kind = self
                    .record_indeterminate_tombstone_marker(&object, &bytes)
                    .err();
                if marker_kind.is_some()
                    && let Ok(mut file) = self.io.open_lock(&target_path)
                {
                    let _ = write_all(
                        self.io.as_ref(),
                        &mut file,
                        b"corrupted_indeterminate_tombstone",
                    );
                    let _ = self.io.sync_file(&file);
                }
            }
            return Err(LocalPublicationError::Indeterminate {
                path: target_path,
                kind: error.kind(),
            });
        }
        self.tombstones.insert(object, record);
        Ok(TombstoneOutcome::Recorded)
    }

    /// Removes exactly the orphaned temporary records classified on open or left by a failed
    /// cleanup. Returns how many were removed. Nothing else is touched.
    pub fn discard_orphaned_temps(&mut self) -> Result<usize, LocalPublicationError> {
        self.require_live()?;
        let mut removed = 0;
        for relative in self.orphan_temps.clone() {
            let path = self.root.join(&relative);
            match self.io.symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    self.io
                        .remove_file(&path)
                        .map_err(|error| io_error(LocalIoOperation::RemoveTemp, &path, &error))?;
                    removed += 1;
                }
                Ok(_) => return Err(LocalPublicationError::InvalidLayout { path }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
            }
            self.orphan_temps.remove(&relative);
        }
        for directory in [&self.roots_dir, &self.tombstones_dir] {
            self.io
                .sync_directory(directory)
                .map_err(|error| io_error(LocalIoOperation::SyncDirectory, directory, &error))?;
        }
        Ok(removed)
    }

    /// Arms a one-shot crash point for the next publish call.
    ///
    /// When it fires, the call returns [`LocalPublicationError::InjectedCrash`], leaves the disk
    /// exactly as a process death at that point would, and poisons this instance.
    #[doc(hidden)]
    pub fn inject_crash_at(&mut self, point: PublishCutPoint) {
        self.injected_crash = Some(point);
    }

    fn require_live(&self) -> Result<(), LocalPublicationError> {
        if self.poisoned {
            return Err(LocalPublicationError::Poisoned);
        }
        Ok(())
    }

    /// Marks this instance as a dead process, exactly as an injected crash does.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Proves the root in `slot` is `Durable` and its on-disk record still has the digest this
    /// instance observed. Any divergence is [`LocalPublicationError::BrokenSlot`].
    pub(crate) fn require_durable_record(
        &self,
        slot: &SlotName,
    ) -> Result<(), LocalPublicationError> {
        self.require_live()?;
        let record_digest = match self.visible.get(slot) {
            Some(entry) if entry.visible.state == LocalPublicationState::Durable => {
                entry.visible.record_digest
            }
            _ => return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        };
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        match read_bounded(self.io.as_ref(), &path, MAX_ROOT_RECORD_BYTES)? {
            Some(bytes) if ContentDigest::sha256(&bytes) == record_digest => Ok(()),
            _ => Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        }
    }

    /// Disarms and returns the injected error kind if the armed fault is at `point`.
    fn take_io_fault(&mut self, point: IoFaultPoint) -> Option<io::ErrorKind> {
        match self.injected_io_fault {
            Some(fault) if fault.point == point => {
                self.injected_io_fault = None;
                Some(fault.kind)
            }
            _ => None,
        }
    }

    /// Every object reachable from `root`: the root, its direct `children`, and, transitively, the
    /// children of any reached object that is itself the root of a visible durable slot. Any other
    /// object is an opaque leaf, exactly as in `fss_object::InMemoryObjectStore::verify_closure`.
    #[must_use]
    pub fn closure(
        &self,
        root: ContentDigest,
        children: &[ContentDigest],
    ) -> BTreeSet<ContentDigest> {
        let manifests: BTreeMap<ContentDigest, &[ContentDigest]> = self
            .visible
            .values()
            .filter(|entry| entry.visible.state == LocalPublicationState::Durable)
            .map(|entry| (entry.visible.root, entry.children.as_slice()))
            .collect();
        compute_closure(&manifests, root, children)
    }

    fn spool_error(&mut self, error: SpoolError) -> LocalPublicationError {
        if matches!(
            error,
            SpoolError::InjectedCrash { .. }
                | SpoolError::StageIndeterminate { .. }
                | SpoolError::Poisoned
        ) {
            self.poisoned = true;
        }
        LocalPublicationError::Spool(error)
    }

    fn cut(
        &mut self,
        point: PublishCutPoint,
        cancel: &dyn PublishCancellation,
        temp: Option<(&Path, &Path)>,
    ) -> Result<(), LocalPublicationError> {
        if self.injected_crash == Some(point) {
            self.injected_crash = None;
            self.poisoned = true;
            return Err(LocalPublicationError::InjectedCrash { point });
        }
        if point != PublishCutPoint::AfterRootRename && cancel.cancel_requested(point) {
            let original = LocalPublicationError::Cancelled { point };
            if let Some((relative, path)) = temp {
                let cleanup = self.remove_temp(relative, path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            return Err(original);
        }
        Ok(())
    }

    fn require_references(&self, manifest: &ObjectManifest) -> Result<(), LocalPublicationError> {
        let root = manifest.root();
        if self.tombstones.contains_key(&root) {
            return Err(LocalPublicationError::ReferenceBlocked {
                object: root,
                role: ReferenceRole::ManifestBody,
                reason: BlockReason::Tombstoned,
            });
        }
        for child in manifest.children() {
            let role = if manifest.metadata_digest() == Some(*child) {
                ReferenceRole::Metadata
            } else {
                ReferenceRole::Child
            };
            if self.tombstones.contains_key(child) {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: BlockReason::Tombstoned,
                });
            }
            if let Some(entry) = self.visible.values().find(|e| e.visible.root == *child)
                && entry.visible.state != LocalPublicationState::Durable
            {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: BlockReason::NotVerified,
                });
            }
            self.spool.require_verified(*child).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: error.into(),
                }
            })?;
        }
        let direct: BTreeSet<ContentDigest> = manifest.children().iter().copied().collect();
        for descendant in self.closure(root, manifest.children()) {
            if descendant == root || direct.contains(&descendant) {
                continue;
            }
            if self.tombstones.contains_key(&descendant) {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: BlockReason::Tombstoned,
                });
            }
            if let Some(entry) = self.visible.values().find(|e| e.visible.root == descendant)
                && entry.visible.state != LocalPublicationState::Durable
            {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: BlockReason::NotVerified,
                });
            }
            self.spool.require_verified(descendant).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: error.into(),
                }
            })?;
        }
        Ok(())
    }

    fn stage_manifest_body(
        &mut self,
        manifest: &ObjectManifest,
    ) -> Result<(), LocalPublicationError> {
        let root = manifest.root();
        let body = manifest
            .try_canonical_bytes()
            .map_err(LocalPublicationError::Encoding)?;
        self.spool
            .stage(root, &body)
            .map_err(|error| self.manifest_body_error(root, error))?;
        self.spool
            .verify(root)
            .map_err(|error| self.manifest_body_error(root, error))?;
        let read_back = self
            .spool
            .read(root)
            .map_err(|error| self.manifest_body_error(root, error))?;
        match ObjectManifest::from_canonical_bytes(&read_back) {
            Ok(decoded) if &decoded == manifest => Ok(()),
            _ => Err(LocalPublicationError::ManifestMismatch { root }),
        }
    }

    /// Classifies a spool failure on the manifest body: corrupt stored bytes under the root are a
    /// blocked [`ReferenceRole::ManifestBody`] reference, as on the idempotent republish path.
    fn manifest_body_error(
        &mut self,
        root: ContentDigest,
        error: SpoolError,
    ) -> LocalPublicationError {
        match error {
            SpoolError::Corrupt { digest, .. } if digest == root => {
                LocalPublicationError::ReferenceBlocked {
                    object: root,
                    role: ReferenceRole::ManifestBody,
                    reason: BlockReason::Corrupt,
                }
            }
            other => self.spool_error(other),
        }
    }

    fn fail_with_cleanup(
        original: LocalPublicationError,
        cleanup: Result<(), LocalPublicationError>,
    ) -> LocalPublicationError {
        match cleanup {
            Ok(()) => original,
            Err(cleanup) => LocalPublicationError::cleanup_failed(original, cleanup),
        }
    }

    /// Rolls back a root rename that was reported failed and returns the error to report.
    ///
    /// The rename may have taken effect anyway, so the record at `target` is removed (the slot
    /// had no record before the rename) and the removal is fsynced; `NotFound` proves the rename
    /// did not take effect. When the rollback completes, nothing is visible and the rename error
    /// is returned. When the removal or its fsync fails, the root may be visible or may reappear
    /// after a crash: the slot is marked indeterminate on disk and in this instance, the instance
    /// is poisoned, and [`LocalPublicationError::RootVisibilityIndeterminate`] carries every
    /// observed outcome. A temporary record left in that case is classified on reopen.
    fn roll_back_failed_rename(
        &mut self,
        slot: &SlotName,
        (temp_relative, temp_path): (&Path, &Path),
        target: &Path,
        record: &[u8],
        rename_kind: io::ErrorKind,
    ) -> LocalPublicationError {
        let rollback = match self.io.remove_file(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => Some((LocalIoOperation::RemoveRecord, error.kind())),
            Ok(()) => match self.io.sync_directory(&self.roots_dir) {
                Ok(()) => None,
                Err(error) => Some((LocalIoOperation::SyncDirectory, error.kind())),
            },
        };
        let Some((rollback_operation, rollback_kind)) = rollback else {
            let original = LocalPublicationError::Io {
                operation: LocalIoOperation::Rename,
                path: target.to_path_buf(),
                kind: rename_kind,
            };
            return Self::fail_with_cleanup(original, self.remove_temp(temp_relative, temp_path));
        };
        self.poisoned = true;
        self.staged.remove(slot);
        self.broken_slots.insert(slot.clone());
        // The marker's success value is `()`, so its failure kind is all there is to keep.
        let marker_kind = self.record_indeterminate_marker(slot, record).err();
        LocalPublicationError::RootVisibilityIndeterminate {
            slot: slot.clone(),
            path: target.to_path_buf(),
            rename_kind,
            rollback_operation,
            rollback_kind,
            marker_kind,
        }
    }

    /// Rolls back a tombstone rename that was reported failed and returns the error to report.
    ///
    /// The rename may have taken effect anyway, so the record at `target` is removed and the
    /// removal is fsynced; `NotFound` proves the rename did not take effect. When the rollback
    /// completes, nothing is visible and the rename error is returned. When the removal or its
    /// fsync fails, the tombstone may be visible or may reappear after a crash: the tombstone is
    /// marked indeterminate on disk, the instance is poisoned, and
    /// [`LocalPublicationError::TombstoneVisibilityIndeterminate`] carries every observed outcome.
    fn roll_back_failed_tombstone_rename(
        &mut self,
        object: &ContentDigest,
        (temp_relative, temp_path): (&Path, &Path),
        target: &Path,
        record: &[u8],
        rename_kind: io::ErrorKind,
    ) -> LocalPublicationError {
        let rollback = match self.io.remove_file(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => Some((LocalIoOperation::RemoveRecord, error.kind())),
            Ok(()) => match self.io.sync_directory(&self.tombstones_dir) {
                Ok(()) => None,
                Err(error) => Some((LocalIoOperation::SyncDirectory, error.kind())),
            },
        };
        let Some((rollback_operation, rollback_kind)) = rollback else {
            let original = LocalPublicationError::Io {
                operation: LocalIoOperation::Rename,
                path: target.to_path_buf(),
                kind: rename_kind,
            };
            return Self::fail_with_cleanup(original, self.remove_temp(temp_relative, temp_path));
        };
        self.poisoned = true;
        self.tombstones.remove(object);
        let marker_kind = self
            .record_indeterminate_tombstone_marker(object, record)
            .err();
        if marker_kind.is_some()
            && let Ok(mut file) = self.io.open_lock(target)
        {
            let _ = write_all(
                self.io.as_ref(),
                &mut file,
                b"corrupted_indeterminate_tombstone",
            );
            let _ = self.io.sync_file(&file);
        }
        LocalPublicationError::TombstoneVisibilityIndeterminate {
            object: *object,
            path: target.to_path_buf(),
            rename_kind,
            rollback_operation,
            rollback_kind,
            marker_kind,
        }
    }

    /// Durably records `<slot>.root.indeterminate`, holding the attempted root `record`.
    ///
    /// A marker that already exists records the same fact and is kept. A marker left partially
    /// written by a failure here still marks the slot on reopen, which classifies it by
    /// existence alone.
    fn record_indeterminate_marker(
        &self,
        slot: &SlotName,
        record: &[u8],
    ) -> Result<(), io::ErrorKind> {
        let path = self.roots_dir.join(format!(
            "{slot}{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
        ));
        match self.io.create_new(&path) {
            Ok(mut file) => {
                let written = write_all(self.io.as_ref(), &mut file, record)
                    .and_then(|()| self.io.sync_file(&file));
                drop(file);
                written.map_err(|error| error.kind())?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.kind()),
        }
        self.io
            .sync_directory(&self.roots_dir)
            .map_err(|error| error.kind())
    }

    /// Durably records `<stem>.tomb.indeterminate`, holding the attempted tombstone `record`.
    ///
    /// A marker that already exists records the same fact and is kept. A marker left partially
    /// written by a failure here still marks the tombstone on reopen, which classifies it by
    /// existence alone.
    fn record_indeterminate_tombstone_marker(
        &self,
        object: &ContentDigest,
        record: &[u8],
    ) -> Result<(), io::ErrorKind> {
        let stem = digest_file_stem(*object);
        let path = self.tombstones_dir.join(format!(
            "{stem}{TOMBSTONE_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
        ));
        match self.io.create_new(&path) {
            Ok(mut file) => {
                let written = write_all(self.io.as_ref(), &mut file, record)
                    .and_then(|()| self.io.sync_file(&file));
                drop(file);
                written.map_err(|error| error.kind())?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.kind()),
        }
        self.io
            .sync_directory(&self.tombstones_dir)
            .map_err(|error| error.kind())
    }

    fn write_temp(
        &mut self,
        relative: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), LocalPublicationError> {
        let parent = record_directory(path)?.to_path_buf();
        let mut file = match self.io.create_new(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(LocalPublicationError::OrphanedTemp {
                    path: relative.to_path_buf(),
                });
            }
            Err(error) => return Err(io_error(LocalIoOperation::CreateTemp, path, &error)),
        };
        let written =
            write_all(self.io.as_ref(), &mut file, bytes).and_then(|()| self.io.sync_file(&file));
        drop(file);
        if let Err(error) = written {
            let original = io_error(LocalIoOperation::WriteTemp, path, &error);
            let cleanup = self.remove_temp(relative, path);
            return Err(Self::fail_with_cleanup(original, cleanup));
        }
        if let Err(error) = self.io.sync_directory(&parent) {
            let original = io_error(LocalIoOperation::SyncDirectory, &parent, &error);
            let cleanup = self.remove_temp(relative, path);
            return Err(Self::fail_with_cleanup(original, cleanup));
        }
        let limit = bytes.len() as u64;
        match read_bounded(self.io.as_ref(), path, limit) {
            Ok(Some(read_back)) if read_back == bytes => Ok(()),
            Ok(_) => {
                let original = LocalPublicationError::Io {
                    operation: LocalIoOperation::ReadRecord,
                    path: path.to_path_buf(),
                    kind: io::ErrorKind::InvalidData,
                };
                let cleanup = self.remove_temp(relative, path);
                Err(Self::fail_with_cleanup(original, cleanup))
            }
            Err(error) => {
                let cleanup = self.remove_temp(relative, path);
                Err(Self::fail_with_cleanup(error, cleanup))
            }
        }
    }

    /// Removes a temporary record this call created. If removal fails, the path is remembered
    /// as an orphan so it is never silently reused, and the removal failure is returned.
    fn remove_temp(&mut self, relative: &Path, path: &Path) -> Result<(), LocalPublicationError> {
        let parent = match record_directory(path) {
            Ok(parent) => parent.to_path_buf(),
            Err(error) => {
                self.orphan_temps.insert(relative.to_path_buf());
                return Err(error);
            }
        };
        match self.io.remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                self.orphan_temps.insert(relative.to_path_buf());
                return Err(io_error(LocalIoOperation::RemoveTemp, path, &error));
            }
        }
        self.io
            .sync_directory(&parent)
            .map_err(|error| io_error(LocalIoOperation::SyncDirectory, &parent, &error))
    }

    fn reverify_existing(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        let (visible, closure_object_count) = match self.visible.get(slot) {
            Some(entry) => (
                entry.visible.clone(),
                self.closure(entry.visible.root, &entry.children).len(),
            ),
            None => return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        };
        self.require_references(manifest)?;
        self.spool.require_verified(visible.root).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: visible.root,
                role: ReferenceRole::ManifestBody,
                reason: error.into(),
            }
        })?;
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        match read_bounded(self.io.as_ref(), &path, MAX_ROOT_RECORD_BYTES)? {
            Some(bytes) if ContentDigest::sha256(&bytes) == visible.record_digest => {}
            _ => return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        }
        Ok(LocalPublicationReceipt {
            slot: slot.clone(),
            root: visible.root,
            record_digest: visible.record_digest,
            child_count: visible.child_count,
            closure_object_count,
            outcome: PublishOutcome::AlreadyPublished,
            claims: PublicationClaims::local_only(visible.state),
            transitions: vec![PublicationTransition::ExistingRootReverified],
        })
    }

    /// Classifies the publication root through [`classify_local`], verifying every reference
    /// through the owned spool, then fsyncs `roots/` and `tombstones/`. Admitted roots are
    /// reported `Durable` only if the roots fsync succeeded.
    fn recover(&mut self) -> Result<(), LocalPublicationError> {
        let io = Arc::clone(&self.io);
        let root = self.root.clone();
        let limits = self.limits;
        let spool = self.spool.recovery_report().clone();
        let layout = LocalLayout {
            roots: true,
            tombstones: true,
        };
        let classified = classify_local(io.as_ref(), &root, &limits, layout, spool, self)?;
        let mut report = classified.report;
        self.visible = classified.visible;
        self.broken_slots = classified.broken_slots;
        self.orphan_temps = classified.orphan_temps;
        self.tombstones = classified.tombstones;

        let roots_synced = self.io.sync_directory(&self.roots_dir).is_ok();
        let _ = self.io.sync_directory(&self.tombstones_dir);

        for entry in self.visible.values_mut() {
            if roots_synced {
                entry.visible.state = LocalPublicationState::Durable;
            }
            report.roots.push(entry.visible.clone());
        }
        let mut referenced = BTreeSet::new();
        for entry in self.visible.values() {
            referenced.extend(self.closure(entry.visible.root, &entry.children));
        }
        report.unreferenced_objects = unreferenced_spool_objects(&report.spool, &referenced);
        self.recovery = report;
        Ok(())
    }
}

impl ReferenceCheck for LocalRootPublisher {
    /// Verifies through the owned spool, placing its durable hold: a corrupt or missing object
    /// classifies the reference, any other spool failure fails the open.
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError> {
        match self.spool.verify(object) {
            Ok(SpoolObjectState::Verified) => Ok(Ok(())),
            Ok(SpoolObjectState::Staged) => Ok(Err(BlockReason::NotVerified)),
            Ok(SpoolObjectState::Corrupt(_)) | Err(SpoolError::Corrupt { .. }) => {
                Ok(Err(BlockReason::Corrupt))
            }
            Err(SpoolError::Missing(_)) => Ok(Err(BlockReason::Missing)),
            Err(error) => Err(self.spool_error(error)),
        }
    }

    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError> {
        self.spool
            .read(root)
            .map_err(|error| self.spool_error(error))
    }

    fn redundant_temp(&mut self, path: &Path) -> RedundantTemp {
        match self.io.remove_file(path) {
            Ok(()) => RedundantTemp::Removed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => RedundantTemp::Removed,
            Err(_) => RedundantTemp::Kept,
        }
    }
}

fn compute_closure(
    manifests: &BTreeMap<ContentDigest, &[ContentDigest]>,
    root: ContentDigest,
    children: &[ContentDigest],
) -> BTreeSet<ContentDigest> {
    let mut seen = BTreeSet::from([root]);
    let mut pending = children.to_vec();
    while let Some(digest) = pending.pop() {
        if seen.insert(digest)
            && let Some(grandchildren) = manifests.get(&digest)
        {
            pending.extend_from_slice(grandchildren);
        }
    }
    seen
}

/// Spool objects, admitted or corrupt, that no closure in `referenced` reaches.
fn unreferenced_spool_objects(
    spool: &SpoolRecoveryReport,
    referenced: &BTreeSet<ContentDigest>,
) -> Vec<ContentDigest> {
    let spool_objects = spool
        .admitted
        .iter()
        .copied()
        .chain(spool.corrupt.iter().map(|corrupt| corrupt.digest))
        .collect::<BTreeSet<_>>();
    spool_objects.difference(referenced).copied().collect()
}

/// How a root temp file whose target record exists was settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedundantTemp {
    /// The open removed it (or it was already gone).
    Removed,
    /// The open could not remove it; it stays an orphaned temp.
    Kept,
    /// Inspection left it in place and reports it.
    Reported,
}

/// What the shared classifier asks of its caller.
///
/// [`LocalRootPublisher`] verifies through, and holds in, its owned spool and removes redundant
/// temps; [`ObservedReferences`] answers from the spool classification without writing.
trait ReferenceCheck {
    /// Classifies one reference that no tombstone names: `Ok(Err(_))` blocks it, `Err(_)` fails
    /// the caller.
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError>;
    /// The rehashed body of a manifest whose reference check passed.
    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError>;
    /// Settles the root temp at `path`, whose target record exists.
    fn redundant_temp(&mut self, path: &Path) -> RedundantTemp;
}

/// Which publication directories exist when the root is classified. The open creates both
/// first; inspection skips a missing one, which is what the open would find in the empty
/// directory it creates.
#[derive(Clone, Copy, Debug)]
struct LocalLayout {
    roots: bool,
    tombstones: bool,
}

/// What [`classify_local`] found; the caller decides durability.
#[derive(Clone, Debug, Default)]
struct LocalClassification {
    /// Everything but `roots` and `unreferenced_objects`, which depend on durability.
    report: LocalRecoveryReport,
    /// Root temps inspection left in place; always empty for the open.
    redundant_temps: Vec<PathBuf>,
    visible: BTreeMap<SlotName, RootEntry>,
    tombstones: BTreeMap<ContentDigest, TombstoneRecord>,
    broken_slots: BTreeSet<SlotName>,
    orphan_temps: BTreeSet<PathBuf>,
}

/// The one classifier of a publication root, shared by [`LocalRootPublisher::open`] and
/// [`inspect_with_io`].
///
/// It lists, stats, and reads, and asks `references` to check every reference, read every
/// manifest body, and settle every redundant temp; those three are the only points where the
/// open and inspection differ. For the open it makes exactly the calls, in exactly the order, the
/// open made before inspection existed.
fn classify_local(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    layout: LocalLayout,
    spool: SpoolRecoveryReport,
    references: &mut dyn ReferenceCheck,
) -> Result<LocalClassification, LocalPublicationError> {
    let mut classified = LocalClassification {
        report: LocalRecoveryReport {
            spool,
            ..LocalRecoveryReport::default()
        },
        ..LocalClassification::default()
    };

    for (name, _) in scan_directory(io, root, TOP_LEVEL_SCAN_BOUND)? {
        let known = [
            LOCAL_LOCK_FILE,
            LOCAL_SPOOL_DIR,
            LOCAL_ROOTS_DIR,
            LOCAL_TOMBSTONES_DIR,
        ];
        if !known.iter().any(|entry| name == *entry) {
            classified.report.foreign.push(PathBuf::from(&name));
        }
    }

    if layout.tombstones {
        classify_tombstones(io, root, limits, &mut classified)?;
    }
    if layout.roots {
        classify_roots(io, root, limits, &mut classified, references)?;
    }

    classified.report.tombstones = classified.tombstones.keys().copied().collect();
    classified.report.orphaned_temps = classified.orphan_temps.iter().cloned().collect();
    classified.report.foreign.sort();
    Ok(classified)
}

/// A reference named by a durable tombstone is blocked before `references` is asked.
fn check_reference(
    tombstones: &BTreeMap<ContentDigest, TombstoneRecord>,
    references: &mut dyn ReferenceCheck,
    object: ContentDigest,
) -> Result<Result<(), BlockReason>, LocalPublicationError> {
    if tombstones.contains_key(&object) {
        return Ok(Err(BlockReason::Tombstoned));
    }
    references.check_reference(object)
}

fn classify_tombstones(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    classified: &mut LocalClassification,
) -> Result<(), LocalPublicationError> {
    let tombstones_dir = root.join(LOCAL_TOMBSTONES_DIR);
    let entries = scan_directory(io, &tombstones_dir, limits.max_scan_entries)?;
    for (name, file_type) in entries {
        let relative = Path::new(LOCAL_TOMBSTONES_DIR).join(&name);
        let Some(text) = name.to_str() else {
            classified.report.foreign.push(relative);
            continue;
        };
        if let Some(stem) = text.strip_suffix(ROOT_INDETERMINATE_SUFFIX) {
            let parsed = stem
                .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                .and_then(parse_digest_file_stem);
            if parsed.is_some() {
                return Err(LocalPublicationError::CorruptTombstone { path: relative });
            }
            classified.report.foreign.push(relative);
            continue;
        }
        if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
            let parsed = stem
                .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                .and_then(parse_digest_file_stem);
            if parsed.is_some() && file_type.is_file() {
                classified.orphan_temps.insert(relative);
            } else {
                classified.report.foreign.push(relative);
            }
            continue;
        }
        let Some(object) = text
            .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
            .and_then(parse_digest_file_stem)
        else {
            classified.report.foreign.push(relative);
            continue;
        };
        if !file_type.is_file() {
            return Err(LocalPublicationError::CorruptTombstone { path: relative });
        }
        let path = tombstones_dir.join(&name);
        let Some(bytes) = read_bounded(io, &path, MAX_TOMBSTONE_RECORD_BYTES)? else {
            return Err(LocalPublicationError::CorruptTombstone { path: relative });
        };
        let record = match record::decode_tombstone_record(&bytes) {
            Ok(record) if record.payload_digest == object => record,
            _ => return Err(LocalPublicationError::CorruptTombstone { path: relative }),
        };
        classified.tombstones.insert(object, record);
    }
    if classified.tombstones.len() > limits.max_tombstones {
        return Err(LocalPublicationError::Capacity {
            resource: CapacityResource::Tombstones,
            current: classified.tombstones.len(),
            maximum: limits.max_tombstones,
        });
    }
    Ok(())
}

fn classify_roots(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    classified: &mut LocalClassification,
    references: &mut dyn ReferenceCheck,
) -> Result<(), LocalPublicationError> {
    struct CandidateRoot {
        relative: PathBuf,
        root: ContentDigest,
        manifest: ObjectManifest,
        record_bytes: Vec<u8>,
    }

    let roots_dir = root.join(LOCAL_ROOTS_DIR);
    let entries = scan_directory(io, &roots_dir, limits.max_scan_entries)?;

    let mut candidates: BTreeMap<SlotName, CandidateRoot> = BTreeMap::new();
    let mut broken_slot_roots: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut indeterminate: BTreeMap<SlotName, PathBuf> = BTreeMap::new();
    let mut record_slots: BTreeSet<SlotName> = BTreeSet::new();

    for (name, file_type) in entries {
        let relative = Path::new(LOCAL_ROOTS_DIR).join(&name);
        let Some(text) = name.to_str() else {
            classified.report.foreign.push(relative);
            continue;
        };
        if let Some(stem) = text.strip_suffix(ROOT_INDETERMINATE_SUFFIX) {
            // Classified by existence alone, whatever its type or contents: fail closed.
            match stem.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse) {
                Some(Ok(slot)) => {
                    indeterminate.insert(slot, relative);
                }
                Some(Err(_)) | None => classified.report.foreign.push(relative),
            }
            continue;
        }
        if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
            let parsed = stem.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse);
            if let Some(Ok(slot)) = parsed {
                if file_type.is_file() {
                    let target_path = roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
                    if io.symlink_metadata(&target_path).is_ok() {
                        match references.redundant_temp(&root.join(&relative)) {
                            RedundantTemp::Removed => {}
                            RedundantTemp::Kept => {
                                classified.orphan_temps.insert(relative);
                            }
                            RedundantTemp::Reported => classified.redundant_temps.push(relative),
                        }
                        continue;
                    }
                    classified.orphan_temps.insert(relative);
                } else {
                    classified.report.foreign.push(relative);
                }
            } else {
                classified.report.foreign.push(relative);
            }
            continue;
        }
        let Some(Ok(slot)) = text.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse) else {
            classified.report.foreign.push(relative);
            continue;
        };
        record_slots.insert(slot.clone());
        if !file_type.is_file() {
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::NotRegularFile,
            });
            continue;
        }
        let path = roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        let Some(bytes) = read_bounded(io, &path, MAX_ROOT_RECORD_BYTES)? else {
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::RecordTooLarge,
            });
            continue;
        };
        let decoded = match record::decode_root_record(&bytes) {
            Ok(decoded) => decoded,
            Err(reason) => {
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: relative,
                    reason,
                });
                continue;
            }
        };
        if decoded.slot != slot.as_str() {
            broken_slot_roots.insert(decoded.root);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::SlotMismatch,
            });
            continue;
        }
        let root_digest = decoded.root;
        if let Err(reason) = check_reference(&classified.tombstones, references, root_digest)? {
            broken_slot_roots.insert(root_digest);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::ReferenceBlocked {
                    object: root_digest,
                    role: ReferenceRole::ManifestBody,
                    reason,
                },
            });
            continue;
        }
        let body = references.manifest_body(root_digest)?;
        let manifest = match ObjectManifest::from_canonical_bytes(&body) {
            Ok(manifest) if manifest.root() == root_digest => manifest,
            _ => {
                broken_slot_roots.insert(root_digest);
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: relative,
                    reason: BrokenRootReason::ManifestUndecodable,
                });
                continue;
            }
        };
        let child_count = manifest.children().len();
        if decoded.child_count != child_count as u64 {
            broken_slot_roots.insert(root_digest);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::ChildCountMismatch {
                    recorded: decoded.child_count,
                    actual: child_count,
                },
            });
            continue;
        }
        if child_count > limits.max_children {
            broken_slot_roots.insert(root_digest);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::ChildBoundExceeded {
                    count: child_count,
                    maximum: limits.max_children,
                },
            });
            continue;
        }
        candidates.insert(
            slot,
            CandidateRoot {
                relative,
                root: root_digest,
                manifest,
                record_bytes: bytes,
            },
        );
    }

    // A durable indeterminate marker overrides whatever the slot's record says: its record,
    // if any, is never admitted, and roots that reach it are broken below.
    for (slot, relative) in indeterminate {
        if let Some(candidate) = candidates.remove(&slot) {
            broken_slot_roots.insert(candidate.root);
        }
        let record_present = record_slots.contains(&slot);
        classified.broken_slots.insert(slot);
        classified.report.broken_roots.push(BrokenRoot {
            path: relative,
            reason: BrokenRootReason::VisibilityIndeterminate { record_present },
        });
    }

    // Multi-pass fixed-point validation of direct references and transitive descendants
    loop {
        let mut newly_broken = Vec::new();
        let candidate_manifests: BTreeMap<ContentDigest, Vec<ContentDigest>> = candidates
            .values()
            .map(|c| (c.root, c.manifest.children().to_vec()))
            .collect();

        for (slot, candidate) in &candidates {
            let mut broken_reason = None;

            // 1. Direct children
            for child in candidate.manifest.children() {
                let role = if candidate.manifest.metadata_digest() == Some(*child) {
                    ReferenceRole::Metadata
                } else {
                    ReferenceRole::Child
                };
                if broken_slot_roots.contains(child) {
                    broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                        object: *child,
                        role,
                        reason: BlockReason::NotVerified,
                    });
                    break;
                }
                match check_reference(&classified.tombstones, references, *child)? {
                    Ok(()) => {}
                    Err(reason) => {
                        broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                            object: *child,
                            role,
                            reason,
                        });
                        break;
                    }
                }
            }

            // 2. Transitive descendants
            if broken_reason.is_none() {
                let direct: BTreeSet<ContentDigest> =
                    candidate.manifest.children().iter().copied().collect();
                let mut seen = BTreeSet::from([candidate.root]);
                let mut pending = candidate.manifest.children().to_vec();
                while let Some(digest) = pending.pop() {
                    if seen.insert(digest)
                        && let Some(grandchildren) = candidate_manifests.get(&digest)
                    {
                        pending.extend_from_slice(grandchildren);
                    }
                }
                for descendant in seen {
                    if descendant == candidate.root || direct.contains(&descendant) {
                        continue;
                    }
                    if broken_slot_roots.contains(&descendant) {
                        broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                            object: descendant,
                            role: ReferenceRole::Descendant,
                            reason: BlockReason::NotVerified,
                        });
                        break;
                    }
                    match check_reference(&classified.tombstones, references, descendant)? {
                        Ok(()) => {}
                        Err(reason) => {
                            broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                                object: descendant,
                                role: ReferenceRole::Descendant,
                                reason,
                            });
                            break;
                        }
                    }
                }
            }

            if let Some(reason) = broken_reason {
                newly_broken.push((slot.clone(), reason));
            }
        }

        if newly_broken.is_empty() {
            break;
        }

        for (slot, reason) in newly_broken {
            if let Some(candidate) = candidates.remove(&slot) {
                broken_slot_roots.insert(candidate.root);
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: candidate.relative,
                    reason,
                });
            }
        }
    }

    classified
        .report
        .broken_roots
        .sort_by(|left, right| left.path.cmp(&right.path));

    for (slot, candidate) in candidates {
        classified.visible.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot,
                    root: candidate.root,
                    record_digest: ContentDigest::sha256(&candidate.record_bytes),
                    child_count: candidate.manifest.children().len(),
                    state: LocalPublicationState::Visible,
                },
                children: candidate.manifest.children().to_vec(),
            },
        );
    }

    if classified.visible.len() > limits.max_roots {
        return Err(LocalPublicationError::Capacity {
            resource: CapacityResource::Roots,
            current: classified.visible.len(),
            maximum: limits.max_roots,
        });
    }
    Ok(())
}

/// Read-only reference checks for inspection.
///
/// The spool classification has already reread and rehashed every object file, so a reference
/// passes exactly when the open's verify would accept it for the same bytes: admitted objects
/// pass, corrupt (including vanished) ones are `Corrupt`, anything unindexed is `Missing`.
/// Manifest bodies are reread and rehashed without the lock; nothing is held or written.
struct ObservedReferences<'a> {
    io: &'a dyn SpoolIo,
    spool_root: PathBuf,
    max_object_bytes: usize,
    admitted: BTreeSet<ContentDigest>,
    corrupt: BTreeSet<ContentDigest>,
}

impl ReferenceCheck for ObservedReferences<'_> {
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError> {
        if self.corrupt.contains(&object) {
            return Ok(Err(BlockReason::Corrupt));
        }
        if self.admitted.contains(&object) {
            return Ok(Ok(()));
        }
        Ok(Err(BlockReason::Missing))
    }

    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError> {
        fss_object::read_verified_payload(&self.spool_root, root, self.max_object_bytes, self.io)
            .map_err(LocalPublicationError::Spool)
    }

    fn redundant_temp(&mut self, _path: &Path) -> RedundantTemp {
        RedundantTemp::Reported
    }
}

/// Whether `path` is a directory, without following a symlink. Absent is `false`; any other file
/// type is [`LocalPublicationError::InvalidLayout`], the class the open reports.
fn directory_present(io: &dyn SpoolIo, path: &Path) -> Result<bool, LocalPublicationError> {
    match io.symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(LocalIoOperation::Inspect, path, &error)),
    }
}

/// Inspects a local publication root without taking locks, creating directories, or repairing
/// state, with the host filesystem and the default read-only writer check. See
/// [`inspect_with_io`].
pub fn inspect(
    root: impl AsRef<Path>,
    limits: impl Into<LocalPublicationLimits>,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_io(
        &HostSpoolIo,
        root.as_ref(),
        limits.into(),
        None,
        WriterDetectionOptions::default(),
    )
}

/// [`inspect_with_io`] taking a shared I/O capability.
pub fn inspect_with_options(
    io: Arc<dyn SpoolIo>,
    root: &Path,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_io(io.as_ref(), root, limits, lock_table, options)
}

/// Inspects a local publication root through explicit I/O and lock-table capabilities.
///
/// Only lists, stats, and reads through `io`: it never creates, locks, renames, removes, or
/// fsyncs, and the only lock call is the opt-in shared probe of
/// [`WriterDetectionOptions::probe_shared_lock`]. The spool and the root are classified by the
/// same classifiers the open runs (see [`LocalInspection`] for the documented differences). A
/// listing over its bound is the typed [`LocalPublicationError::EntryLimit`] or
/// [`fss_object::SpoolError::EntryLimit`] the open returns.
pub fn inspect_with_io(
    io: &dyn SpoolIo,
    root: &Path,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_ledger_journal(io, root, None, limits, lock_table, options)
}

/// [`inspect_with_io`] that also checks the deployment's canonical ledger journal for a writer.
///
/// `root` is the publication root; writer detection checks exactly `<root>/LOCK`,
/// `<root>/spool/LOCK`, and `ledger_journal` when given. The journal path is always passed
/// explicitly, never derived from the publication root, because the deployment layout places it
/// beside the publication root (a ledger repair apply flocks it). With `None` the journal is not
/// checked.
pub fn inspect_with_ledger_journal(
    io: &dyn SpoolIo,
    root: &Path,
    ledger_journal: Option<&Path>,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    let limits = limits.validate()?;
    let spool_root = root.join(LOCAL_SPOOL_DIR);
    let root_present = directory_present(io, root)?;
    let (roots, tombstones) = if root_present {
        (
            directory_present(io, &root.join(LOCAL_ROOTS_DIR))?,
            directory_present(io, &root.join(LOCAL_TOMBSTONES_DIR))?,
        )
    } else {
        (false, false)
    };
    let spool = if root_present {
        fss_object::inspect_with_io(&spool_root, &limits.spool, io)
            .map_err(LocalPublicationError::Spool)?
    } else {
        SpoolInspection {
            missing_layout: true,
            ..SpoolInspection::default()
        }
    };
    let classified = if root_present {
        let mut references = ObservedReferences {
            io,
            spool_root: spool_root.clone(),
            max_object_bytes: limits.spool.max_object_bytes,
            admitted: spool.report.admitted.iter().copied().collect(),
            corrupt: spool.report.corrupt.iter().map(|c| c.digest).collect(),
        };
        let layout = LocalLayout { roots, tombstones };
        classify_local(
            io,
            root,
            &limits,
            layout,
            spool.report.clone(),
            &mut references,
        )?
    } else {
        LocalClassification {
            report: LocalRecoveryReport {
                spool: spool.report.clone(),
                ..LocalRecoveryReport::default()
            },
            ..LocalClassification::default()
        }
    };

    let LocalClassification {
        mut report,
        redundant_temps,
        visible,
        broken_slots,
        ..
    } = classified;
    // Every admitted root is one the open would fsync and admit, so closures span all of them.
    // Their state stays `Visible`: this inspection observed no fsync.
    let manifests: BTreeMap<ContentDigest, &[ContentDigest]> = visible
        .values()
        .map(|entry| (entry.visible.root, entry.children.as_slice()))
        .collect();
    let mut referenced = BTreeSet::new();
    let mut root_closures = BTreeMap::new();
    for (slot, entry) in &visible {
        let closure = compute_closure(&manifests, entry.visible.root, &entry.children);
        referenced.extend(closure.iter().copied());
        root_closures.insert(slot.clone(), closure);
        report.roots.push(entry.visible.clone());
    }
    report.unreferenced_objects = unreferenced_spool_objects(&report.spool, &referenced);

    let mut lock_paths = vec![
        root.join(LOCAL_LOCK_FILE),
        spool_root.join(fss_object::SPOOL_LOCK_FILE),
    ];
    lock_paths.extend(ledger_journal.map(Path::to_path_buf));
    let writer_state = detect_writers(io, &lock_paths, lock_table, options);
    let possibly_stale = writer_state.possibly_stale();
    let possibly_in_flight = writer_state.is_held()
        || !redundant_temps.is_empty()
        || !report.spool.orphaned_staging.is_empty();

    Ok(LocalInspection {
        report,
        redundant_temps,
        durability_not_resynced: !visible.is_empty(),
        holds_migration_pending: spool.holds_migration_pending,
        missing_layout: !root_present || !roots || !tombstones || spool.missing_layout,
        spool_over_capacity: spool.over_capacity,
        writer_state,
        root_closures,
        broken_slots,
        possibly_stale,
        possibly_in_flight,
    })
}

/// Reads and verifies an object's payload directly from a deployment's spool
/// without taking locks, creating holds, or modifying state.
pub fn read_verified(
    root: impl AsRef<Path>,
    digest: ContentDigest,
    max_bytes: usize,
) -> Result<Vec<u8>, LocalPublicationError> {
    read_verified_with_io(root.as_ref(), digest, max_bytes, &HostSpoolIo)
}

/// Reads and verifies an object's payload through the given I/O capability without taking
/// locks, creating holds, or modifying state.
///
/// A missing or non-directory `<root>/spool` is [`LocalPublicationError::InvalidLayout`]; the
/// root itself is never read as a spool. A payload longer than `max_bytes` or bytes that do not
/// rehash to `digest` are [`fss_object::SpoolError::Corrupt`].
pub fn read_verified_with_io(
    root: &Path,
    digest: ContentDigest,
    max_bytes: usize,
    io: &dyn SpoolIo,
) -> Result<Vec<u8>, LocalPublicationError> {
    let spool_root = root.join(LOCAL_SPOOL_DIR);
    if !directory_present(io, &spool_root)? {
        return Err(LocalPublicationError::InvalidLayout { path: spool_root });
    }
    fss_object::read_verified_payload(&spool_root, digest, max_bytes, io)
        .map_err(LocalPublicationError::Spool)
}

impl fss_object::VerifiedObjectCatalog for LocalRootPublisher {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), fss_object::ObjectError> {
        self.spool.require_verified(digest)
    }
}

fn io_error(operation: LocalIoOperation, path: &Path, error: &io::Error) -> LocalPublicationError {
    LocalPublicationError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

fn acquire_lock(io: &dyn SpoolIo, root: &Path) -> Result<File, LocalPublicationError> {
    let path = root.join(LOCAL_LOCK_FILE);
    match io.symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(LocalPublicationError::InvalidLayout { path });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
    }
    let file = io
        .open_lock(&path)
        .map_err(|error| io_error(LocalIoOperation::OpenLock, &path, &error))?;
    match io.try_lock(&file) {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(LocalPublicationError::Locked { path }),
        Err(TryLockError::Error(error)) => Err(io_error(LocalIoOperation::Lock, &path, &error)),
    }
}

fn ensure_subdirectory(io: &dyn SpoolIo, path: &Path) -> Result<(), LocalPublicationError> {
    match io.create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(LocalIoOperation::CreateDirectory, path, &error)),
    }
    let metadata = io
        .symlink_metadata(path)
        .map_err(|error| io_error(LocalIoOperation::Inspect, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Writes all of `bytes` through `io`, resuming after partial writes.
///
/// A write that accepts zero bytes is [`io::ErrorKind::WriteZero`]. An
/// [`io::ErrorKind::Interrupted`] write transferred nothing, so it is retried at the same offset,
/// exactly as the spool's own staging write does; the [`MAX_INTERRUPTED_ATTEMPTS`]-th consecutive
/// interruption at one offset is returned, and the caller reports it as
/// [`LocalIoOperation::WriteTemp`]. Any other error is returned at once. The loop is bounded:
/// every iteration either advances by at least one byte or spends one of the interrupted attempts
/// allowed at the current offset.
fn write_all(io: &dyn SpoolIo, file: &mut File, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0_usize;
    let mut interrupted = 0_u32;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        match io.write(file, rest) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(accepted) => {
                written = written.saturating_add(accepted.min(rest.len()));
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted = interrupted.saturating_add(1);
                if interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn scan_directory(
    io: &dyn SpoolIo,
    dir: &Path,
    bound: usize,
) -> Result<Vec<(OsString, fs::FileType)>, LocalPublicationError> {
    let mut entries = io
        .read_dir(dir)
        .map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
    let mut found = Vec::new();
    while let Some(entry) = io.next_dir_entry(&mut entries) {
        let entry =
            entry.map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
        if found.len() >= bound {
            // Bounded scan: this entry is the first one past `bound`. The rest of the directory
            // is never listed, so only a lower bound on its size is known.
            return Err(LocalPublicationError::EntryLimit {
                directory: dir.to_path_buf(),
                maximum: bound,
                at_least: bound.saturating_add(1),
            });
        }
        let file_type = io
            .entry_file_type(&entry)
            .map_err(|error| io_error(LocalIoOperation::Inspect, &entry.path(), &error))?;
        found.push((entry.file_name(), file_type));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

/// Reads at most `limit` bytes; `Ok(None)` means the file is longer than `limit`.
fn read_bounded(
    io: &dyn SpoolIo,
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, LocalPublicationError> {
    let mut file = io
        .open_read(path)
        .map_err(|error| io_error(LocalIoOperation::ReadRecord, path, &error))?;
    let bytes = io
        .read_bounded(&mut file, limit.saturating_add(1))
        .map_err(|error| io_error(LocalIoOperation::ReadRecord, path, &error))?;
    if bytes.len() as u64 > limit {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// `<algorithm>-<64 lowercase hex>`: a file-name-safe rendering of a content digest.
fn digest_file_stem(digest: ContentDigest) -> String {
    digest.to_text().replacen(':', "-", 1)
}

fn parse_digest_file_stem(stem: &str) -> Option<ContentDigest> {
    let (algorithm, hex) = stem.split_once('-')?;
    let digest = ContentDigest::parse(format!("{algorithm}:{hex}")).ok()?;
    (digest_file_stem(digest) == stem).then_some(digest)
}

/// The directory holding the record at `path`, whose fsync makes the record's creation, rename,
/// or removal durable. A path without a non-empty parent is [`LocalPublicationError::InvalidLayout`]:
/// there is no directory to fsync, and silently fsyncing another one would claim durability that
/// was never observed.
fn record_directory(path: &Path) -> Result<&Path, LocalPublicationError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) | None => Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{LocalPublicationError, record_directory};

    #[test]
    fn record_directory_is_a_typed_error_for_a_path_without_a_parent_directory() {
        for path in ["", "/", "slot.root.tmp"] {
            assert_eq!(
                record_directory(Path::new(path)),
                Err(LocalPublicationError::InvalidLayout {
                    path: PathBuf::from(path),
                }),
                "{path:?}"
            );
        }
        assert_eq!(
            record_directory(Path::new("publication/roots/slot.root.tmp")),
            Ok(Path::new("publication/roots"))
        );
    }
}
