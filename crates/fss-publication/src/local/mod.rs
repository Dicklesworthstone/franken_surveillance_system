//! Root-last local manifest publication over the content-addressed staging spool (FSS-018).
//!
//! # Layout
//!
//! ```text
//! <root>/LOCK                          exclusive owner lock, held for the publisher's lifetime
//! <root>/spool/                        fss_object::StagingSpool (children and manifest bodies)
//! <root>/roots/<slot>.root             one visible root record per slot
//! <root>/roots/<slot>.root.tmp         in-flight root record, never visible
//! <root>/tombstones/<alg>-<hex>.tomb   one durable tombstone per object digest
//! ```
//!
//! # Publication lattice
//!
//! [`LocalPublicationState`] distinguishes `Staged` (the manifest body is in the spool but no
//! root record names it), `Visible` (the root record was renamed into place but the directory
//! fsync that makes the rename durable has not been observed), and `Durable` (the directory fsync
//! succeeded). Replication, protection, and retrievability are outside this crate's authority and
//! every receipt reports them as [`ClaimStatus::NotClaimed`].
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
//! Records that fail are reported as [`BrokenRoot`] and never admitted. Objects not reachable from
//! any admitted root are reported as `unreferenced_objects`; temporary records are reported as
//! `orphaned_temps`. Nothing found on open is deleted implicitly.
//!
//! Filesystem access is scoped by the root path passed to `open`, matching `fss-object`'s spool
//! and `fss-ledger`'s journal. No `Cx` capability is threaded yet.
//!
//! # Fault injection
//!
//! Two test seams exist, and neither is reachable through [`LocalRootPublisher::open`].
//! [`LocalRootPublisher::inject_crash_at`] arms a crash at a [`PublishCutPoint`]: the call returns
//! [`LocalPublicationError::InjectedCrash`] and the instance behaves as a dead process.
//! [`LocalRootPublisher::open_with_injected_io_fault`] is the only way to arm an
//! [`InjectedIoFault`]: the root rename or the roots-directory fsync after it returns the
//! configured [`io::ErrorKind`] instead of touching the filesystem, and the publisher then takes
//! exactly the error path a real failure of that operation takes. The fault is one-shot, and no
//! method arms one on an already open instance.

mod error;
mod record;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fss_core::{CanonicalEncode, ContentDigest, TombstoneRecord};
use fss_object::{
    MAX_MANIFEST_CHILDREN, ObjectManifest, SpoolError, SpoolLimits, SpoolObjectState,
    SpoolRecoveryReport, StagingSpool, VerifiedObjectCatalog,
};

pub use error::{
    BlockReason, CapacityResource, LOCAL_PUBLICATION_ERROR_CODES, LocalIoOperation,
    LocalLimitViolation, LocalPublicationError, LocalPublicationGuidance, ReferenceRole,
    SlotViolation,
};
pub use record::{
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_TOMBSTONE_RECORD_DOMAIN,
    MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, MAX_TOMBSTONE_RECORD_BYTES, SlotName,
    root_record_bytes,
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

struct NeverCancel;

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
    const fn local_only(local: LocalPublicationState) -> Self {
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
    root: PathBuf,
    roots_dir: PathBuf,
    tombstones_dir: PathBuf,
    _lock: File,
    limits: LocalPublicationLimits,
    spool: StagingSpool,
    visible: BTreeMap<SlotName, RootEntry>,
    broken_slots: BTreeSet<SlotName>,
    orphan_temps: BTreeSet<PathBuf>,
    tombstones: BTreeMap<ContentDigest, TombstoneRecord>,
    recovery: LocalRecoveryReport,
    injected_crash: Option<PublishCutPoint>,
    injected_io_fault: Option<InjectedIoFault>,
    poisoned: bool,
}

impl LocalRootPublisher {
    /// Opens or creates a publication directory, takes its lock, and classifies every entry.
    ///
    /// Every durable tombstone must verify or the open fails closed. Every root record is
    /// re-verified with its manifest body and children before admission; broken ones are reported
    /// and never admitted. Admitted roots are reported `Durable` only after this call fsyncs the
    /// roots directory.
    pub fn open(
        root: impl AsRef<Path>,
        limits: LocalPublicationLimits,
    ) -> Result<Self, LocalPublicationError> {
        let limits = limits.validate()?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|error| io_error(LocalIoOperation::CreateDirectory, &root, &error))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| io_error(LocalIoOperation::Inspect, &root, &error))?;
        if !metadata.file_type().is_dir() {
            return Err(LocalPublicationError::InvalidLayout { path: root });
        }
        let lock = acquire_lock(&root)?;
        let roots_dir = root.join(LOCAL_ROOTS_DIR);
        let tombstones_dir = root.join(LOCAL_TOMBSTONES_DIR);
        ensure_subdirectory(&roots_dir)?;
        ensure_subdirectory(&tombstones_dir)?;
        let spool = StagingSpool::open(root.join(LOCAL_SPOOL_DIR), limits.spool)
            .map_err(LocalPublicationError::Spool)?;
        sync_directory(&root)
            .map_err(|error| io_error(LocalIoOperation::SyncDirectory, &root, &error))?;

        let mut publisher = Self {
            root,
            roots_dir,
            tombstones_dir,
            _lock: lock,
            limits,
            spool,
            visible: BTreeMap::new(),
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

    /// The root this instance reports visible in `slot`, if any.
    ///
    /// Remains readable on a poisoned instance so a crash after the rename is reported as
    /// `Visible` rather than hidden or upgraded.
    #[must_use]
    pub fn root(&self, slot: &SlotName) -> Option<&VisibleRoot> {
        self.visible.get(slot).map(|entry| &entry.visible)
    }

    /// Every visible root, in slot order.
    pub fn visible_roots(&self) -> impl Iterator<Item = &VisibleRoot> {
        self.visible.values().map(|entry| &entry.visible)
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
            self.remove_temp(&temp_relative, &temp_path)?;
            return Err(error);
        }
        match fs::symlink_metadata(&target_path) {
            Ok(_) => {
                self.remove_temp(&temp_relative, &temp_path)?;
                return Err(LocalPublicationError::InvalidLayout { path: target_path });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                self.remove_temp(&temp_relative, &temp_path)?;
                return Err(io_error(LocalIoOperation::Inspect, &target_path, &error));
            }
        }

        // 5. Commit point: the rename makes the root visible.
        let renamed = match self.take_io_fault(IoFaultPoint::RootRename) {
            Some(kind) => Err(io::Error::from(kind)),
            None => fs::rename(&temp_path, &target_path),
        };
        if let Err(error) = renamed {
            self.remove_temp(&temp_relative, &temp_path)?;
            return Err(io_error(LocalIoOperation::Rename, &target_path, &error));
        }
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
            None => sync_directory(&self.roots_dir),
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
        if let Err(error) = fs::rename(&temp_path, &target_path) {
            self.remove_temp(&temp_relative, &temp_path)?;
            return Err(io_error(LocalIoOperation::Rename, &target_path, &error));
        }
        if let Err(error) = sync_directory(&self.tombstones_dir) {
            self.poisoned = true;
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
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    fs::remove_file(&path)
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
            sync_directory(directory)
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
    /// children of any reached object that is itself the root of a visible slot. Any other object
    /// is an opaque leaf, exactly as in `fss_object::InMemoryObjectStore::verify_closure`.
    fn closure(&self, root: ContentDigest, children: &[ContentDigest]) -> BTreeSet<ContentDigest> {
        let manifests: BTreeMap<ContentDigest, &[ContentDigest]> = self
            .visible
            .values()
            .map(|entry| (entry.visible.root, entry.children.as_slice()))
            .collect();
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
            if let Some((relative, path)) = temp {
                self.remove_temp(relative, path)?;
            }
            return Err(LocalPublicationError::Cancelled { point });
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

    fn write_temp(
        &mut self,
        relative: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), LocalPublicationError> {
        let mut file = match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(LocalPublicationError::OrphanedTemp {
                    path: relative.to_path_buf(),
                });
            }
            Err(error) => return Err(io_error(LocalIoOperation::CreateTemp, path, &error)),
        };
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written {
            self.remove_temp(relative, path)?;
            return Err(io_error(LocalIoOperation::WriteTemp, path, &error));
        }
        let limit = bytes.len() as u64;
        match read_bounded(path, limit) {
            Ok(Some(read_back)) if read_back == bytes => Ok(()),
            Ok(_) => {
                self.remove_temp(relative, path)?;
                Err(LocalPublicationError::Io {
                    operation: LocalIoOperation::ReadRecord,
                    path: path.to_path_buf(),
                    kind: io::ErrorKind::InvalidData,
                })
            }
            Err(error) => {
                self.remove_temp(relative, path)?;
                Err(error)
            }
        }
    }

    /// Removes a temporary record this call created. If removal fails, the path is remembered
    /// as an orphan so it is never silently reused, and the removal failure is returned.
    fn remove_temp(&mut self, relative: &Path, path: &Path) -> Result<(), LocalPublicationError> {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                self.orphan_temps.insert(relative.to_path_buf());
                return Err(io_error(LocalIoOperation::RemoveTemp, path, &error));
            }
        }
        let parent = path.parent().unwrap_or(&self.root).to_path_buf();
        sync_directory(&parent)
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
        match read_bounded(&path, MAX_ROOT_RECORD_BYTES)? {
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

    /// Checks one reference during reopen: `Ok(Err(_))` classifies it, `Err(_)` fails the open.
    fn verify_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError> {
        if self.tombstones.contains_key(&object) {
            return Ok(Err(BlockReason::Tombstoned));
        }
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

    fn recover(&mut self) -> Result<(), LocalPublicationError> {
        let mut report = LocalRecoveryReport {
            spool: self.spool.recovery_report().clone(),
            ..LocalRecoveryReport::default()
        };

        for (name, _) in scan_directory(&self.root, TOP_LEVEL_SCAN_BOUND)? {
            let known = [
                LOCAL_LOCK_FILE,
                LOCAL_SPOOL_DIR,
                LOCAL_ROOTS_DIR,
                LOCAL_TOMBSTONES_DIR,
            ];
            if !known.iter().any(|entry| name == *entry) {
                report.foreign.push(PathBuf::from(&name));
            }
        }

        self.recover_tombstones(&mut report)?;
        self.recover_roots(&mut report)?;

        for directory in [&self.roots_dir, &self.tombstones_dir] {
            sync_directory(directory)
                .map_err(|error| io_error(LocalIoOperation::SyncDirectory, directory, &error))?;
        }
        let mut referenced = BTreeSet::new();
        for entry in self.visible.values() {
            referenced.extend(self.closure(entry.visible.root, &entry.children));
        }
        for entry in self.visible.values_mut() {
            entry.visible.state = LocalPublicationState::Durable;
            report.roots.push(entry.visible.clone());
        }
        let spool_objects = report
            .spool
            .admitted
            .iter()
            .copied()
            .chain(report.spool.corrupt.iter().map(|corrupt| corrupt.digest))
            .collect::<BTreeSet<_>>();
        report.unreferenced_objects = spool_objects.difference(&referenced).copied().collect();
        report.tombstones = self.tombstones.keys().copied().collect();
        report.orphaned_temps = self.orphan_temps.iter().cloned().collect();
        report.foreign.sort();
        self.recovery = report;
        Ok(())
    }

    fn recover_tombstones(
        &mut self,
        report: &mut LocalRecoveryReport,
    ) -> Result<(), LocalPublicationError> {
        let entries = scan_directory(&self.tombstones_dir, self.limits.max_scan_entries)?;
        for (name, file_type) in entries {
            let relative = Path::new(LOCAL_TOMBSTONES_DIR).join(&name);
            let Some(text) = name.to_str() else {
                report.foreign.push(relative);
                continue;
            };
            if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
                let parsed = stem
                    .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                    .and_then(parse_digest_file_stem);
                if parsed.is_some() && file_type.is_file() {
                    self.orphan_temps.insert(relative);
                } else {
                    report.foreign.push(relative);
                }
                continue;
            }
            let Some(object) = text
                .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                .and_then(parse_digest_file_stem)
            else {
                report.foreign.push(relative);
                continue;
            };
            if !file_type.is_file() {
                return Err(LocalPublicationError::CorruptTombstone { path: relative });
            }
            let path = self.tombstones_dir.join(&name);
            let Some(bytes) = read_bounded(&path, MAX_TOMBSTONE_RECORD_BYTES)? else {
                return Err(LocalPublicationError::CorruptTombstone { path: relative });
            };
            let record = match record::decode_tombstone_record(&bytes) {
                Ok(record) if record.payload_digest == object => record,
                _ => return Err(LocalPublicationError::CorruptTombstone { path: relative }),
            };
            self.tombstones.insert(object, record);
        }
        if self.tombstones.len() > self.limits.max_tombstones {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Tombstones,
                current: self.tombstones.len(),
                maximum: self.limits.max_tombstones,
            });
        }
        Ok(())
    }

    fn recover_roots(
        &mut self,
        report: &mut LocalRecoveryReport,
    ) -> Result<(), LocalPublicationError> {
        let entries = scan_directory(&self.roots_dir, self.limits.max_scan_entries)?;
        for (name, file_type) in entries {
            let relative = Path::new(LOCAL_ROOTS_DIR).join(&name);
            let Some(text) = name.to_str() else {
                report.foreign.push(relative);
                continue;
            };
            if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
                let parsed = stem.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse);
                if matches!(parsed, Some(Ok(_))) && file_type.is_file() {
                    self.orphan_temps.insert(relative);
                } else {
                    report.foreign.push(relative);
                }
                continue;
            }
            let Some(Ok(slot)) = text.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse) else {
                report.foreign.push(relative);
                continue;
            };
            let classified = if file_type.is_file() {
                self.admit_root(&slot)?
            } else {
                Err(BrokenRootReason::NotRegularFile)
            };
            match classified {
                Ok(entry) => {
                    self.visible.insert(slot, entry);
                }
                Err(reason) => {
                    self.broken_slots.insert(slot);
                    report.broken_roots.push(BrokenRoot {
                        path: relative,
                        reason,
                    });
                }
            }
        }
        if self.visible.len() > self.limits.max_roots {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Roots,
                current: self.visible.len(),
                maximum: self.limits.max_roots,
            });
        }
        Ok(())
    }

    /// Fully verifies one root record found on open.
    fn admit_root(
        &mut self,
        slot: &SlotName,
    ) -> Result<Result<RootEntry, BrokenRootReason>, LocalPublicationError> {
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        let Some(bytes) = read_bounded(&path, MAX_ROOT_RECORD_BYTES)? else {
            return Ok(Err(BrokenRootReason::RecordTooLarge));
        };
        let decoded = match record::decode_root_record(&bytes) {
            Ok(decoded) => decoded,
            Err(reason) => return Ok(Err(reason)),
        };
        if decoded.slot != slot.as_str() {
            return Ok(Err(BrokenRootReason::SlotMismatch));
        }
        let root = decoded.root;
        if let Err(reason) = self.verify_reference(root)? {
            return Ok(Err(BrokenRootReason::ReferenceBlocked {
                object: root,
                role: ReferenceRole::ManifestBody,
                reason,
            }));
        }
        let body = self
            .spool
            .read(root)
            .map_err(|error| self.spool_error(error))?;
        let manifest = match ObjectManifest::from_canonical_bytes(&body) {
            Ok(manifest) if manifest.root() == root => manifest,
            _ => return Ok(Err(BrokenRootReason::ManifestUndecodable)),
        };
        let child_count = manifest.children().len();
        if decoded.child_count != child_count as u64 {
            return Ok(Err(BrokenRootReason::ChildCountMismatch {
                recorded: decoded.child_count,
                actual: child_count,
            }));
        }
        if child_count > self.limits.max_children {
            return Ok(Err(BrokenRootReason::ChildBoundExceeded {
                count: child_count,
                maximum: self.limits.max_children,
            }));
        }
        for child in manifest.children() {
            let role = if manifest.metadata_digest() == Some(*child) {
                ReferenceRole::Metadata
            } else {
                ReferenceRole::Child
            };
            if let Err(reason) = self.verify_reference(*child)? {
                return Ok(Err(BrokenRootReason::ReferenceBlocked {
                    object: *child,
                    role,
                    reason,
                }));
            }
        }
        Ok(Ok(RootEntry {
            visible: VisibleRoot {
                slot: slot.clone(),
                root,
                record_digest: ContentDigest::sha256(&bytes),
                child_count,
                state: LocalPublicationState::Visible,
            },
            children: manifest.children().to_vec(),
        }))
    }
}

fn io_error(operation: LocalIoOperation, path: &Path, error: &io::Error) -> LocalPublicationError {
    LocalPublicationError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

fn acquire_lock(root: &Path) -> Result<File, LocalPublicationError> {
    let path = root.join(LOCAL_LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(LocalPublicationError::InvalidLayout { path });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error| io_error(LocalIoOperation::OpenLock, &path, &error))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(LocalPublicationError::Locked { path }),
        Err(TryLockError::Error(error)) => Err(io_error(LocalIoOperation::Lock, &path, &error)),
    }
}

fn ensure_subdirectory(path: &Path) -> Result<(), LocalPublicationError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(LocalIoOperation::CreateDirectory, path, &error)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(LocalIoOperation::Inspect, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn scan_directory(
    dir: &Path,
    bound: usize,
) -> Result<Vec<(OsString, fs::FileType)>, LocalPublicationError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
    let mut found = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
        if found.len() >= bound {
            return Err(LocalPublicationError::EntryLimit {
                directory: dir.to_path_buf(),
                maximum: bound,
            });
        }
        let file_type = entry
            .file_type()
            .map_err(|error| io_error(LocalIoOperation::Inspect, &entry.path(), &error))?;
        found.push((entry.file_name(), file_type));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

/// Reads at most `limit` bytes; `Ok(None)` means the file is longer than `limit`.
fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, LocalPublicationError> {
    let file =
        File::open(path).map_err(|error| io_error(LocalIoOperation::ReadRecord, path, &error))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
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
