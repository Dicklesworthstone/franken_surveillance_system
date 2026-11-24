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
//! Already-held children reuse the spool's fresh digest scan from this same open; the same
//! media object is not rehashed for every root or fixed-point pass. Unheld references still
//! require explicit verification and a durable hold. This is a startup snapshot, not a cache
//! for later reads or publication: those continue to rehash every required object.
//! Records that fail are reported as [`BrokenRoot`] and never admitted. A slot with an
//! indeterminate marker is reported as [`BrokenRootReason::VisibilityIndeterminate`], and its
//! record, if any, is never admitted. Objects not reachable from
//! any admitted root are reported as `unreferenced_objects`; temporary records are reported as
//! `orphaned_temps`. Nothing found on open is deleted implicitly.
//!
//! Every filesystem call the publisher makes, and every call its owned spool makes, goes
//! through one [`fss_object::SpoolIo`] capability. [`LocalRootPublisher::open`] uses
//! [`fss_object::HostSpoolIo`], which performs exactly the host `std::fs` call and does not
//! receive a current `Cx` capability. [`LocalRootPublisher::open_scoped`] accepts a production
//! [`ScopedPublicationIo`] that enforces its immutable root, current authority, and aggregate
//! I/O bounds throughout recovery and the resulting owner's lifetime.
//!
//! # Fault injection
//!
//! Three test seams exist, and none is reachable through [`LocalRootPublisher::open`].
//! [`LocalRootPublisher::inject_crash_at`] arms a crash at a [`PublishCutPoint`]: the call returns
//! [`LocalPublicationError::InjectedCrash`] and the instance behaves as a dead process.
//! [`LocalRootPublisher::open_with_injected_io_fault`] is the only way to arm an
//! [`InjectedIoFault`]: the root rename or the roots-directory fsync after it returns the
//! configured [`std::io::ErrorKind`] instead of touching the filesystem, and the publisher then takes
//! exactly the error path a real failure of that operation takes. The fault is one-shot, and no
//! method arms one on an already open instance. [`LocalRootPublisher::open_with_io`] replaces
//! the host capability for the publisher and its spool together, so a test can count, fail, or
//! interrupt every filesystem call of open, staging, publication, and recovery in one order.

mod classify;
mod error;
mod fs_io;
mod inspect;
mod publish;
mod record;
mod recovery;
mod tombstone;
mod types;
mod writer;

pub use error::{
    BlockReason, CapacityResource, LOCAL_PUBLICATION_ERROR_CODES, LocalIoOperation,
    LocalLimitViolation, LocalPublicationError, LocalPublicationGuidance, ReferenceRole,
    SlotViolation,
};
pub use inspect::{
    inspect, inspect_with_io, inspect_with_ledger_journal, inspect_with_options, read_verified,
    read_verified_with_io,
};
pub use record::{
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_TOMBSTONE_RECORD_DOMAIN,
    MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, MAX_TOMBSTONE_RECORD_BYTES, SlotName,
    root_record_bytes, tombstone_record_bytes,
};
pub use types::{
    BrokenRoot, BrokenRootReason, ClaimStatus, InjectedIoFault, IoFaultPoint, LOCAL_LOCK_FILE,
    LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, LocalInspection,
    LocalPublicationLimits, LocalPublicationReceipt, LocalPublicationState, LocalRecoveryReport,
    MAX_LOCAL_ROOTS, MAX_LOCAL_TOMBSTONES, NeverCancel, PublicationClaims, PublicationTransition,
    PublishCancellation, PublishCutPoint, PublishOutcome, ROOT_INDETERMINATE_SUFFIX,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ScopedPublicationIo, TOMBSTONE_RECORD_SUFFIX,
    TombstoneOutcome, VisibleRoot,
};
pub use writer::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{ContentDigest, TombstoneRecord};
use fss_object::{HostSpoolIo, SpoolError, SpoolIo, SpoolLock, StagingSpool};

use fs_io::{compute_closure, io_error, read_bounded};
use types::RootEntry;

/// Exclusive owner of one root-last local publication directory.
#[derive(Debug)]
pub struct LocalRootPublisher {
    io: Arc<dyn SpoolIo>,
    root: PathBuf,
    roots_dir: PathBuf,
    tombstones_dir: PathBuf,
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
    // The nested spool must release before another publisher can acquire the outer lock.
    _lock: SpoolLock,
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

    /// Opens through a current, root-scoped production capability and its aggregate I/O bounds.
    ///
    /// The ordinary recovery, verification, durable-hold and lock protocol is unchanged. Every
    /// later source read or publication retains this capability; opening another owner must not
    /// replenish its shared accounts. Scope checks surround recovery even when recovery fails,
    /// so a caught I/O denial cannot be misreported as an admitted damaged source. The operation
    /// may create recovery metadata, acquire locks, and fsync; it is not a read-only inspection.
    pub fn open_scoped(
        root: impl AsRef<Path>,
        limits: LocalPublicationLimits,
        io: Arc<dyn ScopedPublicationIo>,
    ) -> Result<Self, LocalPublicationError> {
        let root = root.as_ref();
        io.check_scope(root)
            .map_err(|error| io_error(LocalIoOperation::Inspect, root, &error))?;
        let capability: Arc<dyn SpoolIo> = io.clone();
        let result = Self::open_through(root, limits, capability);
        io.check_scope(root)
            .map_err(|error| io_error(LocalIoOperation::Inspect, root, &error))?;
        result
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

    /// Lowers the owned spool's per-object payload bound; never raises it.
    ///
    /// For a borrowed exclusive owner serving a reader whose allocation contract is narrower than
    /// the bound this publisher was opened with. Every later stage and read, including closure and
    /// manifest reads, is capped at the returned effective bound, and [`Self::limits`] reports it.
    /// An admitted object longer than it fails closed on read; nothing is reclassified or removed.
    pub fn tighten_max_object_bytes(&mut self, maximum: usize) -> usize {
        let effective = self.spool.tighten_max_object_bytes(maximum);
        self.limits.spool.max_object_bytes = effective;
        effective
    }

    /// Installs or tightens this owner's non-refillable indexed object read allowance.
    ///
    /// Covers source, metadata, provenance and verification reads through the owned spool.
    /// Accounting starts at the first explicit cap, after opening recovery. Byte reservations
    /// include stored envelope overhead and one trailing-byte probe; metadata/open syscalls,
    /// directory scans and non-indexed staging writes are separate. Further calls only lower
    /// the absolute caps and never refill usage. See [`StagingSpool::tighten_read_budget`].
    pub fn tighten_read_budget(
        &mut self,
        bytes: u64,
        read_attempts: u64,
    ) -> Result<fss_object::SpoolReadBudgetUsage, SpoolError> {
        self.spool.tighten_read_budget(bytes, read_attempts)
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

    /// Number of locally visible roots in this exclusive publisher owner.
    /// This is an in-memory observation, not an independently retained claim.
    #[must_use]
    pub fn visible_root_count(&self) -> usize {
        self.visible.len()
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

    /// Direct children (including metadata) of the root visible in `slot`, if any.
    #[must_use]
    pub fn root_children(&self, slot: &SlotName) -> Option<&[ContentDigest]> {
        self.visible
            .get(slot)
            .map(|entry| entry.children.as_slice())
    }

    /// Arms a one-shot crash point for the next publish call.
    ///
    /// When it fires, the call returns [`LocalPublicationError::InjectedCrash`], leaves the disk
    /// exactly as a process death at that point would, and poisons this instance.
    #[doc(hidden)]
    pub fn inject_crash_at(&mut self, point: PublishCutPoint) {
        self.injected_crash = Some(point);
    }

    /// Arms the spool's one-shot laboratory crash inside the next object stage, before
    /// publication. Reopening observes the same bytes left by that staging cut point.
    #[doc(hidden)]
    pub fn inject_staging_crash_after(&mut self, phase: fss_object::StagePhase) {
        self.spool.inject_crash_after(phase);
    }

    pub(super) fn require_live(&self) -> Result<(), LocalPublicationError> {
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
    pub fn require_durable_record(&self, slot: &SlotName) -> Result<(), LocalPublicationError> {
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

    pub(super) fn spool_error(&mut self, error: SpoolError) -> LocalPublicationError {
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
}

impl fss_object::VerifiedObjectCatalog for LocalRootPublisher {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), fss_object::ObjectError> {
        self.spool.require_verified(digest)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::LocalPublicationError;
    use super::fs_io::record_directory;

    #[test]
    fn tightening_the_object_bound_never_widens_it_and_refuses_larger_admitted_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{LocalPublicationLimits, LocalRootPublisher};
        use fss_object::{SpoolError, SpoolLimits};
        let root = std::env::temp_dir().join(format!(
            "fss-publication-tighten-object-bound-{}",
            std::process::id()
        ));
        let limits = LocalPublicationLimits::new(8, 8, 8, 64, SpoolLimits::new(8, 4096, 256, 64));
        let mut publisher = LocalRootPublisher::open(&root, limits)?;
        let small = publisher.stage_object(&[1; 16])?;
        let large = publisher.stage_object(&[2; 128])?;
        assert_eq!(publisher.tighten_max_object_bytes(1024), 256);
        assert_eq!(publisher.tighten_max_object_bytes(64), 64);
        assert_eq!(publisher.tighten_max_object_bytes(4096), 64);
        assert_eq!(publisher.limits().spool.max_object_bytes, 64);
        assert_eq!(publisher.spool().limits().max_object_bytes, 64);
        assert_eq!(publisher.spool().read(small)?, vec![1; 16]);
        assert!(matches!(
            publisher.spool().read(large),
            Err(SpoolError::Corrupt { digest, .. }) if digest == large
        ));
        assert!(publisher.stage_object(&[3; 65]).is_err());
        drop(publisher);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

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
