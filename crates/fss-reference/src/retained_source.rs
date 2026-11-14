#![forbid(unsafe_code)]
//! Bounded immutable access to retained import custody.
//!
//! Opening this owner reads existing metadata through native journal inspectors. It never
//! constructs a publisher, acquires a writer lock, repairs a tail, or creates a filesystem
//! entry. Source bytes are read only by an explicitly admitted consumer, through the native
//! content-addressed verifier, under the same non-replenishing allowance as metadata and
//! final revalidation. Read authority is not inferred from the presence of a deployment.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fss_core::{
    CanonicalEncode, ContentDigest, EventHypothesis, EvidenceDeltaBatch, LedgerAnchor,
    LedgerSnapshot, Plane,
};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName, root_record_bytes};

use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, HistoryPosition,
    MetadataReadBudget, OrientLimits,
};
use crate::ingest::{FileIngestError, retained::MAX_RETAINED_PAYLOAD_BYTES};
use crate::{ReferenceDeployment, ReplayCx};

const STAGE: &str = "retained_source:read";
static NEVER_CANCEL: fn() -> bool = || false;

mod sealed {
    pub trait Sealed {}
}

/// Exact snapshot bounds and the aggregate allowance for one immutable source owner.
///
/// `max_read_objects` counts attempted payload reads, including metadata files and
/// publication records. It does not count filesystem stat/open syscalls. Byte accounting is
/// payload bytes returned by successful bounded readers; failed reads permanently poison
/// the allowance, so their possibly consumed allowance is never reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableRetainedReadLimits {
    /// Native metadata reconstruction bounds.
    pub snapshot: OrientLimits,
    /// Aggregate payload byte allowance, shared through final revalidation.
    pub max_read_bytes: usize,
    /// Aggregate payload read-attempt allowance, shared through final revalidation.
    pub max_read_objects: usize,
}

/// Payload I/O consumed by an immutable owner, without filesystem framing or syscall claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedReadUsage {
    /// Payload bytes returned by successful native bounded reads.
    pub read_bytes: u64,
    /// Attempted payload reads, including metadata and final revalidation.
    pub read_objects: u64,
}

/// Borrowed committed authority. No journal handle or mutation method escapes this facade.
#[derive(Clone, Copy, Debug)]
pub struct RetainedLedger<'a> {
    current: &'a LedgerSnapshot,
    batches: &'a [EvidenceDeltaBatch],
}
impl<'a> RetainedLedger<'a> {
    /// Native replayed authority state.
    #[must_use]
    pub fn current(self) -> &'a LedgerSnapshot {
        self.current
    }

    /// Canonical committed batches in their original order.
    #[must_use]
    pub fn batches(self) -> &'a [EvidenceDeltaBatch] {
        self.batches
    }
}

/// Pure history view. It cannot reopen metadata, hydrate objects or replenish read authority.
#[derive(Clone, Copy, Debug)]
pub struct RetainedHistory<'a>(&'a DeploymentHistory);

impl<'a> RetainedHistory<'a> {
    /// Exact committed head observed by this owner.
    #[must_use]
    pub fn head(&self) -> HistoryPosition {
        self.0.head()
    }

    /// The exact authority and both journal roots at a committed position.
    #[must_use]
    pub fn roots_at(
        &self,
        position: HistoryPosition,
    ) -> Option<(fss_core::LedgerAnchor, ContentDigest, ContentDigest)> {
        self.0.roots_at(position)
    }

    /// Whether the opening history contains this committed position.
    #[must_use]
    pub fn contains(&self, position: HistoryPosition) -> bool {
        self.0.contains(position)
    }

    /// Site lineage retained in the canonical deployment layout.
    #[must_use]
    pub fn site_lineage(&self) -> &'a str {
        self.0.site_lineage()
    }

    /// Exact content-addressed namespace from the verified deployment layout.
    #[must_use]
    pub fn replay_objects_root(&self) -> &'a Path {
        self.0.replay_objects_root()
    }

    /// Metadata limits used to reconstruct this owner.
    #[must_use]
    pub fn limits(&self) -> &'a OrientLimits {
        self.0.limits()
    }

    /// Digest of the exact deployment layout observed at open.
    #[must_use]
    pub fn layout_digest(&self) -> ContentDigest {
        self.0.metadata_layout_digest()
    }
}

/// Shared sealed read contract used by operational and immutable retained-source consumers.
///
/// Implementations expose exact native authority and bounded verified object reads. This
/// interface deliberately contains no publisher, staging spool, recovery, or writer handle.
pub trait RetainedSource: sealed::Sealed {
    /// Exact deployment namespace bound to the read authority.
    fn root(&self) -> &Path;
    /// Committed authority supplied by the native ledger owner.
    fn ledger(&self) -> RetainedLedger<'_>;
    /// Site lineage from the exact committed authority snapshot.
    fn site_lineage(&self) -> &str {
        &self.current_anchor().site_lineage
    }
    /// Exact opening authority anchor; this method performs no I/O.
    fn current_anchor(&self) -> &LedgerAnchor {
        &self.ledger().current().anchor
    }
    /// Refuse an authority change using this owner's original read allowance.
    fn verify_read_head(&self) -> Result<(), FileIngestError>;
    /// Maximum native tombstone entries inspected by one custody lookup.
    fn tombstone_lookup_work(&self) -> u64;
    /// Read one content-addressed payload within an explicit allocation bound.
    fn read_object_bounded(
        &self,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, FileIngestError>;
    /// Refuse deleted, tombstoned or unverifiable source custody.
    fn check_object_available(&self, digest: ContentDigest) -> Result<(), FileIngestError>;
    /// Verify one exact current publication record, including its child count.
    fn check_publication(
        &self,
        slot: &SlotName,
        root: ContentDigest,
        children: usize,
    ) -> Result<(), FileIngestError>;
    /// Resolve committed deletion authority before interpreting import metadata.
    fn refuse_deleted_import(&self, identity: ContentDigest) -> Result<(), FileIngestError>;

    /// Read an existing bounded retained payload. Callers with a narrower native bound use
    /// `read_object_bounded` instead.
    fn read_object(&self, digest: ContentDigest) -> Result<Vec<u8>, FileIngestError> {
        self.read_object_bounded(digest, MAX_RETAINED_PAYLOAD_BYTES as usize)
    }
}

impl sealed::Sealed for ReferenceDeployment {}
impl RetainedSource for ReferenceDeployment {
    fn root(&self) -> &Path {
        ReferenceDeployment::root(self)
    }

    fn ledger(&self) -> RetainedLedger<'_> {
        RetainedLedger {
            current: ReferenceDeployment::ledger(self).current(),
            batches: ReferenceDeployment::ledger(self).batches(),
        }
    }

    fn verify_read_head(&self) -> Result<(), FileIngestError> {
        self.ledger()
            .verify_durable_head()
            .map_err(crate::ReferenceError::from)?;
        Ok(())
    }

    fn tombstone_lookup_work(&self) -> u64 {
        self.publisher().limits().max_tombstones as u64
    }

    fn read_object_bounded(
        &self,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.check_object_available(digest)?;
        Ok(self.publisher().spool().read_bounded(digest, maximum)?)
    }

    fn check_object_available(&self, digest: ContentDigest) -> Result<(), FileIngestError> {
        if self.publisher().tombstones().any(|held| *held == digest) {
            return Err(corrupt("retained object is tombstoned"));
        }
        Ok(())
    }

    fn check_publication(
        &self,
        slot: &SlotName,
        root: ContentDigest,
        children: usize,
    ) -> Result<(), FileIngestError> {
        let visible = self
            .publisher()
            .root(slot)
            .ok_or_else(|| corrupt("retained publication is absent"))?;
        if visible.state != LocalPublicationState::Durable
            || visible.root != root
            || visible.child_count != children
        {
            return Err(corrupt("retained publication differs from its authority"));
        }
        Ok(())
    }

    fn refuse_deleted_import(&self, identity: ContentDigest) -> Result<(), FileIngestError> {
        crate::ingest::retained::refuse_deleted(self, identity)
    }
}

/// One root-bound immutable read session with one shared, non-replenishing allowance.
///
/// The borrowed cancellation probe may bind a canonical query permit's principal, request,
/// capabilities and deadline. It is checked before every payload read. `revalidate` ends
/// with a pure comparison against the final native authority observation; it does not invoke
/// caller code after that observation.
pub struct ImmutableRetainedSource<'a> {
    root: PathBuf,
    limits: ImmutableRetainedReadLimits,
    cx: &'a ReplayCx,
    cancelled: &'a (dyn Fn() -> bool + Sync),
    history: DeploymentHistory,
    snapshot: DeploymentSnapshot,
    budget: MetadataReadBudget,
    objects: RefCell<BTreeMap<ContentDigest, usize>>,
    custody: RefCell<BTreeSet<ContentDigest>>,
    publications: RefCell<BTreeMap<SlotName, (ContentDigest, usize)>>,
}

impl<'a> ImmutableRetainedSource<'a> {
    /// Opens existing retained custody under an explicit replay authority.
    pub fn open(
        root: &Path,
        limits: ImmutableRetainedReadLimits,
        cx: &'a ReplayCx,
    ) -> Result<Self, FileIngestError> {
        Self::open_cancellable(root, limits, cx, &NEVER_CANCEL)
    }

    /// Opens with the caller's live cancellation/admission probe, before any filesystem read.
    pub fn open_cancellable(
        root: &Path,
        limits: ImmutableRetainedReadLimits,
        cx: &'a ReplayCx,
        cancelled: &'a (dyn Fn() -> bool + Sync),
    ) -> Result<Self, FileIngestError> {
        let budget = MetadataReadBudget::new(limits.max_read_bytes, limits.max_read_objects);
        Self::open_with_metadata_budget(root, limits, cx, cancelled, budget)
    }

    /// Continue an already admitted metadata read without replenishing its allowance. Private
    /// session owners use this after their initial authority projection shares the same budget.
    pub(crate) fn open_with_metadata_budget(
        root: &Path,
        limits: ImmutableRetainedReadLimits,
        cx: &'a ReplayCx,
        cancelled: &'a (dyn Fn() -> bool + Sync),
        budget: MetadataReadBudget,
    ) -> Result<Self, FileIngestError> {
        if root != cx.root_dir() {
            return Err(corrupt(
                "immutable retained root differs from read authority",
            ));
        }
        if limits.max_read_bytes == 0
            || limits.max_read_objects == 0
            || limits.snapshot.max_layout_bytes == 0
            || limits.snapshot.max_journal_bytes == 0
            || limits.snapshot.max_object_bytes == 0
        {
            return Err(FileIngestError::InvalidLimits {
                detail: "immutable retained read allowances must be positive".to_owned(),
            });
        }
        let admission = || cancelled() || cx.checkpoint(STAGE).is_err();
        if admission() {
            return Err(cancelled_error());
        }
        let history = DeploymentHistory::read_metadata_cancellable(
            root,
            &limits.snapshot,
            &budget,
            &admission,
        )
        .map_err(|error| read_error(&budget, cx, cancelled, error))?;
        if history.has_uncommitted_tail() {
            budget.fail();
            return Err(corrupt(
                "immutable retained history has an uncommitted tail",
            ));
        }
        let snapshot = history
            .snapshot_at_cancellable(history.head(), &admission)
            .map_err(|error| read_error(&budget, cx, cancelled, error))?;
        Ok(Self {
            root: root.to_path_buf(),
            limits,
            cx,
            cancelled,
            history,
            snapshot,
            budget,
            objects: RefCell::new(BTreeMap::new()),
            custody: RefCell::new(BTreeSet::new()),
            publications: RefCell::new(BTreeMap::new()),
        })
    }

    /// Immutable native history observed when the owner opened.
    #[must_use]
    pub fn history(&self) -> RetainedHistory<'_> {
        RetainedHistory(&self.history)
    }

    /// Metadata snapshot at the exact opening authority position.
    #[must_use]
    pub fn snapshot(&self) -> &DeploymentSnapshot {
        &self.snapshot
    }

    /// Rehash every metadata dependency of the opening snapshot under the original allowance.
    ///
    /// This repeats the metadata-only native projection, including non-event coverage, health,
    /// liveness and calibration records. Model receipts and media children remain unopened.
    /// It neither observes a new authority head nor renews read authority: callers must still
    /// withhold their complete output until `revalidate()` performs final custody/head checks.
    pub fn revalidate_snapshot_metadata(&self) -> Result<(), FileIngestError> {
        self.admit()?;
        let mut current = self
            .history
            .snapshot_at_cancellable(self.history.head(), &|| self.admission_cancelled())
            .map_err(|error| read_error(&self.budget, self.cx, self.cancelled, error))?;
        // Counter fields measure individual passes; equality concerns their complete metadata.
        current.bytes_read = self.snapshot.bytes_read;
        current.files_read = self.snapshot.files_read;
        if current != self.snapshot {
            self.budget.fail();
            return Err(corrupt(
                "immutable retained snapshot metadata changed during the read",
            ));
        }
        Ok(())
    }

    /// Aggregate successful payload bytes and attempted payload reads.
    #[must_use]
    pub fn usage(&self) -> RetainedReadUsage {
        let (read_bytes, read_objects) = self.budget.consumed();
        RetainedReadUsage {
            read_bytes,
            read_objects,
        }
    }

    fn admit(&self) -> Result<(), FileIngestError> {
        if (self.cancelled)() || self.cx.checkpoint(STAGE).is_err() {
            self.budget.fail();
            return Err(cancelled_error());
        }
        self.budget
            .ensure_valid()
            .map_err(|_| corrupt("immutable retained read allowance is no longer usable"))
    }

    fn admission_cancelled(&self) -> bool {
        (self.cancelled)() || self.cx.checkpoint(STAGE).is_err()
    }

    /// Rehash selected source payloads, recheck custody/publications, then observe authority.
    ///
    /// The same allowance covers this entire pass. A changed root, journal tail, authority
    /// position, publication, object, deletion or cancellation refuses the complete result.
    pub fn revalidate(&self) -> Result<(), FileIngestError> {
        self.admit()?;
        let objects = self.objects.borrow().clone();
        let custody = self.custody.borrow().clone();
        let publications = self.publications.borrow().clone();
        for (digest, length) in objects {
            let _ = self.read_object_bounded(digest, length)?;
        }
        for digest in custody {
            self.check_object_available(digest)?;
        }
        for (slot, (root, children)) in publications {
            self.check_publication(&slot, root, children)?;
        }
        self.verify_read_head()
    }

    fn revalidate_authority(&self) -> Result<(), FileIngestError> {
        self.admit()?;
        let current = DeploymentHistory::read_metadata_cancellable(
            &self.root,
            &self.limits.snapshot,
            &self.budget,
            &|| self.admission_cancelled(),
        )
        .map_err(|error| read_error(&self.budget, self.cx, self.cancelled, error))?;
        // No caller callback follows the final authority observation.
        if current.has_uncommitted_tail()
            || current.metadata_layout_digest() != self.history.metadata_layout_digest()
            || current.site_lineage() != self.history.site_lineage()
            || current.replay_objects_root() != self.history.replay_objects_root()
            || current.head() != self.history.head()
            || current.roots_at(current.head()) != self.history.roots_at(self.history.head())
        {
            self.budget.fail();
            return Err(corrupt(
                "immutable retained authority changed during the read",
            ));
        }
        self.budget
            .ensure_valid()
            .map_err(|_| corrupt("immutable retained read allowance is no longer usable"))
    }
}

impl sealed::Sealed for ImmutableRetainedSource<'_> {}
impl RetainedSource for ImmutableRetainedSource<'_> {
    fn root(&self) -> &Path {
        &self.root
    }

    fn ledger(&self) -> RetainedLedger<'_> {
        RetainedLedger {
            current: self.history.retained_ledger_snapshot(),
            batches: self.history.batches_through_head(),
        }
    }

    fn verify_read_head(&self) -> Result<(), FileIngestError> {
        self.revalidate_authority()
    }

    fn tombstone_lookup_work(&self) -> u64 {
        // Native immutable custody checks inspect the digest's exact tombstone path.
        1
    }

    fn read_object_bounded(
        &self,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, FileIngestError> {
        self.check_object_available(digest)?;
        let maximum = self
            .budget
            .allowance(maximum.min(MAX_RETAINED_PAYLOAD_BYTES as usize))
            .map_err(|_| {
                self.budget.fail();
                corrupt("immutable retained aggregate read allowance exhausted")
            })?;
        let bytes =
            fss_publication::read_verified(self.history.replay_objects_root(), digest, maximum)
                .map_err(|error| {
                    self.budget.fail();
                    FileIngestError::from(error)
                })?;
        self.budget.charge(bytes.len()).map_err(|_| {
            self.budget.fail();
            corrupt("immutable retained aggregate read allowance exhausted")
        })?;
        self.objects.borrow_mut().insert(digest, bytes.len());
        Ok(bytes)
    }

    fn check_object_available(&self, digest: ContentDigest) -> Result<(), FileIngestError> {
        self.admit()?;
        if self.snapshot.deletions.object(digest).is_some() {
            self.budget.fail();
            return Err(corrupt("retained object has committed deletion authority"));
        }
        self.history
            .wait_check_tombstone(digest)
            .map_err(|error| read_error(&self.budget, self.cx, self.cancelled, error))?;
        let mut custody = self.custody.borrow_mut();
        if !custody.contains(&digest) && custody.len() >= self.limits.max_read_objects {
            self.budget.fail();
            return Err(corrupt(
                "immutable retained custody index exceeds its bound",
            ));
        }
        custody.insert(digest);
        Ok(())
    }

    fn check_publication(
        &self,
        slot: &SlotName,
        root: ContentDigest,
        children: usize,
    ) -> Result<(), FileIngestError> {
        self.admit()?;
        if self
            .snapshot
            .deletions
            .unit_deleted(&format!("slot:{slot}"))
        {
            self.budget.fail();
            return Err(corrupt(
                "retained publication has committed deletion authority",
            ));
        }
        let expected = root_record_bytes(slot, root, children)?;
        let actual = self
            .history
            .wait_read_publication_cancellable(slot, expected.len(), &|| self.admission_cancelled())
            .map_err(|error| read_error(&self.budget, self.cx, self.cancelled, error))?;
        if actual != expected {
            self.budget.fail();
            return Err(corrupt("retained publication differs from its authority"));
        }
        self.publications
            .borrow_mut()
            .insert(slot.clone(), (root, children));
        Ok(())
    }

    fn refuse_deleted_import(&self, identity: ContentDigest) -> Result<(), FileIngestError> {
        self.admit()?;
        match self.snapshot.deletions.import(identity) {
            Some(entry) => {
                self.budget.fail();
                Err(FileIngestError::EvidenceDeleted {
                    import_identity: identity,
                    plan_digest: entry.plan_digest,
                })
            }
            None => Ok(()),
        }
    }
}

/// Verify and retain one complete committed event lineage under this owner's read allowance.
///
/// Only event manifests and canonical revision metadata are opened. Their declared model,
/// evidence and source children remain metadata handles, without new read authority. Every
/// selected payload and witness is registered for the caller's final `revalidate` pass.
/// Returned rows are publication-root/commit-sequence pairs in canonical revision order.
///
/// # Errors
///
/// Refuses empty or invalid chains, unmatched committed declarations, changed canonical
/// metadata, unavailable custody and exhausted read allowances. The caller must withhold
/// derived output until `owner.revalidate()` succeeds under the same authority.
pub fn verify_event_lineage(
    owner: &ImmutableRetainedSource<'_>,
    revisions: &[EventHypothesis],
    maximum: usize,
) -> Result<Vec<(ContentDigest, u64)>, FileIngestError> {
    let first = revisions
        .first()
        .ok_or_else(|| corrupt("event lineage is empty"))?;
    EventHypothesis::verify_chain(revisions)
        .map_err(|_| corrupt("event lineage chain is invalid"))?;
    let object = format!("object:event:{}", first.event_id.as_str());
    let mut publications = Vec::with_capacity(revisions.len());
    for batch in owner.ledger().batches() {
        for delta in &batch.deltas {
            if delta.family != "event_revision" || delta.object_id.as_str() != object {
                continue;
            }
            let revision = revisions
                .get(publications.len())
                .ok_or_else(|| corrupt("event lineage has additional committed revisions"))?;
            if delta.plane != Plane::Authority
                || delta.new_generation != revision.revision
                || delta.prior_generation
                    != revision.revision.checked_sub(1).filter(|prior| *prior != 0)
                || delta.witness_digest != Some(revision.revision_digest())
                || delta.validity != revision.interval
                || delta.operation_id.is_some()
            {
                return Err(corrupt("event lineage differs from committed authority"));
            }
            let bytes = owner.read_object_bounded(delta.payload_digest, maximum)?;
            let manifest = ObjectManifest::from_canonical_bytes(&bytes)
                .map_err(|_| corrupt("event lineage manifest is invalid"))?;
            let payload = manifest
                .metadata_digest()
                .ok_or_else(|| corrupt("event lineage manifest has no metadata"))?;
            let mut receipts = revision.model_receipts.clone();
            receipts.push(payload);
            receipts.sort_unstable();
            receipts.dedup();
            if manifest.kind() != "event-revision" || manifest.children() != receipts {
                return Err(corrupt("event lineage manifest differs from declared metadata"));
            }
            let retained = owner.read_object_bounded(payload, maximum)?;
            if retained != revision.canonical_bytes() {
                return Err(corrupt("event lineage canonical metadata differs"));
            }
            // The witness is independently bound by the canonical record and committed delta.
            // It is a metadata handle, never permission to open model or source children.
            owner.check_object_available(revision.revision_digest())?;
            publications.push((delta.payload_digest, batch.new_anchor.commit_sequence));
        }
    }
    if publications.len() != revisions.len() {
        return Err(corrupt("event lineage lacks a committed revision"));
    }
    Ok(publications)
}

fn cancelled_error() -> FileIngestError {
    FileIngestError::CancellationRequested { stage: STAGE }
}

fn corrupt(detail: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: detail.to_owned(),
    }
}

fn read_error(
    budget: &MetadataReadBudget,
    cx: &ReplayCx,
    cancelled: &dyn Fn() -> bool,
    _error: DeploymentReadError,
) -> FileIngestError {
    budget.fail();
    if cancelled() || cx.is_cancelled() {
        cancelled_error()
    } else {
        corrupt("immutable retained metadata or custody could not be verified")
    }
}
