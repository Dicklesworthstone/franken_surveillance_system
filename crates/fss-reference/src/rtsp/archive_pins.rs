#![forbid(unsafe_code)]
//! Independently owned disk journal for archive recovery references, not footage or authority.
//!
//! Candidate references are synchronized before acknowledging the existing work barrier.
//! Confirmation never erases the predecessor from history. The caller protects this directory
//! independently of footage custody; checksums detect corruption, not malicious rollback.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::archive_recovery::archive_retirement_digest;
use super::recording_archive::checkpoint::write_ahead::ArchiveCheckpoint;
use super::recording_archive::checkpoint::{
    ArchiveWorkLimits, MAX_ARCHIVE_WORK_BYTES, PreparedArchiveWork, load_archive_work,
};
use super::recording_archive::{ArchiveError, ArchiveRetirement};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_ledger::{IncompleteTailPolicy, Journal, JournalError, RecoveryReport, recover_bytes};
use fss_publication::{
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, SlotName,
};

mod codec;
mod restore;
pub use restore::ArchivePinRestoration;
mod writer;
pub use writer::*;
/// Live capture whose checkpoint acknowledgements follow independent disk synchronization.
pub mod live;

const RECORD_KIND: u16 = 0x4150;
const RECORD_OVERHEAD: usize = 128;
const MAX_PAYLOAD: usize = 1024;
const JOURNAL_FILE: &str = "pins.journal";

/// Explicit journal identity and the only archive namespace whose pins it may retain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivePinScope {
    /// Independently selected journal epoch; never inferred from a file's own checksum.
    pub journal_id: ContentDigest,
    /// Exact ArchiveNamespace::digest(), including sensor, generation and clock bases.
    pub archive_namespace: ContentDigest,
}
/// Independent recovery and append bounds; reaching them never removes old records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivePinLimits {
    /// Complete committed records including genesis, at most 16,384.
    pub max_records: usize,
    /// All framing and payload bytes, at most 16 MiB, including a possible incomplete tail.
    pub max_bytes: usize,
}
impl Default for ArchivePinLimits {
    fn default() -> Self {
        Self {
            max_records: 8193,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}
impl ArchivePinLimits {
    fn validate(self) -> PinResult<()> {
        if self.max_records == 0
            || self.max_records > 16_384
            || self.max_bytes < RECORD_OVERHEAD
            || self.max_bytes > 16 * 1024 * 1024
        {
            return Err(ArchivePinError::Limit);
        }
        Ok(())
    }
}
/// Independently retained minimum prefix. Recovery may accept verified descendants after a
/// lost acknowledgement, but never a shorter/different prefix. It is not a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivePinAnchor {
    /// One-based committed record sequence.
    pub sequence: u64,
    /// Exact existing Journal frame root at that sequence.
    pub root: ContentDigest,
}
/// Bounded restart metadata reconstructed without a former process's Rust objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredArchivePin {
    slot: SlotName,
    root: ContentDigest,
    retirement: ContentDigest,
    new_payload_bytes: usize,
}
impl StoredArchivePin {
    /// Exact work slot, not a latest-pointer lookup.
    pub fn slot(&self) -> &SlotName {
        &self.slot
    }
    /// Exact complete work-root identity.
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Existing archive retirement identity; no parallel resumption protocol.
    pub fn retirement_digest(&self) -> ContentDigest {
        self.retirement
    }
    /// Original complete work quote, excluding existing historical media.
    pub fn new_payload_bytes(&self) -> usize {
        self.new_payload_bytes
    }
    fn checkpoint(pin: &ArchiveCheckpoint) -> Self {
        Self {
            slot: pin.slot().clone(),
            root: pin.root(),
            retirement: pin.retirement_digest(),
            new_payload_bytes: pin.new_payload_bytes(),
        }
    }
}
/// Distinct recoverable possibilities. A candidate may or may not have reached work durability.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchivePinState {
    candidate: Option<StoredArchivePin>,
    confirmed: Option<StoredArchivePin>,
}
impl ArchivePinState {
    /// Must be reconciled against current source custody; never silently fall back on an error.
    pub fn candidate(&self) -> Option<&StoredArchivePin> {
        self.candidate.as_ref()
    }
    /// Last confirmed work root, retained alongside a newer unconfirmed candidate.
    pub fn last_confirmed(&self) -> Option<&StoredArchivePin> {
        self.confirmed.as_ref()
    }
}
/// What this metadata-only commit proves, separate from normal archive publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchivePinPhase {
    /// Recovery reference persisted; the work root itself might not yet exist.
    Candidate,
    /// Work-root durability verified, then its confirmation persisted.
    Confirmed,
}
/// Produced only after actual journal synchronization or verified exact retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivePinReceipt {
    anchor: ArchivePinAnchor,
    pin: StoredArchivePin,
    phase: ArchivePinPhase,
}
impl ArchivePinReceipt {
    /// Verified committed journal tip containing this state.
    pub fn anchor(&self) -> ArchivePinAnchor {
        self.anchor
    }
    /// Exact checkpoint whose reference was retained.
    pub fn pin(&self) -> &StoredArchivePin {
        &self.pin
    }
    /// Candidate persistence versus confirmed work custody.
    pub fn phase(&self) -> ArchivePinPhase {
        self.phase
    }
}
/// Errors have payload-free diagnostics; original bytes and storage are not cleaned up.
pub enum ArchivePinError {
    /// Existing journal framing, corruption or uncertain append failure.
    Journal(JournalError),
    /// Underlying OS category; no filename or secret argument is printed.
    Io(std::io::ErrorKind),
    /// Bounded current source-custody verification refused.
    Archive(ArchiveError),
    /// Directory or file is missing, symlinked, or not the expected native kind.
    Layout,
    /// The independent journal's exclusive process lock could not be acquired.
    Busy,
    /// Explicit record, byte, payload, or allocation ceiling.
    Limit,
    /// Scope does not match the independently accepted journal/archive identities.
    Scope,
    /// Invalid transition, foreign record, empty history, or reused checkpoint.
    History,
    /// Checkpointed original work has not yet settled at its normal archive slots.
    Unsettled,
    /// The independently pinned prefix, current tip, or historical bytes differ.
    RootMismatch,
    /// Cooperative cancellation or authority/deadline withdrawal.
    Cancelled,
    /// No further acknowledgement may be issued by this failed owner.
    Fenced,
}
impl fmt::Display for ArchivePinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Journal(_) => "archive pin journal requires reconciliation",
            Self::Io(_) => "archive pin I/O refused",
            Self::Archive(_) => "archive pin custody refused",
            Self::Layout => "invalid archive pin layout",
            Self::Busy => "archive pin owner busy",
            Self::Limit => "archive pin bound exceeded",
            Self::Scope => "archive pin scope mismatch",
            Self::History => "invalid archive pin history",
            Self::Unsettled => "archive work requires recovery",
            Self::RootMismatch => "archive pin prefix mismatch",
            Self::Cancelled => "archive pin operation cancelled",
            Self::Fenced => "archive pin owner fenced",
        })
    }
}
impl fmt::Debug for ArchivePinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ArchivePinError {}
impl From<JournalError> for ArchivePinError {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}
impl From<std::io::Error> for ArchivePinError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<ArchiveError> for ArchivePinError {
    fn from(e: ArchiveError) -> Self {
        Self::Archive(e)
    }
}
/// Result retaining typed errors without leaking private filesystem diagnostics.
pub type PinResult<T> = Result<T, ArchivePinError>;

#[derive(Clone, Default, Eq, PartialEq)]
struct ReplayState {
    pins: ArchivePinState,
    seen: Vec<(ContentDigest, ContentDigest)>,
}
/// One exclusive, bounded, metadata-only journal in a separately protected directory.
///
/// Uses the existing fss-ledger Journal's body-sync/commit-sync protocol, plus an actual
/// sidecar process lock and synchronized directory entries. No source pixels, credentials,
/// mutable head file, filesystem repair, retention policy, or network authority is stored.
/// Paths and their ancestors must be trusted: this is not a hostile-directory sandbox.
#[must_use]
pub struct ArchivePinJournal {
    journal: Journal,
    // Separate lock file: locking the journal itself would conflict with its second I/O handle
    // on platforms with mandatory file locks. Keep this handle alive until after Journal drops.
    _lock: File,
    scope: ArchivePinScope,
    limits: ArchivePinLimits,
    replay: ReplayState,
    records: usize,
    fenced: bool,
}
impl fmt::Debug for ArchivePinJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivePinJournal")
            .field("records", &self.records)
            .field("fenced", &self.fenced)
            .finish_non_exhaustive()
    }
}
impl ArchivePinJournal {
    /// Create a NEW directory and genesis only. Existing directories are never adopted or
    /// erased. Failure may leave an incomplete directory for explicit inspection, not reuse.
    pub fn create(
        directory: impl AsRef<Path>,
        scope: ArchivePinScope,
        limits: ArchivePinLimits,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<Self> {
        limits.validate()?;
        codec::validate_scope(scope)?;
        check(cancel)?;
        let payload = codec::encode(scope, 0, None)?;
        capacity(0, 0, payload.len(), limits)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory.as_ref())?;
        let dir = fs::canonicalize(directory.as_ref())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("LOCK"))?;
        acquire_lock(&lock)?;
        lock.sync_all()?;
        let path = dir.join(JOURNAL_FILE);
        let initial = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        initial.sync_all()?;
        drop(initial);
        check(cancel)?;
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        journal.append(RECORD_KIND, &payload)?;
        File::open(&dir)?.sync_all()?;
        File::open(dir.parent().ok_or(ArchivePinError::Layout)?)?.sync_all()?;
        check(cancel)?;
        Ok(Self {
            journal,
            _lock: lock,
            scope,
            limits,
            replay: ReplayState::default(),
            records: 1,
            fenced: false,
        })
    }
    /// Open only an existing protected directory. Validate scope, transitions, ceilings and
    /// the optional independent minimum prefix BEFORE any explicit torn-tail truncation.
    /// Reject is the ordinary policy. Truncate is an explicit repair choice, never automatic.
    /// Recovered complete records are synchronized before any acknowledgement can be returned.
    pub fn open_existing(
        directory: impl AsRef<Path>,
        scope: ArchivePinScope,
        minimum: Option<ArchivePinAnchor>,
        limits: ArchivePinLimits,
        tail: IncompleteTailPolicy,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<Self> {
        limits.validate()?;
        codec::validate_scope(scope)?;
        check(cancel)?;
        let (dir, lock) = existing(directory.as_ref())?;
        let path = dir.join(JOURNAL_FILE);
        let report = read_report(&path, limits, cancel)?;
        let replay = codec::replay(&report, scope, limits)?;
        if let Some(minimum) = minimum
            && (minimum.sequence == 0
                || !report
                    .records()
                    .iter()
                    .any(|r| r.sequence() == minimum.sequence && r.root() == minimum.root))
        {
            return Err(ArchivePinError::RootMismatch);
        }
        check(cancel)?;
        let journal = Journal::open(&path, tail)?;
        if journal.last_root() != report.last_root()
            || journal.committed_len() != report.committed_len()
        {
            return Err(ArchivePinError::RootMismatch);
        }
        OpenOptions::new().write(true).open(&path)?.sync_all()?;
        File::open(&dir)?.sync_all()?;
        check(cancel)?;
        Ok(Self {
            journal,
            _lock: lock,
            scope,
            limits,
            replay,
            records: report.records().len(),
            fenced: false,
        })
    }
    /// Accepted independent scope; it grants no source access or camera permission.
    pub fn scope(&self) -> ArchivePinScope {
        self.scope
    }
    /// Last acknowledged metadata prefix. When fenced, an attempted append may also exist.
    pub fn anchor(&self) -> ArchivePinAnchor {
        ArchivePinAnchor {
            sequence: self.records as u64,
            root: self.journal.last_root(),
        }
    }
    /// Candidate and predecessor from the last acknowledged committed prefix.
    pub fn state(&self) -> &ArchivePinState {
        &self.replay.pins
    }
    /// Whether this owner requires explicit close/reopen and reconciliation.
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
    /// Rehash and replay the complete bounded history against the open owner. No writes.
    /// Even an exact retry must pass this check; an old receipt does not mask damaged storage.
    pub fn verify(&mut self, cancel: &dyn PublishCancellation) -> PinResult<()> {
        if self.fenced {
            return Err(ArchivePinError::Fenced);
        }
        let result = (|| {
            let report = read_report(self.journal.path(), self.limits, cancel)?;
            if report.incomplete_tail().is_some()
                || report.last_root() != self.journal.last_root()
                || report.committed_len() != self.journal.committed_len()
                || report.records().len() != self.records
                || codec::replay(&report, self.scope, self.limits)? != self.replay
            {
                return Err(ArchivePinError::RootMismatch);
            }
            Ok(())
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Bounded path/length/final-trailer check for the live loop. Full historical replay still
    /// runs on every new candidate and confirmation. A removed/replaced/torn tip fences intake.
    pub fn verify_tip(&mut self, cancel: &dyn PublishCancellation) -> PinResult<()> {
        if self.fenced {
            return Err(ArchivePinError::Fenced);
        }
        let result = (|| {
            check(cancel)?;
            if !fs::symlink_metadata(self.journal.path())?.is_file() {
                return Err(ArchivePinError::Layout);
            }
            self.journal.verify_committed_tail()?;
            check(cancel)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    /// Synchronize an opaque checkpoint from the existing barrier before acknowledging it.
    /// An identical current candidate is an idempotent read, not another journal record.
    pub fn persist_candidate(
        &mut self,
        pin: &ArchiveCheckpoint,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchivePinReceipt> {
        self.persist(
            StoredArchivePin::checkpoint(pin),
            ArchivePinPhase::Candidate,
            cancel,
        )
    }
    /// Reconcile a cold candidate against current complete work/source custody, then record its
    /// confirmation. An absent, damaged or deleted work root is an error, never an implicit
    /// fallback or permission to clear the candidate. This performs no archive publication.
    pub fn confirm_recovered(
        &mut self,
        publisher: &LocalRootPublisher,
        bounds: ArchiveWorkLimits,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchivePinReceipt> {
        let _ = self.load_work(ArchivePinPhase::Candidate, publisher, bounds, cancel)?;
        let pin = self
            .replay
            .pins
            .candidate
            .clone()
            .ok_or(ArchivePinError::History)?;
        self.persist(pin, ArchivePinPhase::Confirmed, cancel)
    }
    /// Explicitly choose candidate or last-confirmed work, without silently falling back when
    /// the chosen root is missing, corrupt or superseded. Returns the existing recovery input.
    pub fn load_work(
        &mut self,
        which: ArchivePinPhase,
        publisher: &LocalRootPublisher,
        bounds: ArchiveWorkLimits,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchiveRetirement> {
        self.verify(cancel)?;
        let selected = match which {
            ArchivePinPhase::Candidate => self.replay.pins.candidate.as_ref(),
            ArchivePinPhase::Confirmed => self.replay.pins.confirmed.as_ref(),
        };
        let pin = selected.ok_or(ArchivePinError::History)?;
        let work = load_archive_work(publisher, &pin.slot, pin.root, bounds, cancel)?;
        if work.snapshot.namespace().digest() != self.scope.archive_namespace
            || archive_retirement_digest(&work)? != pin.retirement
            || PreparedArchiveWork::prepare(&work, publisher, bounds, cancel)?.new_payload_bytes()
                != pin.new_payload_bytes
        {
            return Err(ArchivePinError::Scope);
        }
        Ok(work)
    }
    /// Admission for a new writer/capture attempt. A confirmed work bundle alone is NOT proof
    /// its normal archive publications settled. Reconcile them before accepting fresh input.
    /// Unconfirmed candidates always block, even if their root might already be durable.
    pub fn require_settled(
        &mut self,
        publisher: &LocalRootPublisher,
        bounds: ArchiveWorkLimits,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<()> {
        self.verify(cancel)?;
        if self.replay.pins.candidate.is_some() {
            return Err(ArchivePinError::Unsettled);
        }
        if self.replay.pins.confirmed.is_none() {
            return Ok(());
        }
        let work = self.load_work(ArchivePinPhase::Confirmed, publisher, bounds, cancel)?;
        if let Some(window) = &work.pending {
            let slot = work
                .snapshot
                .namespace()
                .window_slot(work.snapshot.windows().len())?;
            if publisher.root(&slot).is_none_or(|r| {
                r.root != window.manifest().root() || r.state != LocalPublicationState::Durable
            }) {
                return Err(ArchivePinError::Unsettled);
            }
        }
        if let Some(page) = &work.prepared_page {
            let slot = work
                .snapshot
                .namespace()
                .page_slot(work.snapshot.indexed_windows())?;
            if publisher.root(&slot).is_none_or(|r| {
                r.root != page.manifest().root() || r.state != LocalPublicationState::Durable
            }) {
                return Err(ArchivePinError::Unsettled);
            }
        }
        check(cancel)
    }
    // Only composition modules inside this pin owner may use a receipt obtained directly from
    // their private checkpointed writer. Public callers must reverify custody above.
    fn confirm_receipt(
        &mut self,
        pin: &ArchiveCheckpoint,
        receipt: &LocalPublicationReceipt,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchivePinReceipt> {
        if receipt.root != pin.root() || receipt.claims.local != LocalPublicationState::Durable {
            return Err(ArchivePinError::History);
        }
        self.persist(
            StoredArchivePin::checkpoint(pin),
            ArchivePinPhase::Confirmed,
            cancel,
        )
    }
    fn persist(
        &mut self,
        pin: StoredArchivePin,
        phase: ArchivePinPhase,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchivePinReceipt> {
        self.verify(cancel)?;
        codec::validate_pin(&pin)?;
        let current = if phase == ArchivePinPhase::Candidate {
            self.replay.pins.candidate.as_ref()
        } else {
            self.replay
                .pins
                .confirmed
                .as_ref()
                .filter(|_| self.replay.pins.candidate.is_none())
        };
        if current == Some(&pin) {
            return Ok(ArchivePinReceipt {
                anchor: self.anchor(),
                pin,
                phase,
            });
        }
        let tag = if phase == ArchivePinPhase::Candidate {
            1
        } else {
            2
        };
        let payload = codec::encode(self.scope, tag, Some(&pin))?;
        let mut next = self.replay.clone();
        codec::apply(&mut next, tag, pin.clone())?;
        capacity(
            self.records,
            self.journal.committed_len(),
            payload.len(),
            self.limits,
        )?;
        check(cancel)?;
        if let Err(error) = self.journal.append(RECORD_KIND, &payload) {
            self.fenced = true;
            return Err(error.into());
        }
        // All transition allocation happened before append; install only a synchronized commit.
        self.records += 1;
        self.replay = next;
        Ok(ArchivePinReceipt {
            anchor: self.anchor(),
            pin,
            phase,
        })
    }
}
fn capacity(records: usize, bytes: u64, payload: usize, limits: ArchivePinLimits) -> PinResult<()> {
    if records >= limits.max_records
        || payload > MAX_PAYLOAD
        || bytes
            .checked_add((payload + RECORD_OVERHEAD) as u64)
            .is_none_or(|n| n > limits.max_bytes as u64)
    {
        return Err(ArchivePinError::Limit);
    }
    Ok(())
}
fn check(cancel: &dyn PublishCancellation) -> PinResult<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        Err(ArchivePinError::Cancelled)
    } else {
        Ok(())
    }
}
fn acquire_lock(file: &File) -> PinResult<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(ArchivePinError::Busy),
        Err(fs::TryLockError::Error(error)) => Err(error.into()),
    }
}
fn existing(path: &Path) -> PinResult<(PathBuf, File)> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(ArchivePinError::Layout);
    }
    let dir = fs::canonicalize(path)?;
    for name in ["LOCK", JOURNAL_FILE] {
        if !fs::symlink_metadata(dir.join(name))?.is_file() {
            return Err(ArchivePinError::Layout);
        }
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("LOCK"))?;
    acquire_lock(&lock)?;
    Ok((dir, lock))
}
fn read_report(
    path: &Path,
    limits: ArchivePinLimits,
    cancel: &dyn PublishCancellation,
) -> PinResult<RecoveryReport> {
    check(cancel)?;
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(ArchivePinError::Layout);
    }
    let mut file = File::open(path)?;
    let bytes = usize::try_from(file.metadata()?.len()).map_err(|_| ArchivePinError::Limit)?;
    if bytes > limits.max_bytes {
        return Err(ArchivePinError::Limit);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(bytes.saturating_add(1))
        .map_err(|_| ArchivePinError::Limit)?;
    file.seek(SeekFrom::Start(0))?;
    file.take(bytes as u64 + 1).read_to_end(&mut data)?;
    if data.len() != bytes {
        return Err(ArchivePinError::RootMismatch);
    }
    let report = recover_bytes(&data)?;
    if report.records().is_empty() || report.records().len() > limits.max_records {
        return Err(ArchivePinError::History);
    }
    check(cancel)?;
    Ok(report)
}

#[cfg(test)]
mod tests;
