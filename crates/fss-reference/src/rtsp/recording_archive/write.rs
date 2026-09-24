#![forbid(unsafe_code)]
//! One retained recording, automatic immutable catalog pages, and explicit retry.

use super::*;
use fss_publication::LocalPublicationReceipt;
use super::super::recording::local::{RecordingProgress, RecordingPublication};

/// Exact rejected original recording remains caller-owned, including under pressure.
#[derive(Debug)]
#[must_use]
pub struct ArchiveWriteRefusal<C: ArchiveCodec = AvcArchiveCodec> {
    /// Typed reason; no source bytes or filesystem paths are printed.
    pub reason: Box<ArchiveError>,
    /// Unconsumed immutable recording, safe to retry or retain separately.
    pub recording: Box<C::Recording>,
}
impl<C: ArchiveCodec> std::fmt::Display for ArchiveWriteRefusal<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.reason) }
}
impl<C: ArchiveCodec> std::error::Error for ArchiveWriteRefusal<C> {}

/// Admission is in-memory ownership transfer, NOT a durability acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveAdmission {
    /// Reserved zero-based ordinal.
    pub ordinal: usize,
    /// Deterministic slot, never replaced by retry.
    pub slot: SlotName,
    /// Exact immutable source-linked recording root.
    pub root: ContentDigest,
}
/// Explicitly distinct custody, indexing, and terminal write states.
#[derive(Debug)]
pub enum ArchiveWriteProgress {
    /// One complete recording was published through the existing local owner.
    /// It remains unindexed until a later CatalogPublished acknowledgement.
    /// Zero-based durable position and the publisher's exact storage receipt.
    WindowDurable {
        /// Ordinal assigned at admission; equals the prior snapshot window count.
        ordinal: usize,
        /// Durable publisher receipt for this window's exact root closure.
        receipt: LocalPublicationReceipt,
    },
    /// Ordinal where the fixed tail page begins and how many windows it holds.
    PageStarted {
        /// Ordinal of the first window on the new page.
        first_ordinal: usize,
        /// Number of windows the new page holds.
        windows: usize,
    },
    /// Reloaded window identity for one catalog page entry.
    PageWindowVerified {
        /// Zero-based ordinal of the verified window.
        ordinal: usize,
        /// Content digest checked against the original recording manifest.
        root: ContentDigest,
    },
    /// Content digest of the prepared catalog page bytes.
    CatalogPrepared {
        /// Digest of the fully prepared catalog page.
        root: ContentDigest,
    },
    /// Content digest of the staged canonical index object.
    CatalogIndexStaged {
        /// Digest of the staged canonical index object.
        digest: ContentDigest,
    },
    /// Ordinal range covered by the page and its durable publisher receipt.
    CatalogPublished {
        /// First window ordinal settled by this page.
        first_ordinal: usize,
        /// Number of windows the published page indexes.
        windows: usize,
        /// Durable publisher receipt for the catalog root.
        receipt: LocalPublicationReceipt,
    },
    /// Acknowledged durable and indexed window counts after this step.
    Ready {
        /// Windows durable in the publisher at this step.
        durable_windows: usize,
        /// Windows represented in the staged index at this step.
        indexed_windows: usize,
    },
    /// Terminal snapshot identity and the totals it accounts for.
    Finished {
        /// Digest over the fully published archive snapshot.
        snapshot_digest: ContentDigest,
        /// Total durable windows in the finished archive.
        windows: usize,
        /// Total immutable catalog pages in the finished archive.
        pages: usize,
    },
    /// Finished was already returned; no new publication or verification occurred.
    Exhausted,
}

struct PendingWindow<C: ArchiveCodec> { recording: C::Recording, entry: CatalogEntry, reservation: usize }

/// Ownership returned on stop. No root or staged source is deleted or retracted.
#[derive(Debug)]
#[must_use]
pub struct ArchiveRetirement<C: ArchiveCodec = AvcArchiveCodec> {
    /// Last acknowledged durable inventory. A failed publication may require owner reconciliation.
    pub snapshot: CodecArchiveSnapshot<C>,
    /// Exact accepted recording whose successful publication was not acknowledged by this driver.
    pub pending: Option<C::Recording>,
    /// Prepared page retained unchanged after cancellation or ambiguous publication.
    pub prepared_page: Option<C::Catalog>,
}

/// Request-owned archive writer over one exclusive, already-open local publisher.
/// It owns at most one pending media window; all other retained state is bounded metadata.
/// Drive step until Ready before requesting more upstream capture output. Before
/// abandoning this value, use retire to transfer any unacknowledged original bytes.
/// No Drop publication, deletion, socket, background task, or retention authority.
pub type RecordingArchiveWriter<'a> = CodecRecordingArchiveWriter<'a, AvcArchiveCodec>;

/// Shared writer; the public aliases pin recording and catalog types before I/O.
#[doc(hidden)]
#[must_use]
pub struct CodecRecordingArchiveWriter<'a, C: ArchiveCodec> {
    publisher: &'a mut LocalRootPublisher,
    snapshot: CodecArchiveSnapshot<C>,
    pending: Option<PendingWindow<C>>,
    builder: Option<C::Builder>,
    build_next: usize,
    flush_end: Option<usize>,
    page: Option<C::Catalog>,
    index_staged: bool,
    flush_requested: bool,
    input_closed: bool,
    deadline_ns: u64,
    last_ns: u64,
    blocked: bool,
    done: bool,
}
impl<'a, C: ArchiveCodec> CodecRecordingArchiveWriter<'a, C> {
    /// Recover exact published windows/pages. A recovered unindexed tail is flushed
    /// BEFORE accepting another window, even when smaller than the configured page.
    /// Open itself performs bounded reads only; step explicitly drives any new writes.
    pub fn open(publisher: &'a mut LocalRootPublisher, namespace: CodecArchiveNamespace<C>,
        limits: ArchiveLimits, now_ns: u64, deadline_ns: u64, cancel: &dyn PublishCancellation)
        -> ArchiveResult<Self>
    {
        if now_ns >= deadline_ns { return Err(ArchiveError::Deadline); }
        let snapshot = CodecArchiveSnapshot::<C>::load(publisher, namespace, limits, cancel)?;
        let tail = snapshot.windows.len() - snapshot.indexed;
        // Reserve the worst-case flat closure, not a hopeful shared-leaf estimate.
        if publisher.limits().max_children < limits.windows_per_page.max(tail) * 5 + 1 {
            return Err(ArchiveError::Limit);
        }
        Ok(Self { publisher, snapshot, pending: None, builder: None, build_next: 0,
            flush_end: None, page: None, index_staged: false, flush_requested: tail != 0,
            input_closed: false, deadline_ns, last_ns: now_ns, blocked: false, done: false })
    }
    /// Read-only inventory of acknowledged durable roots and published pages.
    pub fn snapshot(&self) -> &CodecArchiveSnapshot<C> { &self.snapshot }
    /// Exact retained source after an unsuccessful write; no copying or ownership loss.
    pub fn pending(&self) -> Option<&C::Recording> { self.pending.as_ref().map(|p| &p.recording) }
    /// Admit one immutable window with an explicit complete-payload reservation.
    /// Every refusal returns the same recording, and never advances the ordinal.
    pub fn offer(&mut self, recording: C::Recording, reserved_bytes: usize, now_ns: u64)
        -> Result<ArchiveAdmission, ArchiveWriteRefusal<C>>
    {
        let result = self.prepare_admission(&recording, reserved_bytes, now_ns);
        let entry = match result {
            Ok(entry) => entry,
            Err(reason) => return Err(ArchiveWriteRefusal { reason: Box::new(reason), recording: Box::new(recording) }),
        };
        let admission = ArchiveAdmission { ordinal: self.snapshot.windows.len(), slot: entry.slot().clone(), root: entry.root() };
        self.pending = Some(PendingWindow { recording, entry, reservation: reserved_bytes });
        self.last_ns = now_ns;
        Ok(admission)
    }
    fn prepare_admission(&mut self, recording: &C::Recording, reserved_bytes: usize, now_ns: u64)
        -> ArchiveResult<CatalogEntry>
    {
        self.check_time(now_ns)?;
        if self.blocked { return Err(ArchiveError::Blocked); }
        if self.input_closed { return Err(ArchiveError::Closed); }
        owner_ready(self.publisher)?;
        if self.pending.is_some() || self.flush_requested || self.flush_end.is_some() || self.page.is_some()
            || self.snapshot.windows.len() - self.snapshot.indexed >= self.snapshot.limits.windows_per_page {
            return Err(ArchiveError::Backpressure);
        }
        if self.snapshot.windows.len() == self.snapshot.limits.max_windows
            || self.snapshot.pages.len() == self.snapshot.limits.max_pages
            || C::plan(recording).byte_len() > reserved_bytes { return Err(ArchiveError::Limit); }
        if C::plan(recording).summary().scope != self.snapshot.namespace.scope.recording
            || C::plan(recording).summary().time_scale != self.snapshot.namespace.scope.time_scale { return Err(ArchiveError::Scope); }
        if self.snapshot.windows.iter().any(|e| e.root() == C::plan(recording).manifest().root()) { return Err(ArchiveError::Duplicate); }
        let slot = self.snapshot.namespace.window_slot(self.snapshot.windows.len())?;
        let entry = descriptor_for::<C>(&self.snapshot.namespace.scope, &slot, recording)?;
        if self.snapshot.windows.last().is_some_and(|e| e.decode_interval().end > entry.decode_interval().start) {
            return Err(ArchiveError::Sequence);
        }
        // Allocate acknowledgement metadata before any media publication side effect.
        self.snapshot.windows.try_reserve_exact(1).map_err(|_| ArchiveError::Limit)?;
        self.snapshot.pages.try_reserve_exact(1).map_err(|_| ArchiveError::Limit)?;
        Ok(entry)
    }
    /// Request a smaller immutable page without ending capture. No I/O here.
    pub fn flush(&mut self) { if !self.done { self.flush_requested = true; } }
    /// Stop input admission, then drive step through the pending window and final partial page.
    pub fn finish(&mut self) { self.input_closed = true; self.flush_requested = true; }
    /// Explicit new attempt/lease over the SAME pending bytes and slots. A poisoned
    /// owner cannot be retried in place: retire this driver, reopen/reconcile the owner,
    /// then recover. No ambiguous root is reported as absent or automatically overwritten.
    pub fn retry(&mut self, now_ns: u64, deadline_ns: u64) -> ArchiveResult<()> {
        if now_ns < self.last_ns { return Err(ArchiveError::ClockReversed); }
        if now_ns >= deadline_ns { return Err(ArchiveError::Deadline); }
        if self.done { return Err(ArchiveError::Closed); }
        owner_ready(self.publisher)?;
        if self.builder.is_none() && self.page.is_none() { self.build_next = self.snapshot.indexed; }
        self.last_ns = now_ns; self.deadline_ns = deadline_ns; self.blocked = false;
        Ok(())
    }
    /// One full window publication, one catalog child verification, or one root/index
    /// operation. A full window uses at most five RecordingPublication driver steps;
    /// underlying root-last verification may perform multiple bounded filesystem calls.
    /// Live syscall-time deadline/revocation checks belong in the cancellation probe.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> ArchiveResult<ArchiveWriteProgress> {
        if self.done { return Ok(ArchiveWriteProgress::Exhausted); }
        if self.blocked { return Err(ArchiveError::Blocked); }
        if now_ns < self.last_ns { return Err(ArchiveError::ClockReversed); }
        self.last_ns = now_ns;
        let result = self.check_time(now_ns).and_then(|()| probe(cancel)).and_then(|()| self.advance(now_ns, cancel));
        if result.is_err() { self.blocked = true; }
        result
    }
    fn advance(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> ArchiveResult<ArchiveWriteProgress> {
        owner_ready(self.publisher)?;
        if let Some(pending) = &self.pending {
            let receipt = {
                let mut job = RecordingPublication::new(C::plan(&pending.recording), self.publisher,
                    pending.entry.slot().clone(), pending.reservation, self.deadline_ns)?;
                let mut receipt = None;
                for _ in 0..5 {
                    if let RecordingProgress::Published(value) = job.step(now_ns, cancel)? { receipt = Some(value); break; }
                }
                receipt.ok_or(ArchiveError::Metadata)?
            };
            if receipt.claims.local != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable.into()); }
            let pending = self.pending.take().ok_or(ArchiveError::Metadata)?;
            let ordinal = self.snapshot.windows.len();
            self.snapshot.windows.push(pending.entry);
            // Releasing this in-memory copy never releases the publisher's durable custody.
            return Ok(ArchiveWriteProgress::WindowDurable { ordinal, receipt });
        }
        if let Some(page) = &self.page {
            if !self.index_staged {
                let digest = self.publisher.stage_object(C::index(page)).map_err(RecordingIoError::from)?;
                if Some(digest) != C::manifest(page).metadata_digest() { return Err(ArchiveError::Metadata); }
                self.index_staged = true;
                return Ok(ArchiveWriteProgress::CatalogIndexStaged { digest });
            }
            let first = self.snapshot.indexed;
            let slot = self.snapshot.namespace.page_slot(first)?;
            let receipt = self.publisher.publish_cancellable(&slot, C::manifest(page), cancel)
                .map_err(RecordingIoError::from)?;
            if receipt.claims.local != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable.into()); }
            let catalog = self.page.take().ok_or(ArchiveError::Metadata)?;
            let windows = C::entries(&catalog).len();
            self.snapshot.pages.push(CodecArchivePage::<C> { slot, first, catalog });
            self.snapshot.indexed += windows;
            self.flush_end = None; self.builder = None; self.index_staged = false;
            return Ok(ArchiveWriteProgress::CatalogPublished { first_ordinal: first, windows, receipt });
        }
        if let Some(end) = self.flush_end {
            if self.builder.is_none() {
                self.builder = Some(C::builder(self.snapshot.namespace.scope.clone())?);
                self.build_next = self.snapshot.indexed;
            }
            if self.build_next < end {
                let ordinal = self.build_next; let entry = &self.snapshot.windows[ordinal];
                let recording = C::load_recording(self.publisher, entry.slot(), entry.root(),
                    &self.snapshot.namespace.scope.recording, cancel)?;
                verify_descriptor_for::<C>(&self.snapshot.namespace.scope, entry, &recording)?;
                probe(cancel)?;
                C::push(self.builder.as_mut().ok_or(ArchiveError::Metadata)?, entry.slot(), &recording)?;
                self.build_next += 1;
                return Ok(ArchiveWriteProgress::PageWindowVerified { ordinal, root: entry.root() });
            }
            // On allocation/encoding refusal, durable tail references are unchanged.
            // Explicit retry reconstructs metadata from those same verified objects.
            let page = C::prepare(self.builder.take().ok_or(ArchiveError::Metadata)?)?;
            let root = C::manifest(&page).root(); self.page = Some(page);
            return Ok(ArchiveWriteProgress::CatalogPrepared { root });
        }
        let tail = self.snapshot.windows.len() - self.snapshot.indexed;
        if tail != 0 && (self.flush_requested || self.input_closed || tail >= self.snapshot.limits.windows_per_page) {
            if self.snapshot.pages.len() == self.snapshot.limits.max_pages { return Err(ArchiveError::Limit); }
            self.snapshot.pages.try_reserve_exact(1).map_err(|_| ArchiveError::Limit)?;
            self.flush_end = Some(self.snapshot.windows.len()); self.flush_requested = false;
            return Ok(ArchiveWriteProgress::PageStarted { first_ordinal: self.snapshot.indexed, windows: tail });
        }
        self.flush_requested = false;
        if self.input_closed {
            let snapshot_digest = self.snapshot.digest()?;
            self.done = true;
            return Ok(ArchiveWriteProgress::Finished { snapshot_digest, windows: self.snapshot.windows.len(), pages: self.snapshot.pages.len() });
        }
        Ok(ArchiveWriteProgress::Ready { durable_windows: self.snapshot.windows.len(), indexed_windows: self.snapshot.indexed })
    }
    fn check_time(&self, now_ns: u64) -> ArchiveResult<()> {
        if now_ns < self.last_ns { return Err(ArchiveError::ClockReversed); }
        if now_ns >= self.deadline_ns { return Err(ArchiveError::Deadline); }
        Ok(())
    }
    /// Transfer all unacknowledged originals and immutable page bytes; release only
    /// this driver's borrow of the owner. Staged/durable disk custody stays untouched.
    pub fn retire(self) -> ArchiveRetirement<C> {
        ArchiveRetirement { snapshot: self.snapshot, pending: self.pending.map(|p| p.recording), prepared_page: self.page }
    }
}
impl<C: ArchiveCodec> std::fmt::Debug for CodecRecordingArchiveWriter<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingArchiveWriter").field("durable_windows", &self.snapshot.windows.len())
            .field("indexed_windows", &self.snapshot.indexed).field("pending", &self.pending.is_some())
            .field("blocked", &self.blocked).field("done", &self.done).finish_non_exhaustive()
    }
}

/// Root-last durable pending work and exact cold restart without camera recapture.
pub mod checkpoint;
