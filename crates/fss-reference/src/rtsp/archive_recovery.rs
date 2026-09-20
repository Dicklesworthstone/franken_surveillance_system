#![forbid(unsafe_code)]
//! Explicit resumption of exact retired AVC archive work, without contacting a camera.
//!
//! A failed publication may already be durable. Recovery verifies the original acknowledged
//! prefix and at most its one pending window/page. It never treats a lost ACK as permission to
//! choose a new ordinal, replace a page, follow arbitrary later history, or reopen a live stream.

use std::fmt;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_publication::{LocalRootPublisher, PublishCancellation};
use super::recording::{PreparedRecording, MAX_RECORDING_BYTES};
use super::recording_archive::{ArchiveAdmission, ArchiveError, ArchiveNamespace, ArchiveRetirement,
    ArchiveSnapshot, ArchiveWriteProgress, RecordingArchiveWriter};
use super::recording_catalog::{CatalogBuilder, RecordingCatalog};

/// Pin this commitment independently when retaining work after a failed attempt. A checksum
/// stored beside untrusted bytes is not authority. Includes routing, all old roots, pending
/// identities and original inventory limits; no source bytes or credentials are serialized.
pub fn archive_retirement_digest(retired: &ArchiveRetirement) -> Result<ContentDigest, ArchiveError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.reference_archive_retirement.v1");
    e.digest(retired.snapshot.digest()?);
    let limits = retired.snapshot.limits();
    for value in [limits.max_windows, limits.max_pages, limits.max_scan_roots, limits.windows_per_page] {
        e.u64(u64::try_from(value).map_err(|_| ArchiveError::Limit)?);
    }
    e.bool(retired.pending.is_some());
    if let Some(pending) = &retired.pending { e.digest(pending.manifest().root()); }
    e.bool(retired.prepared_page.is_some());
    if let Some(page) = &retired.prepared_page { e.digest(page.manifest().root()); }
    ContentDigest::try_sha256(&e.finish_checked().map_err(|_| ArchiveError::Limit)?)
        .map_err(|_| ArchiveError::Limit)
}

/// Explicit bounds for a new storage-only attempt. Namespace/page sizes remain frozen by input.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveResumeConfig {
    /// Independently retained identity of the exact old acknowledged and pending work.
    pub expected_retirement_digest: ContentDigest,
    /// Full pending-window payload allowance; zero is valid only when no window is pending.
    pub max_window_bytes: usize,
    /// Finite progress calls, including no-op readiness and terminal classification.
    pub max_steps: u64,
    /// New storage-only absolute lease. This never renews a camera/session/generation.
    pub deadline_ns: u64,
}

/// Observed durable status after rehashing current custody, not a receipt for a new write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetiredPublicationState {
    /// The prior attempt held no pending object of this kind.
    NotPending,
    /// Exact bytes still require explicit publication at their original slot.
    NotPublished(ContentDigest),
    /// Current verified custody proves the exact pending publication already durable.
    AlreadyDurable(ContentDigest),
}

/// Read-only reconciliation result, available before any new publication step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveReconciliation {
    /// Independently pinned old work commitment.
    pub retirement_digest: ContentDigest,
    /// Reverified inventory at open, not an automatically trusted canonical ledger root.
    pub recovered_snapshot_digest: ContentDigest,
    /// Whether a retained window crossed its original durability boundary.
    pub window: RetiredPublicationState,
    /// Whether a retained immutable page crossed its original durability boundary.
    pub page: RetiredPublicationState,
}

/// Opening never consumes an unacknowledged recording on failure.
#[must_use]
pub struct ArchiveResumeRefusal {
    /// Existing archive failure category; nested details require authorized diagnostics.
    pub reason: ArchiveError,
    /// Every original old reference, pending recording, and prepared page remains available.
    pub retired: Box<ArchiveRetirement>,
}
impl fmt::Debug for ArchiveResumeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("ArchiveResumeRefusal") }
}
impl fmt::Display for ArchiveResumeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("archive resume preflight refused") }
}
impl std::error::Error for ArchiveResumeRefusal {}

/// All work remaining after a resumed attempt. No filesystem cleanup or publication in Drop.
#[must_use]
pub struct ArchiveResumeRetirement {
    /// Latest acknowledged inventory and the existing writer's unacknowledged objects.
    pub archive: ArchiveRetirement,
    /// Original window waiting for the recovered unindexed tail to flush before its admission.
    pub unoffered_window: Option<PreparedRecording>,
    /// Exact original page retained until an identical replacement has been re-prepared.
    pub expected_page: Option<RecordingCatalog>,
}
impl fmt::Debug for ArchiveResumeRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveResumeRetirement")
            .field("unoffered_window", &self.unoffered_window.is_some())
            .field("expected_page", &self.expected_page.is_some()).finish_non_exhaustive()
    }
}
impl ArchiveResumeRetirement {
    /// Reassemble a retry input without losing competing objects. Different simultaneous page
    /// identities are refused intact; no one may resolve that conflict by silently picking one.
    pub fn into_retry(self) -> Result<ArchiveRetirement, Self> {
        if self.unoffered_window.is_some() && self.archive.pending.is_some() { return Err(self); }
        if let (Some(old), Some(new)) = (&self.expected_page, &self.archive.prepared_page)
            && (old.manifest() != new.manifest() || old.index_bytes() != new.index_bytes()) {
            return Err(self);
        }
        let Self { mut archive, unoffered_window, expected_page } = self;
        archive.pending = archive.pending.or(unoffered_window);
        archive.prepared_page = archive.prepared_page.or(expected_page);
        Ok(archive)
    }
}

/// Uses the original writer's vocabulary rather than treating recovery as new camera capture.
#[must_use]
#[derive(Debug)]
pub enum ArchiveResumeProgress {
    /// The original, previously unpublished window entered the writer at its original ordinal.
    WindowAccepted(ArchiveAdmission),
    /// Normal publication/indexing progress. Finished means storage drain only, never camera EOF.
    Archive(ArchiveWriteProgress),
    /// The storage completion already transferred once; no repeated receipt.
    Ended,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { InitialDrain, Offer, FinalDrain, Finished }

/// Storage-only recovery over an explicitly reopened/reconciled, exclusively owned publisher.
/// Opening reads only; step explicitly publishes. No network, remux, deletion, root repair,
/// implicit retry after error, catalog-size change or new live stream generation is introduced.
#[must_use]
pub struct RecordingArchiveResume<'a> {
    writer: RecordingArchiveWriter<'a>,
    unoffered: Option<PreparedRecording>,
    expected_page: Option<RecordingCatalog>,
    reconciliation: ArchiveReconciliation,
    config: ArchiveResumeConfig,
    phase: Phase,
    last_ns: u64,
    remaining_steps: u64,
    blocked: bool,
}
impl fmt::Debug for RecordingArchiveResume<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingArchiveResume").field("blocked", &self.blocked)
            .field("unoffered", &self.unoffered.is_some()).finish_non_exhaustive()
    }
}
impl<'a> RecordingArchiveResume<'a> {
    /// Reverify exact prior history and classify its pending publication before permitting new publication.
    /// Missing old roots, different slot contents, extra unaccounted windows/pages and unresolved
    /// root temporaries are errors. Every refusal returns original input without storage writes.
    pub fn open(publisher: &'a mut LocalRootPublisher, retired: ArchiveRetirement,
        config: ArchiveResumeConfig, now: u64, cancel: &dyn PublishCancellation)
        -> Result<Self, ArchiveResumeRefusal> {
        let preflight = prepare(publisher, &retired, config, now, cancel);
        let (writer, reconciliation) = match preflight {
            Ok(values) => values,
            Err(reason) => return Err(ArchiveResumeRefusal { reason, retired: Box::new(retired) }),
        };
        // Fully reverified durable counterparts now own custody; drop only redundant memory.
        let unoffered = if matches!(reconciliation.window, RetiredPublicationState::NotPublished(_)) {
            retired.pending
        } else { None };
        let expected_page = if matches!(reconciliation.page, RetiredPublicationState::NotPublished(_)) {
            retired.prepared_page
        } else { None };
        Ok(Self { writer, unoffered, expected_page, reconciliation, config,
            phase: Phase::InitialDrain, last_ns: now, remaining_steps: config.max_steps, blocked: false })
    }
    /// Read-only classification made before this attempt wrote anything.
    pub fn reconciliation(&self) -> ArchiveReconciliation { self.reconciliation }
    /// Current acknowledged inventory; pending writes may still need reconciliation.
    pub fn snapshot(&self) -> &ArchiveSnapshot { self.writer.snapshot() }
    /// One original window across the pre-admission and writer-owned stages, without copying it.
    pub fn pending(&self) -> Option<&PreparedRecording> { self.unoffered.as_ref().or(self.writer.pending()) }
    /// One existing writer step or one original-window admission. Error fences this attempt;
    /// retire and independently inspect/reopen before creating another attempt. No automatic retry.
    pub fn step(&mut self, now: u64, cancel: &dyn PublishCancellation)
        -> Result<ArchiveResumeProgress, ArchiveError> {
        if self.phase == Phase::Finished { return Ok(ArchiveResumeProgress::Ended); }
        if self.blocked { return Err(ArchiveError::Blocked); }
        if now < self.last_ns { return Err(ArchiveError::ClockReversed); }
        if now >= self.config.deadline_ns { self.blocked = true; return Err(ArchiveError::Deadline); }
        if self.remaining_steps == 0 { self.blocked = true; return Err(ArchiveError::Limit); }
        self.last_ns = now; self.remaining_steps -= 1;
        let result = self.advance(now, cancel);
        if result.is_err() { self.blocked = true; }
        result
    }
    fn advance(&mut self, now: u64, cancel: &dyn PublishCancellation)
        -> Result<ArchiveResumeProgress, ArchiveError> {
        if self.phase == Phase::Offer {
            if cancel.cancel_requested(fss_publication::PublishCutPoint::AfterChildrenVerified) {
                return Err(ArchiveError::Cancelled);
            }
            let window = self.unoffered.take().ok_or(ArchiveError::Metadata)?;
            match self.writer.offer(window, self.config.max_window_bytes, now) {
                Ok(admission) => {
                    self.writer.finish(); self.phase = Phase::FinalDrain;
                    return Ok(ArchiveResumeProgress::WindowAccepted(admission));
                }
                Err(refusal) => { self.unoffered = Some(*refusal.recording); return Err(*refusal.reason); }
            }
        }
        let progress = self.writer.step(now, cancel)?;
        if let ArchiveWriteProgress::CatalogPrepared { root } = &progress
            && let Some(expected) = &self.expected_page {
                if *root != expected.manifest().root() { return Err(ArchiveError::Metadata); }
                // The identical immutable page is now retained by the writer, before index/root I/O.
                self.expected_page = None;
        }
        if matches!(&progress, ArchiveWriteProgress::Ready { .. }) {
            if self.phase != Phase::InitialDrain || self.expected_page.is_some() { return Err(ArchiveError::Metadata); }
            if self.unoffered.is_some() { self.phase = Phase::Offer; }
            else { self.writer.finish(); self.phase = Phase::FinalDrain; }
        }
        if matches!(&progress, ArchiveWriteProgress::Finished { .. }) {
            if self.unoffered.is_some() || self.expected_page.is_some() || self.phase != Phase::FinalDrain {
                return Err(ArchiveError::Metadata);
            }
            self.phase = Phase::Finished;
        }
        Ok(ArchiveResumeProgress::Archive(progress))
    }
    /// Transfer all unacknowledged originals; never deletes, repairs or publishes in cleanup.
    pub fn retire(self) -> ArchiveResumeRetirement {
        ArchiveResumeRetirement { archive: self.writer.retire(), unoffered_window: self.unoffered,
            expected_page: self.expected_page }
    }
}

fn prepare<'a>(publisher: &'a mut LocalRootPublisher, retired: &ArchiveRetirement,
    config: ArchiveResumeConfig, now: u64, cancel: &dyn PublishCancellation)
    -> Result<(RecordingArchiveWriter<'a>, ArchiveReconciliation), ArchiveError> {
    if now >= config.deadline_ns { return Err(ArchiveError::Deadline); }
    if config.max_steps == 0 || config.max_window_bytes > MAX_RECORDING_BYTES
        || retired.pending.as_ref().is_some_and(|w| w.byte_len() > config.max_window_bytes) {
        return Err(ArchiveError::Limit);
    }
    let digest = archive_retirement_digest(retired)?;
    if digest != config.expected_retirement_digest { return Err(ArchiveError::Metadata); }
    let old = &retired.snapshot;
    let namespace = ArchiveNamespace::new(old.namespace().scope().clone())?;
    let writer = RecordingArchiveWriter::open(publisher, namespace, old.limits(), now, config.deadline_ns, cancel)?;
    let current = writer.snapshot();
    let old_count = old.windows().len(); let page_count = old.pages().len();
    if current.windows().len() < old_count || current.windows().len() > old_count + usize::from(retired.pending.is_some())
        || current.pages().len() < page_count || current.pages().len() > page_count + usize::from(retired.prepared_page.is_some())
        || current.windows()[..old_count] != *old.windows() {
        return Err(ArchiveError::Sequence);
    }
    for (prior, recovered) in old.pages().iter().zip(current.pages()) {
        if prior.slot() != recovered.slot() || prior.first_ordinal() != recovered.first_ordinal()
            || prior.catalog().manifest() != recovered.catalog().manifest()
            || prior.catalog().index_bytes() != recovered.catalog().index_bytes() { return Err(ArchiveError::Metadata); }
    }
    // A resumed drain can hold an unoffered window behind a prepared older tail page.
    // The window cannot already have published while that original page is still missing.
    if retired.pending.is_some() && retired.prepared_page.is_some()
        && current.windows().len() > old_count && current.pages().len() == page_count {
        return Err(ArchiveError::Metadata);
    }
    let window = match &retired.pending {
        None => RetiredPublicationState::NotPending,
        Some(window) => {
            let slot = old.namespace().window_slot(old_count)?;
            let mut builder = CatalogBuilder::new(old.namespace().scope().clone())?;
            builder.push(&slot, window)?;
            let catalog = builder.prepare()?;
            let entry = catalog.entries().first().ok_or(ArchiveError::Metadata)?;
            let root = window.manifest().root();
            if let Some(recovered) = current.windows().get(old_count) {
                if recovered != entry { return Err(ArchiveError::Metadata); }
                RetiredPublicationState::AlreadyDurable(root)
            } else { RetiredPublicationState::NotPublished(root) }
        }
    };
    let page = match &retired.prepared_page {
        None => RetiredPublicationState::NotPending,
        Some(page) => {
            if page.scope() != old.namespace().scope() || page.entries().is_empty()
                || page.entries() != old.unindexed_windows() { return Err(ArchiveError::Metadata); }
            let root = page.manifest().root();
            if let Some(recovered) = current.pages().get(page_count) {
                if recovered.first_ordinal() != old.indexed_windows()
                    || recovered.catalog().manifest() != page.manifest()
                    || recovered.catalog().index_bytes() != page.index_bytes() { return Err(ArchiveError::Metadata); }
                RetiredPublicationState::AlreadyDurable(root)
            } else { RetiredPublicationState::NotPublished(root) }
        }
    };
    let reconciliation = ArchiveReconciliation { retirement_digest: digest,
        recovered_snapshot_digest: current.digest()?, window, page };
    Ok((writer, reconciliation))
}
