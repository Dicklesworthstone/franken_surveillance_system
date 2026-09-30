#![forbid(unsafe_code)]
//! Durable connection-boundary history over the existing root-last object publisher.
//!
//! This owner wraps native reconnect recording, never accepts a caller-authored terminal
//! observation, and never releases a connection boundary before its exact history root is
//! durable and reverified. Each root links the preceding boundary and every original read
//! of this generation. A selected history is a prefix, not proof that capture finished or
//! that no later attempt exists. Receive time, native response completion, physical coverage,
//! boundary publication and permission to reconnect remain different facts.

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalPublicationReceipt, LocalRootPublisher};

use crate::ingest::http_archive::{HttpArchiveError, HttpArchiveLimits, HttpWireScope};
use crate::ingest::http_reconnect::{HttpReconnectHandoff, MAX_RECONNECT_CONNECTIONS};
use crate::ingest::http_reconnect_recording::{
    HttpReconnectBoundary, HttpReconnectFrameKey, HttpReconnectRecording,
    HttpReconnectRecordingError, HttpReconnectRecordingPlan, HttpReconnectRecordingRetirement,
    HttpReconnectRecordingStep, HttpReconnectWireCommit, HttpReconnectWirePlan,
};
use crate::ingest::http_recording::HttpRecordingAccess;
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;

mod record;
mod storage;
pub use record::{ArchivedReconnectBoundary, BoundaryOutcome};
pub use storage::VerifiedReconnectHistory;

/// An independently saved expected root. A pin alone is not evidence of publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectHistoryPin {
    /// Exact owner-approved acquisition plan identity, not an authentication credential.
    pub session: ContentDigest,
    /// Root of the last selected connection-boundary object graph.
    pub root: ContentDigest,
    /// Length of this prefix, from one through thirty-two.
    pub connections: u32,
}
impl ReconnectHistoryPin {
    pub(crate) fn validate(self) -> Result<(), HistoryError> {
        if !sha(self.session)
            || !sha(self.root)
            || !(1..=MAX_RECONNECT_CONNECTIONS as u32).contains(&self.connections)
        {
            return Err(HistoryError::Configuration);
        }
        Ok(())
    }
}

/// Independent cold-reader ceilings. Stored records never widen these limits.
#[derive(Clone, Copy, Debug)]
pub struct ReconnectHistoryLimits {
    /// Per-generation original-source and allocating-read ceilings.
    pub archive: HttpArchiveLimits,
    /// Total original reads across the selected history, at most 8192.
    pub maximum_reads: u64,
    /// Total original bytes across the selected history, at most 512 MiB.
    pub maximum_bytes: u64,
}
impl ReconnectHistoryLimits {
    pub(crate) fn validate(self) -> Result<(), HistoryError> {
        let a = self.archive;
        if !(1..=8192).contains(&self.maximum_reads)
            || !(1..=512 * 1024 * 1024).contains(&self.maximum_bytes)
            || !(1..=4096).contains(&a.maximum_reads)
            || !(1..=256 * 1024 * 1024).contains(&a.maximum_bytes)
            || !(1..=65536).contains(&a.maximum_scan_roots)
            || !(2048..=16 * 1024 * 1024).contains(&a.maximum_spool_object_bytes)
        {
            return Err(HistoryError::Configuration);
        }
        Ok(())
    }
}

/// Non-disclosing refusal. No error authorizes repair, reacquisition or nominal fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Invalid plan, pin or independent resource ceilings.
    Configuration,
    /// The exact connection/parent/source/prepare key is inconsistent.
    Mismatch,
    /// A selected root, metadata or canonical chain is invalid.
    Metadata,
    /// A previous capture already used this session namespace, including zero-byte attempts.
    Occupied,
    /// Publication is absent, broken, poisoned, visible-only or otherwise not durable.
    NotDurable,
    /// Required source or history has been tombstoned.
    Tombstoned,
    /// Storage could not verify or publish the selected object graph.
    Storage,
    /// Whole-history input, output or allocation ceiling was reached.
    Limit,
    /// Current original-custody/read/publication authority refused.
    Cancelled,
    /// Original source verification refused.
    Archive(HttpArchiveError),
    /// Native recorder refused; it still owns unfinished source.
    Recording(HttpReconnectRecordingError),
    /// Explicit history work allowance exhausted or cancellation requested.
    Work(GeometryError),
}
impl HistoryError {
    /// Stable identity for the history boundary, with the precise dimension kept in the variant.
    pub const fn stable_id(&self) -> &'static str {
        "ERR-CAPTURE-RECONNECT-SOURCE-001"
    }
}
impl From<HttpArchiveError> for HistoryError {
    fn from(e: HttpArchiveError) -> Self {
        Self::Archive(e)
    }
}
impl From<HttpReconnectRecordingError> for HistoryError {
    fn from(e: HttpReconnectRecordingError) -> Self {
        Self::Recording(e)
    }
}
impl From<GeometryError> for HistoryError {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}
impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP reconnect history refused: {self:?}")
    }
}
impl std::error::Error for HistoryError {}

fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}

/// Pending native boundary. Construction is private; a caller cannot supply a fabricated EOF.
#[derive(Debug)]
pub struct PreparedReconnectBoundary {
    observation: ArchivedReconnectBoundary,
    native: HttpReconnectBoundary,
    pin: ReconnectHistoryPin,
    durable: bool,
}
impl PreparedReconnectBoundary {
    /// Save this expected root before permitting publication.
    pub fn pin(&self) -> ReconnectHistoryPin {
        self.pin
    }
    /// Bounded, payload-free archived observation, not a reconnect capability.
    pub fn observation(&self) -> &ArchivedReconnectBoundary {
        &self.observation
    }
    /// Whether this live owner received a durable publication acknowledgement.
    pub fn published(&self) -> bool {
        self.durable
    }
}

/// Source steps retain their original meaning; native BoundaryReady is intercepted below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableReconnectStep {
    /// Existing recorder progress, never its uncommitted BoundaryReady escape.
    Source(HttpReconnectRecordingStep),
    /// Native boundary ready for exact, root-last history publication.
    BoundaryPrepared(ReconnectHistoryPin),
    /// Root is durable; an explicit, reverified release is still required before reconnect.
    BoundaryDurable(ReconnectHistoryPin),
}

/// Exclusive recording owner with a durable barrier between every connection generation.
/// No mutable inner recorder, responsibility-only boundary ACK, hidden retry or new journal.
pub struct DurableReconnectRecording {
    inner: HttpReconnectRecording,
    session: ContentDigest,
    limits: ReconnectHistoryLimits,
    scopes: Vec<HttpWireScope>,
    preflight: bool,
    last: Option<ReconnectHistoryPin>,
    pending: Option<PreparedReconnectBoundary>,
    history_work: WorkBudget<'static>,
}
impl DurableReconnectRecording {
    /// Validate a frozen native plan and reserve a separate, explicit WHOLE-RUN history budget.
    /// Native source/framing budgets remain unchanged; neither allowance resets on reconnect.
    /// This creates no filesystem, clock or network state.
    pub fn new(
        plan: HttpReconnectRecordingPlan,
        session: ContentDigest,
        history_work: u64,
        now_ns: u64,
    ) -> Result<Self, HistoryError> {
        if !sha(session)
            || history_work == 0
            || plan.slots.is_empty()
            || plan.slots.len() > MAX_RECONNECT_CONNECTIONS
        {
            return Err(HistoryError::Configuration);
        }
        let mut limits = ReconnectHistoryLimits {
            archive: plan.slots[0].archive,
            maximum_reads: 0,
            maximum_bytes: 0,
        };
        let mut scopes = Vec::with_capacity(plan.slots.len());
        for slot in &plan.slots {
            let a = slot.archive;
            limits.maximum_reads = limits
                .maximum_reads
                .checked_add(a.maximum_reads as u64)
                .ok_or(HistoryError::Limit)?;
            limits.maximum_bytes = limits
                .maximum_bytes
                .checked_add(a.maximum_bytes)
                .ok_or(HistoryError::Limit)?;
            limits.archive.maximum_reads = limits.archive.maximum_reads.max(a.maximum_reads);
            limits.archive.maximum_bytes = limits.archive.maximum_bytes.max(a.maximum_bytes);
            limits.archive.maximum_scan_roots =
                limits.archive.maximum_scan_roots.max(a.maximum_scan_roots);
            limits.archive.maximum_spool_object_bytes = limits
                .archive
                .maximum_spool_object_bytes
                .max(a.maximum_spool_object_bytes);
            // One predecessor and one metadata child fit alongside the entire original inventory.
            if a.maximum_reads > fss_object::MAX_MANIFEST_CHILDREN.saturating_sub(2) {
                return Err(HistoryError::Limit);
            }
            scopes.push(slot.scope);
        }
        limits.validate()?;
        Ok(Self {
            inner: HttpReconnectRecording::new(plan, now_ns)?,
            session,
            limits,
            scopes,
            preflight: false,
            last: None,
            pending: None,
            history_work: WorkBudget::new(history_work),
        })
    }
    /// Read-only source/work accounting, without mutable release authority.
    pub fn recording(&self) -> &HttpReconnectRecording {
        &self.inner
    }
    /// Last acknowledged durable boundary; not necessarily the end of this acquisition.
    pub fn history_pin(&self) -> Option<ReconnectHistoryPin> {
        self.last
    }
    /// Current expected boundary, including after an ambiguous publication or output refusal.
    pub fn pending_boundary(&self) -> Option<&PreparedReconnectBoundary> {
        self.pending.as_ref()
    }
    /// Consumed history verification/publication work over the entire run.
    pub fn history_work_used(&self) -> u64 {
        self.history_work.used()
    }
    /// Unspent history allowance; no implicit refill is available.
    pub fn history_work_remaining(&self) -> u64 {
        self.history_work.remaining()
    }

    /// Every repeated poll is charged by the underlying recorder, even while a boundary is held.
    /// A used session is refused before the first native connection, including byte-empty history.
    pub fn poll(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<DurableReconnectStep, HistoryError> {
        storage::probe(access.storage)?;
        self.history_work.charge(1)?;
        if !self.preflight {
            storage::require_empty(
                publisher,
                self.session,
                self.limits,
                access.storage,
                &mut self.history_work,
            )?;
            self.preflight = true;
        }
        if self.pending.is_none() {
            let next = self.last.map_or(1, |pin| pin.connections + 1);
            if next <= self.scopes.len() as u32 && self.inner.totals().slots_started < next {
                storage::require_unused_slot(
                    publisher,
                    self.session,
                    next,
                    self.limits,
                    access.storage,
                    &mut self.history_work,
                )?;
            }
        }
        match self.inner.poll(publisher, access)? {
            HttpReconnectRecordingStep::BoundaryReady(native) => {
                if let Some(pending) = &self.pending {
                    if pending.native != native {
                        return Err(HistoryError::Mismatch);
                    }
                } else {
                    let scope = *self
                        .scopes
                        .get(
                            native
                                .source
                                .connection
                                .checked_sub(1)
                                .ok_or(HistoryError::Mismatch)?
                                as usize,
                        )
                        .ok_or(HistoryError::Mismatch)?;
                    let observation = ArchivedReconnectBoundary::from_native(
                        self.session,
                        self.last,
                        scope,
                        native,
                    )?;
                    let pin = storage::prepare(
                        publisher,
                        &observation,
                        self.limits,
                        access.storage,
                        &mut self.history_work,
                    )?;
                    self.pending = Some(PreparedReconnectBoundary {
                        observation,
                        native,
                        pin,
                        durable: false,
                    });
                }
                let pending = self.pending.as_ref().ok_or(HistoryError::Mismatch)?;
                Ok(if pending.durable {
                    DurableReconnectStep::BoundaryDurable(pending.pin)
                } else {
                    DurableReconnectStep::BoundaryPrepared(pending.pin)
                })
            }
            step if self.pending.is_none() => Ok(DurableReconnectStep::Source(step)),
            _ => Err(HistoryError::Mismatch),
        }
    }
    /// Original durability-before-parse write, unchanged from the native recorder.
    pub fn commit_wire(
        &mut self,
        plan: HttpReconnectWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectWireCommit, HistoryError> {
        Ok(self.inner.commit_wire(plan, publisher, access)?)
    }
    /// Original source mapping and live transfer authority; downstream pixels still need masking.
    pub fn take_frame(
        &mut self,
        key: HttpReconnectFrameKey,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpJpegFrame, HistoryError> {
        Ok(self.inner.take_frame(key, publisher, access)?)
    }

    /// Reverify all selected history and source, then publish metadata and its exact root last.
    /// An exact retry reuses the same slot/root; a refusal leaves the source barrier held.
    pub fn commit_boundary(
        &mut self,
        expected: ReconnectHistoryPin,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<LocalPublicationReceipt, HistoryError> {
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.pin == expected)
            .ok_or(HistoryError::Mismatch)?;
        let receipt = storage::publish(
            publisher,
            &pending.observation,
            expected,
            self.limits,
            access.storage,
            &mut self.history_work,
        )?;
        // No fallible operation after the actual durable acknowledgement.
        self.last = Some(expected);
        if let Some(pending) = &mut self.pending {
            pending.durable = true;
        }
        Ok(receipt)
    }
    /// Reverify AGAIN after the caller's checkpoint/output delay, then release the native barrier.
    /// A missing/tombstoned ancestor or original source prevents every subsequent connection.
    pub fn release_boundary(
        &mut self,
        expected: ReconnectHistoryPin,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpReconnectHandoff, HistoryError> {
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.pin == expected && p.durable)
            .ok_or(HistoryError::NotDurable)?;
        let verified = VerifiedReconnectHistory::load(
            publisher,
            expected,
            self.limits,
            access.storage,
            &mut self.history_work,
        )?;
        if verified.boundaries().last() != Some(&pending.observation) {
            return Err(HistoryError::Mismatch);
        }
        let handoff = self
            .inner
            .release_boundary(pending.native, publisher, access)?;
        self.pending = None;
        Ok(handoff)
    }
    /// Close without extra I/O and transfer unfinished original custody and any ambiguous root.
    pub fn retire(self) -> DurableReconnectRetirement {
        DurableReconnectRetirement {
            recording: self.inner.retire(),
            boundary: self.pending,
            last_durable_boundary: self.last,
            history_work: self.history_work.used(),
        }
    }
}

/// Ownership after stop, NOT permission to restart a source or to retry a network request.
#[must_use]
pub struct DurableReconnectRetirement {
    /// Unfinished raw bytes, native outcomes and exact source pins.
    pub recording: HttpReconnectRecordingRetirement,
    /// Exact prepared boundary, including a potentially ambiguous disk publication.
    pub boundary: Option<PreparedReconnectBoundary>,
    /// Last boundary whose publication was acknowledged to this process.
    pub last_durable_boundary: Option<ReconnectHistoryPin>,
    /// Charged whole-run history work, including refused operations.
    pub history_work: u64,
}

#[cfg(test)]
mod tests;
