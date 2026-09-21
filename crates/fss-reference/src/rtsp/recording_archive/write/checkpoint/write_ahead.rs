#![forbid(unsafe_code)]
//! Write-ahead source protection around the existing archive writer, not a new journal.
//!
//! Every pending window and prepared page crosses a work-root durability barrier before its
//! normal archive slot can be published. The owner must pin the announced root independently
//! and acknowledge that pin; the driver never equates a checksum with trusted persistence.

use super::*;

/// Exact restart reference announced BEFORE checkpoint I/O. This is not a bearer capability,
/// durable receipt, or automatically trusted latest pointer. Keep the prior durable pin too
/// until this candidate's work root is independently verified durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveCheckpoint {
    slot: SlotName,
    root: ContentDigest,
    retirement: ContentDigest,
    new_payload_bytes: usize,
}
impl ArchiveCheckpoint {
    /// Pass unchanged to load_archive_work or fss-archive inspect-work/restore-work.
    pub fn slot(&self) -> &SlotName { &self.slot }
    /// Independently pin this exact content identity before acknowledging it.
    pub fn root(&self) -> ContentDigest { self.root }
    /// Existing archive_retirement_digest, not a second operation identity.
    pub fn retirement_digest(&self) -> ContentDigest { self.retirement }
    /// Complete work-payload reservation, excluding already durable historical media.
    pub fn new_payload_bytes(&self) -> usize { self.new_payload_bytes }
    fn prepared(work: &PreparedArchiveWork<'_>) -> Self {
        Self { slot: work.slot().clone(), root: work.root(), retirement: work.retirement_digest(),
            new_payload_bytes: work.new_payload_bytes() }
    }
}

/// The ordinary archive vocabulary is unchanged. Neither pin admission nor checkpoint
/// durability claims the normal recording ordinal, catalog publication, or complete capture.
#[must_use]
#[derive(Debug)]
pub enum CheckpointedArchiveProgress {
    /// Read-only preparation. Persist this pin in the runtime's independent trusted state and
    /// call acknowledge_checkpoint. Repeated unacknowledged polls do no publication I/O.
    PinRequired(ArchiveCheckpoint),
    /// The complete work graph is durable. Normal archive publication happens on a later step.
    WorkDurable {
        /// Original acknowledged restart reference, unchanged across retries.
        checkpoint: ArchiveCheckpoint,
        /// Actual existing publisher receipt for the work root, not its auxiliary children.
        receipt: LocalPublicationReceipt,
    },
    /// Existing archive progress: durability, indexing and finalization stay distinct.
    Archive(ArchiveWriteProgress),
}

/// Exact retirement plus pending and last acknowledged checkpoint identities. No payload is
/// copied into the barrier. A candidate pin can name a missing/uncertain root after failure;
/// reopen and inspect it rather than assuming the write failed or deleting partial storage.
#[must_use]
#[derive(Debug)]
pub struct CheckpointedArchiveRetirement {
    /// Unchanged archive resumption/checkpoint input, including all unacknowledged bytes.
    pub archive: ArchiveRetirement,
    /// Candidate whose whole work-root durability was not acknowledged by this driver.
    pub pending_checkpoint: Option<ArchiveCheckpoint>,
    /// Historical acknowledged work root; later archive progress can supersede its load scope.
    pub last_durable_checkpoint: Option<ArchiveCheckpoint>,
}

// Shared by the exclusive standalone and live owners. Deliberately not a public mutable
// handle: callers cannot interleave bare writer mutations around its durability barrier.
pub(crate) struct CheckpointBarrier {
    limits: ArchiveWorkLimits,
    pending: Option<ArchiveCheckpoint>,
    acknowledged: bool,
    protected: Option<ContentDigest>,
    last_durable: Option<ArchiveCheckpoint>,
}
impl CheckpointBarrier {
    pub(crate) fn new(limits: ArchiveWorkLimits, archive: ArchiveLimits) -> ArchiveResult<Self> {
        limits.validate(archive)?;
        Ok(Self { limits, pending: None, acknowledged: false, protected: None, last_durable: None })
    }
    pub(crate) fn pending(&self) -> Option<&ArchiveCheckpoint> { self.pending.as_ref() }
    pub(crate) fn last_durable(&self) -> Option<&ArchiveCheckpoint> { self.last_durable.as_ref() }
    pub(crate) fn awaiting_pin(&self) -> bool { self.pending.is_some() && !self.acknowledged }
    pub(crate) fn max_pending_bytes(&self) -> usize { self.limits.max_pending_bytes }
    pub(crate) fn acknowledge(&mut self, pin: &ArchiveCheckpoint) -> ArchiveResult<()> {
        if self.pending.as_ref() != Some(pin) { return Err(ArchiveError::Metadata); }
        self.acknowledged = true;
        Ok(())
    }
    pub(crate) fn step(&mut self, writer: &mut RecordingArchiveWriter<'_>, now: u64,
        cancel: &dyn PublishCancellation) -> ArchiveResult<CheckpointedArchiveProgress> {
        if writer.done { return Ok(CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::Exhausted)); }
        if writer.blocked { return Err(ArchiveError::Blocked); }
        if now < writer.last_ns { return Err(ArchiveError::ClockReversed); }
        writer.last_ns = now;
        let result = writer.check_time(now).and_then(|()| probe(cancel))
            .and_then(|()| self.advance(writer, now, cancel));
        if result.is_err() { writer.blocked = true; }
        result
    }
    fn advance(&mut self, writer: &mut RecordingArchiveWriter<'_>, now: u64,
        cancel: &dyn PublishCancellation) -> ArchiveResult<CheckpointedArchiveProgress> {
        owner_ready(writer.publisher)?;
        if writer.pending.is_none() && writer.page.is_none() {
            if self.pending.is_some() { return Err(ArchiveError::Metadata); }
            self.protected = None;
            return writer.step(now, cancel).map(CheckpointedArchiveProgress::Archive);
        }
        let identity = WorkView::writer(writer).retirement_digest()?;
        if self.protected == Some(identity) {
            return writer.step(now, cancel).map(CheckpointedArchiveProgress::Archive);
        }
        if let Some(pin) = &self.pending {
            if pin.retirement != identity { return Err(ArchiveError::Metadata); }
            if !self.acknowledged {
                return Ok(CheckpointedArchiveProgress::PinRequired(pin.clone()));
            }
        }
        // Borrow the immutable fields separately so publishing never aliases the storage owner
        // or requires cloning/moving a single source/media byte out of the live writer.
        let view = WorkView { snapshot: &writer.snapshot,
            pending: writer.pending.as_ref().map(|p| &p.recording), prepared_page: writer.page.as_ref() };
        let prepared = PreparedArchiveWork::prepare_view(view, writer.publisher, self.limits, cancel)?;
        let pin = ArchiveCheckpoint::prepared(&prepared);
        if self.pending.is_none() {
            self.pending = Some(pin.clone()); self.acknowledged = false;
            return Ok(CheckpointedArchiveProgress::PinRequired(pin));
        }
        if self.pending.as_ref() != Some(&pin) { return Err(ArchiveError::Metadata); }
        // Allocate the bounded metadata copies BEFORE the possibly committing I/O.
        let saved = pin.clone();
        let receipt = prepared.publish(writer.publisher, now, writer.deadline_ns, cancel)?;
        self.last_durable = Some(saved); self.protected = Some(identity);
        self.pending = None; self.acknowledged = false;
        Ok(CheckpointedArchiveProgress::WorkDurable { checkpoint: pin, receipt })
    }
    pub(crate) fn into_pins(self) -> (Option<ArchiveCheckpoint>, Option<ArchiveCheckpoint>) {
        (self.pending, self.last_durable)
    }
}

/// Exclusive AVC writer with automatic work barriers. There is no mutable bare-writer escape,
/// new task/runtime, automatic error retry, root deletion, or in-memory media duplication.
/// Existing unprotected writer APIs and HEVC formats remain unchanged.
#[must_use]
pub struct CheckpointedArchiveWriter<'a> {
    writer: RecordingArchiveWriter<'a>,
    barrier: CheckpointBarrier,
    remaining_steps: u64,
}
impl std::fmt::Debug for CheckpointedArchiveWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointedArchiveWriter").field("writer", &self.writer)
            .field("awaiting_pin", &self.barrier.awaiting_pin())
            .field("remaining_steps", &self.remaining_steps).finish_non_exhaustive()
    }
}
impl<'a> CheckpointedArchiveWriter<'a> {
    /// Bounded recovery reads only. A recovered unindexed tail is protected before its newly
    /// prepared catalog can publish. max_steps covers commands and polls, including pin waits.
    #[allow(clippy::too_many_arguments)]
    pub fn open(publisher: &'a mut LocalRootPublisher, namespace: ArchiveNamespace,
        archive: ArchiveLimits, work: ArchiveWorkLimits, max_steps: u64, now: u64, deadline: u64,
        cancel: &dyn PublishCancellation) -> ArchiveResult<Self> {
        if max_steps == 0 { return Err(ArchiveError::Limit); }
        let barrier = CheckpointBarrier::new(work, archive)?;
        let writer = RecordingArchiveWriter::open(publisher, namespace, archive, now, deadline, cancel)?;
        Ok(Self { writer, barrier, remaining_steps: max_steps })
    }
    /// Acknowledged normal archive state, not checkpoint auxiliary roots or raw ingress.
    pub fn snapshot(&self) -> &ArchiveSnapshot { self.writer.snapshot() }
    /// The same original recording retained by the ordinary writer, with no second cache.
    pub fn pending(&self) -> Option<&PreparedRecording> { self.writer.pending() }
    /// Pin to retain independently before permitting checkpoint publication.
    pub fn pending_checkpoint(&self) -> Option<&ArchiveCheckpoint> { self.barrier.pending() }
    /// Last acknowledged work-root receipt identity, not a promise of current retrievability.
    pub fn last_durable_checkpoint(&self) -> Option<&ArchiveCheckpoint> { self.barrier.last_durable() }
    /// Remaining progress/command admissions. Waiting never renews work or time allowances.
    pub fn remaining_steps(&self) -> u64 { self.remaining_steps }

    /// In-memory admission only. The next step automatically prepares its checkpoint before
    /// the ordinary writer can publish anything. Every refusal returns the original bytes.
    pub fn offer(&mut self, recording: PreparedRecording, reserved_bytes: usize, now: u64)
        -> Result<ArchiveAdmission, ArchiveWriteRefusal> {
        let admission = self.admit(now).and_then(|()| {
            if recording.byte_len() > self.barrier.max_pending_bytes() { return Err(ArchiveError::Limit); }
            Ok(())
        });
        if let Err(reason) = admission {
            return Err(ArchiveWriteRefusal { reason: Box::new(reason), recording: Box::new(recording) });
        }
        self.writer.offer(recording, reserved_bytes, now)
    }
    /// Trusted runtime acknowledgement that it independently persisted this exact candidate
    /// pin alongside the prior durable pin. No checksum or this call proves such persistence;
    /// the runtime must implement it. Wrong/stale pins are safe refusals and do not unlock work.
    pub fn acknowledge_checkpoint(&mut self, pin: &ArchiveCheckpoint, now: u64,
        cancel: &dyn PublishCancellation) -> ArchiveResult<()> {
        self.admit(now)?;
        if let Err(error) = probe(cancel) { self.writer.blocked = true; return Err(error); }
        self.barrier.acknowledge(pin)
    }
    /// Request catalog publication; the automatically prepared page crosses its own barrier.
    pub fn flush(&mut self, now: u64) -> ArchiveResult<()> {
        self.admit(now)?; self.writer.flush(); Ok(())
    }
    /// Finish only accepted work, through the same window/page protection barriers.
    pub fn finish(&mut self, now: u64) -> ArchiveResult<()> {
        self.admit(now)?; self.writer.finish(); Ok(())
    }
    /// One read-preparation, pin wait, complete bounded checkpoint publication, or ordinary
    /// archive step. A checkpoint step can perform multiple bounded filesystem calls.
    pub fn step(&mut self, now: u64, cancel: &dyn PublishCancellation)
        -> ArchiveResult<CheckpointedArchiveProgress> {
        if self.writer.done { return Ok(CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::Exhausted)); }
        self.admit(now)?;
        self.barrier.step(&mut self.writer, now, cancel)
    }
    /// Retire without writes. Reopen/reconcile storage and load a pinned work root for cold
    /// recovery, or use the ordinary exact retirement. There is no retry-through-error bypass.
    pub fn retire(self) -> CheckpointedArchiveRetirement {
        let (pending_checkpoint, last_durable_checkpoint) = self.barrier.into_pins();
        CheckpointedArchiveRetirement { archive: self.writer.retire(), pending_checkpoint, last_durable_checkpoint }
    }
    fn admit(&mut self, now: u64) -> ArchiveResult<()> {
        if self.writer.blocked { return Err(ArchiveError::Blocked); }
        if self.writer.done { return Err(ArchiveError::Closed); }
        if now < self.writer.last_ns { return Err(ArchiveError::ClockReversed); }
        if now >= self.writer.deadline_ns { self.writer.blocked = true; return Err(ArchiveError::Deadline); }
        if self.remaining_steps == 0 { self.writer.blocked = true; return Err(ArchiveError::Limit); }
        self.remaining_steps -= 1; self.writer.last_ns = now;
        Ok(())
    }
}
