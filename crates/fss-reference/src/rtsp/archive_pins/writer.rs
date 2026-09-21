#![forbid(unsafe_code)]
//! Automatic pin persistence around the unchanged checkpointed archive owner.
use super::*;
use crate::rtsp::recording::PreparedRecording;
use crate::rtsp::recording_archive::{ArchiveAdmission, ArchiveLimits, ArchiveNamespace,
    ArchiveSnapshot, ArchiveWriteProgress, ArchiveWriteRefusal};
use crate::rtsp::recording_archive::checkpoint::write_ahead::{CheckpointedArchiveProgress,
    CheckpointedArchiveRetirement, CheckpointedArchiveWriter};

/// Source work committed, but recording its confirmation may have failed. Preserve this
/// receipt and the journal's candidate; do not replace either with an invented failure.
#[must_use]
#[derive(Debug)]
pub struct UnrecordedWorkConfirmation {
    /// Exact existing work checkpoint, not an archive ordinal.
    pub checkpoint: ArchiveCheckpoint,
    /// Actual work-root publisher receipt retained across a pin-journal failure.
    pub receipt: LocalPublicationReceipt,
}
/// Pin synchronization, work durability and ordinary archive progression stay separate.
#[must_use]
#[derive(Debug)]
pub enum JournaledArchiveProgress {
    /// The candidate record synchronized and only then unlocked checkpoint publication.
    PinPersisted {
        /// Exact existing checkpoint reference, without new resumption semantics.
        checkpoint: ArchiveCheckpoint,
        /// Metadata-only journal commit; not a work/source publication receipt.
        receipt: ArchivePinReceipt,
    },
    /// Work committed and its confirmation synchronized before any normal archive write.
    WorkConfirmed {
        /// Exact original checkpoint.
        checkpoint: ArchiveCheckpoint,
        /// Actual complete work-root storage receipt.
        work_receipt: LocalPublicationReceipt,
        /// Independent metadata confirmation receipt.
        pin_receipt: ArchivePinReceipt,
    },
    /// Existing recording durability, catalog publication or completion result.
    Archive(ArchiveWriteProgress),
}
/// Exact writer ownership plus any confirmation not acknowledged by the metadata journal.
#[must_use]
#[derive(Debug)]
pub struct JournaledArchiveRetirement {
    /// All original pending source and prepared catalog ownership.
    pub writer: CheckpointedArchiveRetirement,
    /// Work already committed when independent confirmation failed.
    pub unrecorded_confirmation: Option<UnrecordedWorkConfirmation>,
    /// Last acknowledged metadata prefix; an uncertain append may be a descendant.
    pub journal_anchor: ArchivePinAnchor,
    /// Candidate/predecessor state at that acknowledged prefix.
    pub pins: ArchivePinState,
}
/// Exclusive standalone writer with actual independent pin storage. No mutable inner escape
/// and no caller acknowledgement API. Source data stays in the existing writer exactly once.
#[must_use]
pub struct JournaledArchiveWriter<'a, 'p> {
    inner: CheckpointedArchiveWriter<'a>,
    pins: &'p mut ArchivePinJournal,
    unrecorded: Option<UnrecordedWorkConfirmation>,
    blocked: bool,
    last_ns: u64,
    finished: bool,
}
impl fmt::Debug for JournaledArchiveWriter<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledArchiveWriter").field("blocked", &self.blocked).finish_non_exhaustive()
    }
}
impl<'a, 'p> JournaledArchiveWriter<'a, 'p> {
    /// Confirm the prior pinned work settled before opening a new ordinary writer. Scope and
    /// journal admission precede archive mutation. Both stores remain explicitly owned.
    #[allow(clippy::too_many_arguments)]
    pub fn open(publisher: &'a mut LocalRootPublisher, pins: &'p mut ArchivePinJournal,
        namespace: ArchiveNamespace, archive: ArchiveLimits, work: ArchiveWorkLimits,
        max_steps: u64, now: u64, deadline: u64, cancel: &dyn PublishCancellation) -> PinResult<Self> {
        if pins.scope().archive_namespace != namespace.digest() { return Err(ArchivePinError::Scope); }
        pins.require_settled(publisher, work, cancel)?;
        let inner = CheckpointedArchiveWriter::open(publisher, namespace, archive, work, max_steps, now, deadline, cancel)?;
        Ok(Self { inner, pins, unrecorded: None, blocked: false, last_ns: now, finished: false })
    }
    /// Only acknowledged normal archive roots, not candidate or auxiliary work roots.
    pub fn snapshot(&self) -> &ArchiveSnapshot { self.inner.snapshot() }
    /// Original pending recording, without duplicating a payload buffer.
    pub fn pending(&self) -> Option<&PreparedRecording> { self.inner.pending() }
    /// Read-only independent journal prefix.
    pub fn journal_anchor(&self) -> ArchivePinAnchor { self.pins.anchor() }
    /// Read-only acknowledged pin state; mutation cannot bypass this owner.
    pub fn pin_state(&self) -> &ArchivePinState { self.pins.state() }
    /// In-memory admission only. Every refusal returns the same owned recording.
    pub fn offer(&mut self, recording: PreparedRecording, bytes: usize, now: u64)
        -> Result<ArchiveAdmission, ArchiveWriteRefusal> {
        if self.blocked {
            return Err(ArchiveWriteRefusal { reason: Box::new(ArchiveError::Blocked), recording: Box::new(recording) });
        }
        if now >= self.last_ns { self.last_ns = now; }
        self.inner.offer(recording, bytes, now)
    }
    /// Request an immutable discovery page through its own pin/work barrier.
    pub fn flush(&mut self, now: u64) -> PinResult<()> {
        if self.blocked { return Err(ArchivePinError::Fenced); }
        if now >= self.last_ns { self.last_ns = now; }
        Ok(self.inner.flush(now)?)
    }
    /// Close input, then drain accepted work through both synchronization boundaries.
    pub fn finish(&mut self, now: u64) -> PinResult<()> {
        if self.blocked { return Err(ArchivePinError::Fenced); }
        if now >= self.last_ns { self.last_ns = now; }
        Ok(self.inner.finish(now)?)
    }
    /// One existing checkpoint/archive step plus its bounded metadata append when needed.
    /// Work and confirmation may both write in this call, always in that order. No subsequent
    /// normal publication can occur until confirmation succeeds. Errors require retirement.
    pub fn step(&mut self, now: u64, cancel: &dyn PublishCancellation) -> PinResult<JournaledArchiveProgress> {
        if self.blocked { return Err(ArchivePinError::Fenced); }
        if self.finished { return Ok(JournaledArchiveProgress::Archive(ArchiveWriteProgress::Exhausted)); }
        if now < self.last_ns { return Err(ArchiveError::ClockReversed.into()); }
        self.last_ns = now;
        let result = self.advance(now, cancel);
        if matches!(&result, Ok(JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished { .. }
            | ArchiveWriteProgress::Exhausted))) { self.finished = true; }
        if result.is_err() && !matches!(&result, Err(ArchivePinError::Archive(ArchiveError::ClockReversed))) {
            self.blocked = true;
        }
        result
    }
    fn advance(&mut self, now: u64, cancel: &dyn PublishCancellation) -> PinResult<JournaledArchiveProgress> {
        self.pins.verify_tip(cancel)?;
        match self.inner.step(now, cancel)? {
            CheckpointedArchiveProgress::PinRequired(checkpoint) => {
                let receipt = self.pins.persist_candidate(&checkpoint, cancel)?;
                self.inner.acknowledge_checkpoint(&checkpoint, now, cancel)?;
                Ok(JournaledArchiveProgress::PinPersisted { checkpoint, receipt })
            }
            CheckpointedArchiveProgress::WorkDurable { checkpoint, receipt } => {
                match self.pins.confirm_receipt(&checkpoint, &receipt, cancel) {
                    Ok(pin_receipt) => Ok(JournaledArchiveProgress::WorkConfirmed {
                        checkpoint, work_receipt: receipt, pin_receipt }),
                    Err(error) => {
                        self.unrecorded = Some(UnrecordedWorkConfirmation { checkpoint, receipt });
                        Err(error)
                    }
                }
            }
            CheckpointedArchiveProgress::Archive(progress) => Ok(JournaledArchiveProgress::Archive(progress)),
        }
    }
    /// Transfer every unacknowledged recording and work receipt. No cleanup writes or retries.
    pub fn retire(self) -> JournaledArchiveRetirement {
        JournaledArchiveRetirement { writer: self.inner.retire(), unrecorded_confirmation: self.unrecorded,
            journal_anchor: self.pins.anchor(), pins: self.pins.state().clone() }
    }
}
