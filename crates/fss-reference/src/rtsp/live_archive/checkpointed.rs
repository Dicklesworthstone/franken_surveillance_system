#![forbid(unsafe_code)]
//! Native live capture with the same source-protection barrier as the standalone writer.
//!
//! The legacy live owner remains unchanged. This exclusive wrapper never calls its unprotected
//! storage-poll branch: capture runs only while the inner owner is ready, and every storage
//! pause is advanced by CheckpointBarrier. No mutable inner-owner access is exposed.

use super::*;
use crate::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use crate::rtsp::recording_archive::checkpoint::write_ahead::{
    ArchiveCheckpoint, CheckpointBarrier, CheckpointedArchiveProgress,
};

/// Original terminal source/network/archive ownership plus the exact recovery candidates.
/// Pins alone are neither durable publication receipts nor current disclosure authority.
#[must_use]
#[derive(Debug)]
pub struct CheckpointedLiveArchiveRetirement {
    /// Unchanged live-owner retirement, including all unsealed and pending source.
    pub live: LiveArchiveRetirement,
    /// Candidate announced before checkpoint I/O; it may still be missing or uncertain.
    pub pending_checkpoint: Option<ArchiveCheckpoint>,
    /// Last acknowledged work root, possibly superseded by subsequent normal archive progress.
    pub last_durable_checkpoint: Option<ArchiveCheckpoint>,
}

/// Safe request/timing/pin refusals retain the driver. Fatal failures stop the socket and
/// transfer source ownership and checkpoint references together, exactly once.
#[derive(Debug)]
pub struct CheckpointedLiveArchiveFailure {
    /// Existing live failure vocabulary, not a new semantic effect status.
    pub reason: LiveArchiveError,
    /// All remaining ownership when this operation stopped the owner.
    pub retirement: Option<Box<CheckpointedLiveArchiveRetirement>>,
}
impl fmt::Display for CheckpointedLiveArchiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for CheckpointedLiveArchiveFailure {}

/// Checkpoint work is distinct from camera intake, normal archive durability, and indexing.
#[must_use]
#[derive(Debug)]
pub enum CheckpointedLiveArchiveStep {
    /// Existing live result. Stopped is instead lifted to the complete retirement below.
    Live(LiveArchiveStep),
    /// PinRequired or WorkDurable; ordinary archive progress stays in Live::Archive.
    Checkpoint(CheckpointedArchiveProgress),
    /// Original source failure plus all pending checkpoint and archive ownership.
    Stopped {
        /// The original network/protocol/capture trigger, without a fabricated EOF.
        trigger: Box<LiveRecordingStep>,
        /// Remaining source and independent-pin obligations.
        retained: Box<CheckpointedLiveArchiveRetirement>,
    },
}

/// Opt-in native AVC capture whose normal window/page publications are write-ahead protected.
/// Independent source retention and pin ownership must be authorized by the runtime. One
/// pending recording remains in the existing writer; no source queue or payload copy is added.
#[must_use]
pub struct CheckpointedLiveAvcArchive<'a> {
    inner: LiveAvcArchive<'a>,
    barrier: CheckpointBarrier,
}
impl fmt::Debug for CheckpointedLiveAvcArchive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointedLiveAvcArchive")
            .field("inner", &self.inner)
            .field("awaiting_pin", &self.barrier.awaiting_pin())
            .finish_non_exhaustive()
    }
}
impl<'a> CheckpointedLiveAvcArchive<'a> {
    /// Validate work/inventory ceilings before archive recovery or any connection attempt.
    /// Existing live scope, authentication, owner authority and network limits still apply.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        live: LiveAvcConfig,
        recording: LiveRecordingConfig,
        archive: LiveArchiveConfig,
        work: ArchiveWorkLimits,
        publisher: &'a mut LocalRootPublisher,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<Self, LiveArchiveConnectFailure> {
        let refused = |e| LiveArchiveConnectFailure {
            reason: LiveArchiveError::Archive(e),
            connection_attempted: false,
        };
        let barrier = CheckpointBarrier::new(work, archive.limits).map_err(refused)?;
        if archive.max_window_bytes > work.max_pending_bytes || work.max_new_bytes == 0 {
            return Err(refused(ArchiveError::Limit));
        }
        let inner =
            LiveAvcArchive::connect(live, recording, archive, publisher, now, authority, cancel)?;
        Ok(Self { inner, barrier })
    }
    /// Normal acknowledged archive inventory, excluding auxiliary checkpoint roots.
    pub fn snapshot(&self) -> Option<&ArchiveSnapshot> {
        self.inner.snapshot()
    }
    /// Exact original window in the existing writer, not a second source cache.
    pub fn pending(&self) -> Option<&PreparedRecording> {
        self.inner.pending()
    }
    /// Original protocol state; Playing is not evidence of complete recording.
    pub fn state(&self) -> ClientState {
        self.inner.state()
    }
    /// Actual transport observations, never remote acknowledgement or durable source proof.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.inner.totals()
    }
    /// Independently retain this candidate alongside the prior durable pin before acknowledgement.
    pub fn pending_checkpoint(&self) -> Option<&ArchiveCheckpoint> {
        self.barrier.pending()
    }
    /// Historical acknowledged work-root identity, not an automatically trusted latest pointer.
    pub fn last_durable_checkpoint(&self) -> Option<&ArchiveCheckpoint> {
        self.barrier.last_durable()
    }
    /// Pin waiting needs an owner notification or the existing hard deadlines, not a busy loop.
    /// Other storage work is immediately runnable. Protocol/collection time is never reset.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.inner.finished || self.inner.writer.is_none() {
            return None;
        }
        if self.barrier.awaiting_pin() {
            let mut at = self.inner.publication_deadline_ns;
            if let Some(since) = self.inner.storage_since_ns {
                at = at.min(since.saturating_add(self.inner.max_storage_pause_ns));
            }
            if self.inner.completion.is_none() {
                at = at.min(self.inner.live_deadline_ns);
            }
            return Some(at);
        }
        self.inner.next_wake_ns()
    }
    /// Explicit RTSP request. Pin waits and checkpoint work preserve normal storage backpressure.
    pub fn request(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedAvcRequest, CheckpointedLiveArchiveFailure> {
        let result = self
            .inner
            .request(command, credentials, cnonce, now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Answer only the existing held challenge; credentials/entropy are still borrowed.
    pub fn respond(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedAvcRequest, CheckpointedLiveArchiveFailure> {
        let result = self.inner.respond(credentials, cnonce, now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Explicit media timing, never guessed from TCP or RTP. Safe refusals preserve the picture.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedCapture, CheckpointedLiveArchiveFailure> {
        let result = self.inner.supply_timing(timing, now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Seal only an actual completed prefix. Its window will cross the checkpoint barrier.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<bool, CheckpointedLiveArchiveFailure> {
        let result = self.inner.seal(now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Flush discovery metadata through its own work barrier without ending capture.
    pub fn flush(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), CheckpointedLiveArchiveFailure> {
        let result = self.inner.flush(now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Stop the socket and return unsealed source immediately. Only already accepted windows
    /// are drained through protection; finalization retains the original OwnerStopped cause.
    pub fn finish_capture(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Option<LiveRecordingRetirement>, CheckpointedLiveArchiveFailure> {
        let result = self.inner.finish_capture(now, authority);
        result.map_err(|e| self.failure(e))
    }
    /// Trusted runtime assertion that the exact candidate and prior durable pins are retained
    /// independently. This call cannot verify an external journal. Wrong pins do no I/O, while
    /// revocation, cancellation and expiry stop capture even during a pin wait.
    pub fn acknowledge_checkpoint(
        &mut self,
        pin: &ArchiveCheckpoint,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<(), CheckpointedLiveArchiveFailure> {
        self.inner
            .admit(now, authority)
            .map_err(|e| self.failure(e))?;
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(self.fatal(LiveArchiveError::Archive(ArchiveError::Cancelled)));
        }
        self.barrier
            .acknowledge(pin)
            .map_err(|reason| CheckpointedLiveArchiveFailure {
                reason: LiveArchiveError::Archive(reason),
                retirement: None,
            })
    }
    /// One checkpoint/archive storage step OR one existing capture step. Positive socket
    /// readiness never bypasses a pending pin or checkpoint. Every fatal storage error closes
    /// the existing live owner and returns the original source together with recovery pins.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<CheckpointedLiveArchiveStep, CheckpointedLiveArchiveFailure> {
        if self.inner.finished || self.inner.writer.is_none() {
            return Ok(CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended));
        }
        if self.inner.ready {
            // This is the ONLY call to the old poll: its unprotected storage branch is unreachable.
            let step = self
                .inner
                .poll(readiness, now, authority, cancel)
                .map_err(|e| self.failure(e))?;
            return Ok(match step {
                LiveArchiveStep::Stopped { trigger, retained } => {
                    CheckpointedLiveArchiveStep::Stopped {
                        trigger,
                        retained: Box::new(self.retirement(*retained)),
                    }
                }
                other => CheckpointedLiveArchiveStep::Live(other),
            });
        }
        self.inner
            .admit(now, authority)
            .map_err(|e| self.failure(e))?;
        let Some(writer) = self.inner.writer.as_mut() else {
            return Err(self.fatal(LiveArchiveError::Invariant));
        };
        let progress = self
            .barrier
            .step(writer, now, cancel)
            .map_err(|e| self.fatal(LiveArchiveError::Archive(e)))?;
        let progress = match progress {
            CheckpointedArchiveProgress::Archive(progress) => progress,
            checkpoint => return Ok(CheckpointedLiveArchiveStep::Checkpoint(checkpoint)),
        };
        if matches!(&progress, ArchiveWriteProgress::Ready { .. }) {
            self.inner.ready = true;
            self.inner.storage_since_ns = None;
        }
        if matches!(&progress, ArchiveWriteProgress::Finished { .. }) {
            let Some(cause) = self.inner.completion else {
                return Err(self.fatal(LiveArchiveError::Invariant));
            };
            self.inner.finished = true;
            return Ok(CheckpointedLiveArchiveStep::Live(
                LiveArchiveStep::Finished {
                    archive: progress,
                    cause,
                },
            ));
        }
        Ok(CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            progress,
        )))
    }
    /// No publication, deletion or remote teardown in cleanup. Every source and checkpoint
    /// obligation is transferred; repeated cancellation returns None.
    pub fn cancel(&mut self) -> Option<CheckpointedLiveArchiveRetirement> {
        let live = self.inner.cancel()?;
        Some(self.retirement(live))
    }
    fn retirement(&self, live: LiveArchiveRetirement) -> CheckpointedLiveArchiveRetirement {
        CheckpointedLiveArchiveRetirement {
            live,
            pending_checkpoint: self.barrier.pending().cloned(),
            last_durable_checkpoint: self.barrier.last_durable().cloned(),
        }
    }
    fn failure(&self, failure: LiveArchiveFailure) -> CheckpointedLiveArchiveFailure {
        CheckpointedLiveArchiveFailure {
            reason: failure.reason,
            retirement: failure.retirement.map(|r| Box::new(self.retirement(*r))),
        }
    }
    fn fatal(&mut self, reason: LiveArchiveError) -> CheckpointedLiveArchiveFailure {
        let failure = self.inner.fatal(reason, None, None);
        self.failure(failure)
    }
}

#[cfg(test)]
mod tests;
