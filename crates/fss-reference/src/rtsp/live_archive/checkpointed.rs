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

// Compile the same pure sequencer privately for both native ownership paths. No public
// injection API or alternate control implementation can bypass either owner's admission.
#[path = "../live_avc/automatic/control.rs"]
mod automatic_control;
use automatic_control::{Action, ControlDriver};

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
    /// Original acquisition failure while its verified prefix crosses the same work barrier.
    /// This never establishes EOF, capture success, or authority for a successor connection.
    pub fn interruption(&self) -> Option<&LiveRecordingError> {
        self.inner.interruption()
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
            if self.inner.completion.is_none() && self.inner.interrupted.is_none() {
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
        if let Some(failure) = self.inner.finish_interruption() {
            return Err(self.failure(failure));
        }
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
            let step = self
                .inner
                .finish_archive(progress)
                .map_err(|e| self.failure(e))?;
            return Ok(CheckpointedLiveArchiveStep::Live(step));
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

/// One automatically prepared request OR one unchanged protected-archive output.
/// Queued means local preparation, never successful dispatch, recording or durable custody.
#[must_use]
#[derive(Debug)]
pub enum AutomaticLiveArchiveStep {
    /// One existing request queued without performing a socket write in this call.
    Queued(QueuedAvcRequest),
    /// All source, timing, checkpoint, publication and retirement outputs remain explicit.
    Archive(CheckpointedLiveArchiveStep),
}

/// Automatic DESCRIBE/Digest/SETUP/PLAY/keepalive over one write-ahead protected AVC archive.
///
/// Only accepted responses select subsequent commands. Safe protocol backpressure preserves
/// the unsent intent but advances native drainage before another preparation. Recovery and
/// every pending window/page/pin still drain before any command or socket read; automation
/// cannot bypass the write-ahead barrier. No source queue, reconnect or credential cache exists.
///
/// The owner retains original outputs and independently saves candidate pins before
/// acknowledgement. Picture timing is explicit; PLAY remains neither media nor coverage proof.
#[must_use]
pub struct AutomaticLiveAvcArchive<'a> {
    archive: CheckpointedLiveAvcArchive<'a>,
    control: ControlDriver,
}
impl fmt::Debug for AutomaticLiveAvcArchive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutomaticLiveAvcArchive")
            .field("archive", &self.archive)
            .field("control", &self.control)
            .finish_non_exhaustive()
    }
}
impl<'a> AutomaticLiveAvcArchive<'a> {
    /// Recover the exact archive and connect once. No RTSP command is prepared until the
    /// initial recovery barrier has drained; no credential is borrowed by this constructor.
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
        Ok(Self {
            archive: CheckpointedLiveAvcArchive::connect(
                live, recording, archive, work, publisher, now, authority, cancel,
            )?,
            control: ControlDriver::new(now),
        })
    }
    /// Existing local negotiation state, not camera or source health.
    pub fn state(&self) -> ClientState {
        self.archive.state()
    }
    /// Actual transport work; final observations transfer in retirement.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.archive.totals()
    }
    /// Acknowledged inventory, never the pending window or an auxiliary work root.
    pub fn snapshot(&self) -> Option<&ArchiveSnapshot> {
        self.archive.snapshot()
    }
    /// The sole pending recording, immutably borrowed from the existing writer.
    pub fn pending(&self) -> Option<&PreparedRecording> {
        self.archive.pending()
    }
    /// Exact candidate the runtime must save independently before acknowledging it.
    pub fn pending_checkpoint(&self) -> Option<&ArchiveCheckpoint> {
        self.archive.pending_checkpoint()
    }
    /// Prior acknowledged work root; retain it until the successor is demonstrably durable.
    pub fn last_durable_checkpoint(&self) -> Option<&ArchiveCheckpoint> {
        self.archive.last_durable_checkpoint()
    }
    /// True only when a command can be prepared next. Neither storage/pin waits nor
    /// deferred protocol drainage repeatedly request credentials or nonce generation.
    pub fn needs_credentials(&self) -> bool {
        self.control.action().is_some()
            && self.archive.inner.ready
            && !self.archive.inner.finished
            && self.archive.inner.writer.is_some()
            && self.archive.inner.recording.is_some()
            && self.archive.inner.completion.is_none()
    }
    /// Deferred protocol control preserves native wakes. Storage work and independent
    /// pin waits retain precedence over a queued unsent intent and keep their own deadlines.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.needs_credentials() {
            self.control.wake(self.archive.next_wake_ns())
        } else {
            self.archive.next_wake_ns()
        }
    }
    /// Prepare one automatic command OR advance one protected archive step, never both.
    /// Safe protocol backpressure selects native drainage next; already prepared or
    /// partially dispatched requests are never repeated by this control sequencer.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<AutomaticLiveArchiveStep, CheckpointedLiveArchiveFailure> {
        if self.needs_credentials() {
            // Preserve the non-mutating clock-refusal contract even when cancelled.
            if now < self.archive.inner.last_ns {
                return Err(CheckpointedLiveArchiveFailure {
                    reason: LiveArchiveError::ClockReversed,
                    retirement: None,
                });
            }
            // Automatic preparation cannot bypass the independent cancellation gate.
            if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
                let failure = self
                    .archive
                    .fatal(LiveArchiveError::Archive(ArchiveError::Cancelled));
                return Err(self.failed(failure));
            }
            let result = match self.control.action() {
                Some(Action::Request(command)) => {
                    self.archive
                        .request(command, credentials, cnonce, now, authority)
                }
                Some(Action::Respond) => self.archive.respond(credentials, cnonce, now, authority),
                None => {
                    let failure = self.archive.fatal(LiveArchiveError::Invariant);
                    return Err(self.failed(failure));
                }
            };
            return match result {
                Ok(queued) => {
                    self.control.clear();
                    Ok(AutomaticLiveArchiveStep::Queued(queued))
                }
                Err(failure) => Err(self.failed(failure)),
            };
        }
        let step = match self.archive.poll(readiness, now, authority, cancel) {
            Ok(step) => step,
            Err(failure) => return Err(self.failed(failure)),
        };
        if self.archive.inner.recording.is_none() {
            self.control.clear();
        } else if let CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(recording)) =
            &step
            && let LiveRecordingStep::Network(network) = recording.as_ref()
        {
            self.control.observe(network, now);
        }
        // Storage outputs do not erase deferred intent, and never count as protocol
        // drainage. The same protected archive retains exclusive source ownership.
        Ok(AutomaticLiveArchiveStep::Archive(step))
    }
    /// Supply only explicit owner timing. Invalid timing preserves the original held picture.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedCapture, CheckpointedLiveArchiveFailure> {
        let result = self.archive.supply_timing(timing, now, authority);
        result.map_err(|e| self.failed(e))
    }
    /// Seal a real completed prefix; poll then protects it before ordinary publication.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<bool, CheckpointedLiveArchiveFailure> {
        let result = self.archive.seal(now, authority);
        result.map_err(|e| self.failed(e))
    }
    /// Flush acknowledged windows into protected discovery metadata without ending input.
    pub fn flush(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), CheckpointedLiveArchiveFailure> {
        let result = self.archive.flush(now, authority);
        result.map_err(|e| self.failed(e))
    }
    /// Stop automatic commands and socket input. Unsealed originals transfer immediately;
    /// accepted windows and final catalogs still drain through the checkpoint barrier.
    pub fn finish_capture(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Option<LiveRecordingRetirement>, CheckpointedLiveArchiveFailure> {
        match self.archive.finish_capture(now, authority) {
            Ok(retirement) => {
                self.control.clear();
                Ok(retirement)
            }
            Err(failure) => Err(self.failed(failure)),
        }
    }
    /// Exact owner acknowledgement only. Automation never manufactures independent pin custody.
    pub fn acknowledge_checkpoint(
        &mut self,
        pin: &ArchiveCheckpoint,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<(), CheckpointedLiveArchiveFailure> {
        let result = self
            .archive
            .acknowledge_checkpoint(pin, now, authority, cancel);
        result.map_err(|e| self.failed(e))
    }
    /// Stop without I/O and transfer all pending source and recovery candidates exactly once.
    pub fn cancel(&mut self) -> Option<CheckpointedLiveArchiveRetirement> {
        self.control.clear();
        self.archive.cancel()
    }
    fn failed(
        &mut self,
        failure: CheckpointedLiveArchiveFailure,
    ) -> CheckpointedLiveArchiveFailure {
        if failure.retirement.is_some() || matches!(&failure.reason, LiveArchiveError::Closed) {
            self.control.clear();
        } else if let LiveArchiveError::Recording(error) = &failure.reason
            && let LiveRecordingError::Network(reason) = error.as_ref()
        {
            self.control.refused(reason, false);
        }
        failure
    }
}

#[cfg(test)]
mod tests;
