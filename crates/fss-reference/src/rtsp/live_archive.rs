#![forbid(unsafe_code)]
//! Bounded live AVC capture -> durable windows -> immutable archive pages.
//!
//! There is one pending recording, owned by the existing archive writer. Storage progress
//! backpressures the entire live path: no socket or media poll occurs until the writer is ready.
//! Live authority is still checked, and an explicit finite storage-pause deadline is enforced.
//! Original wire, skipped pictures, and terminal capture ownership are never called archived.

use std::fmt;

use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::authentication::DigestCredentials;
use super::client::{ClientCommand, ClientState};
use super::live_avc::recording::{
    LiveAvcRecording, LiveRecordingConfig, LiveRecordingError, LiveRecordingFailure,
    LiveRecordingRetirement, LiveRecordingStep,
};
use super::live_avc::{LiveAvcConfig, QueuedAvcRequest, SocketReadiness};
use super::recording::{MAX_RECORDING_BYTES, PreparedRecording};
use super::recording_archive::{
    ArchiveAdmission, ArchiveError, ArchiveLimits, ArchiveNamespace, ArchiveRetirement,
    ArchiveSnapshot, ArchiveWriteProgress, RecordingArchiveWriter,
};
use super::recording_capture::{CapturePoll, TimedCapture};
use super::recording_collector::RecordingTiming;
use super::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpTotals};

/// Explicit archival policy for one bounded live attempt. No defaults select a camera or sink.
#[derive(Clone, Debug)]
pub struct LiveArchiveConfig {
    /// Exact sensor, generation, receive-clock and decode-clock routing scope.
    pub namespace: ArchiveNamespace,
    /// Bounded durable inventory and immutable catalog-page sizes.
    pub limits: ArchiveLimits,
    /// Maximum complete retained recording, including all four children and root.
    pub max_window_bytes: usize,
    /// Finite request/respond/timing/flush/poll allowance, including no-readiness calls.
    pub max_steps: u64,
    /// Independent absolute deadline for storage progress, including final catalog draining.
    pub publication_deadline_ns: u64,
    /// Maximum elapsed admission time per continuous storage pause, in 1 ns..=60 seconds.
    /// This does not reset the live client's original protocol or collection deadlines.
    pub max_storage_pause_ns: u64,
}

/// Payload-free outer failures; detailed storage errors belong in protected diagnostics.
#[derive(Debug)]
pub enum LiveArchiveError {
    /// Inconsistent recording/archive scope, invalid limits, or an invalid initial lease.
    Configuration,
    /// Live capture refused. Any terminal state is retained separately, not inside this reason.
    Recording(Box<LiveRecordingError>),
    /// Publication/verification failed; it may have crossed a durable boundary.
    Archive(ArchiveError),
    /// The exact live network grant was withdrawn while storage was backpressuring capture.
    Authority(TcpDenial),
    /// Trusted monotonic admission time regressed. This refusal changes no state.
    ClockReversed,
    /// The absolute publication deadline expired.
    Deadline,
    /// The current bounded storage pause expired; no next publication was attempted.
    StoragePauseExpired,
    /// The finite outer driver allowance is exhausted.
    WorkBudget,
    /// Drain storage before preparing another command, timing input, seal, or flush.
    Backpressure,
    /// Input has ended or terminal ownership has already transferred.
    Closed,
    /// An impossible state was observed; no EOF or success is fabricated.
    Invariant,
}
impl fmt::Display for LiveArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid live archive configuration",
            Self::Recording(_) => "live archive capture refused",
            Self::Archive(_) => "live archive publication requires reconciliation",
            Self::Authority(_) => "live archive authority refused",
            Self::ClockReversed => "live archive clock regressed",
            Self::Deadline => "live archive publication deadline expired",
            Self::StoragePauseExpired => "live archive storage pause expired",
            Self::WorkBudget => "live archive work allowance exhausted",
            Self::Backpressure => "live archive storage must drain first",
            Self::Closed => "live archive admission closed",
            Self::Invariant => "live archive state refused",
        })
    }
}
impl std::error::Error for LiveArchiveError {}

/// Constructor failure. Recovery reads precede connecting; no RTSP command is sent here.
#[derive(Debug)]
pub struct LiveArchiveConnectFailure {
    /// Typed failure; Display does not expose addresses, paths, or media.
    pub reason: LiveArchiveError,
    /// A native connection attempt occurred, not a successful RTSP session.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveArchiveConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveArchiveConnectFailure {}

/// Exact unacknowledged work. The publisher's staged/durable storage is never rolled back.
#[must_use]
pub struct LiveArchiveRetirement {
    /// Network uncertainty, unsealed originals, and untimed/unoffered capture input.
    /// None when an earlier returned terminal capture event already owns these values.
    pub recording: Option<LiveRecordingRetirement>,
    /// Last acknowledged inventory, one pending recording, and any exact prepared catalog.
    pub archive: Option<ArchiveRetirement>,
    /// A window rejected before the writer took ownership; not an admission or durability claim.
    pub unoffered_window: Option<PreparedRecording>,
}
impl fmt::Debug for LiveArchiveRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveArchiveRetirement")
            .field("recording", &self.recording.is_some())
            .field("archive", &self.archive.is_some())
            .field("unoffered_window", &self.unoffered_window.is_some())
            .finish()
    }
}

/// A safe correction has no retirement. Fatal failures close capture and transfer all work once.
#[derive(Debug)]
pub struct LiveArchiveFailure {
    /// Failure stage, not permission to retry an ambiguous storage effect.
    pub reason: LiveArchiveError,
    /// Exact retained work after a fatal call; no further operation is admitted on this driver.
    pub retirement: Option<Box<LiveArchiveRetirement>>,
}
impl fmt::Display for LiveArchiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveArchiveFailure {}

/// Why input was deliberately closed before the final catalog drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveArchiveCompletion {
    /// The existing recording owner emitted its real terminal capture event.
    InputEnded,
    /// The owner explicitly stopped input. Returned unsealed work was NOT archived.
    OwnerStopped,
}

/// Every output is a distinct boundary. Never equate admission, durability, indexing, and EOF.
#[must_use]
pub enum LiveArchiveStep {
    /// Original live output, including wire, timing, skipped source, and EOF retirement.
    /// Successful prepared windows are intercepted and owned by the writer instead.
    Recording(Box<LiveRecordingStep>),
    /// The writer accepted the exact window in memory. No publication has happened yet.
    WindowAccepted(ArchiveAdmission),
    /// Existing writer progress, including WindowDurable and CatalogPublished separately.
    Archive(ArchiveWriteProgress),
    /// Catalog drain finished after the stated input disposition. Not a coverage certificate.
    Finished {
        /// Original writer completion, including its snapshot digest and window/page counts.
        archive: ArchiveWriteProgress,
        /// EOF and deliberate owner stop remain distinguishable.
        cause: LiveArchiveCompletion,
    },
    /// A source/protocol/capture fault stopped archival progress without finalizing a fake EOF.
    Stopped {
        /// Original trigger, which may itself own capture/network retirement.
        trigger: Box<LiveRecordingStep>,
        /// Remaining archive/capture ownership, never automatically retried.
        retained: Box<LiveArchiveRetirement>,
    },
    /// Terminal progress already transferred; no repeated publication/finished receipt.
    Ended,
}
impl fmt::Debug for LiveArchiveStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Recording(_) => "LiveArchiveStep::Recording",
            Self::WindowAccepted(_) => "LiveArchiveStep::WindowAccepted",
            Self::Archive(_) => "LiveArchiveStep::Archive",
            Self::Finished { .. } => "LiveArchiveStep::Finished",
            Self::Stopped { .. } => "LiveArchiveStep::Stopped",
            Self::Ended => "LiveArchiveStep::Ended",
        })
    }
}

/// One live attempt borrowing one already-open, exclusively owned local publisher.
///
/// Connect performs bounded archive recovery reads before opening the socket. Poll drains any
/// recovered unindexed tail BEFORE permitting requests or intake. Publication steps never poll
/// the socket or reconstruct media. Raw ingress remains caller-owned; there is no thread, timer,
/// reconnect, automatic credential lookup, retention change, or second pending-window queue.
#[must_use]
pub struct LiveAvcArchive<'a> {
    recording: Option<LiveAvcRecording>,
    writer: Option<RecordingArchiveWriter<'a>>,
    binding: TcpBinding,
    live_deadline_ns: u64,
    publication_deadline_ns: u64,
    max_window_bytes: usize,
    remaining_steps: u64,
    max_storage_pause_ns: u64,
    storage_since_ns: Option<u64>,
    last_ns: u64,
    ready: bool,
    completion: Option<LiveArchiveCompletion>,
    finished: bool,
}
impl fmt::Debug for LiveAvcArchive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveAvcArchive")
            .field("ready", &self.ready)
            .field("completion", &self.completion)
            .field("finished", &self.finished)
            .field("remaining_steps", &self.remaining_steps)
            .finish_non_exhaustive()
    }
}
impl<'a> LiveAvcArchive<'a> {
    /// Validate exact cross-owner scope, recover inventory, then connect once. A configuration or
    /// recovery failure performs no network attempt; open itself publishes no recording or page.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        live: LiveAvcConfig,
        recording: LiveRecordingConfig,
        archive: LiveArchiveConfig,
        publisher: &'a mut LocalRootPublisher,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<Self, LiveArchiveConnectFailure> {
        let refused = |reason| LiveArchiveConnectFailure {
            reason,
            connection_attempted: false,
        };
        if archive.namespace.scope().recording != recording.scope
            || archive.namespace.scope().time_scale != recording.time_scale
            || recording.scope.generation != live.binding.key().generation
            || recording.limits.validate().is_err()
            || recording.payload_type > 127
            || archive.limits.validate().is_err()
            || archive.max_steps == 0
            || !(1..=MAX_RECORDING_BYTES).contains(&archive.max_window_bytes)
            || !(1..=60_000_000_000).contains(&archive.max_storage_pause_ns)
            || now >= archive.publication_deadline_ns
            || now >= live.deadline_ns
        {
            return Err(refused(LiveArchiveError::Configuration));
        }
        let binding = live.binding.clone();
        let live_deadline_ns = live.deadline_ns;
        let writer = RecordingArchiveWriter::open(
            publisher,
            archive.namespace,
            archive.limits,
            now,
            archive.publication_deadline_ns,
            cancel,
        )
        .map_err(|e| refused(LiveArchiveError::Archive(e)))?;
        let recording =
            LiveAvcRecording::connect(live, recording, now, authority).map_err(|e| {
                LiveArchiveConnectFailure {
                    reason: LiveArchiveError::Recording(Box::new(e.reason)),
                    connection_attempted: e.connection_attempted,
                }
            })?;
        Ok(Self {
            recording: Some(recording),
            writer: Some(writer),
            binding,
            live_deadline_ns,
            publication_deadline_ns: archive.publication_deadline_ns,
            max_window_bytes: archive.max_window_bytes,
            remaining_steps: archive.max_steps,
            max_storage_pause_ns: archive.max_storage_pause_ns,
            storage_since_ns: Some(now),
            last_ns: now,
            ready: false,
            completion: None,
            finished: false,
        })
    }

    /// Acknowledged durable/indexed inventory only. Absent after terminal ownership transfer.
    pub fn snapshot(&self) -> Option<&ArchiveSnapshot> {
        self.writer.as_ref().map(|w| w.snapshot())
    }
    /// One accepted recording not yet acknowledged durable; source bytes are never logged.
    pub fn pending(&self) -> Option<&PreparedRecording> {
        self.writer.as_ref().and_then(|w| w.pending())
    }
    /// The existing protocol's local state, not camera health or archive completeness.
    pub fn state(&self) -> ClientState {
        self.recording
            .as_ref()
            .map_or(ClientState::Closed, |r| r.state())
    }
    /// Transport observations, absent after their terminal transfer.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.recording.as_ref().and_then(|r| r.totals())
    }
    /// Storage work wakes immediately; otherwise preserve all existing live wakes and storage lease.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.finished || self.writer.is_none() {
            return None;
        }
        if !self.ready {
            return Some(self.last_ns);
        }
        Some(
            self.recording
                .as_ref()
                .and_then(|r| r.next_wake_ns())
                .map_or(self.publication_deadline_ns, |at| {
                    at.min(self.publication_deadline_ns)
                }),
        )
    }

    /// Explicit existing RTSP command. Storage must drain before a new request can be prepared.
    pub fn request(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedAvcRequest, LiveArchiveFailure> {
        self.admit(now, authority)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .request(command, credentials, cnonce, now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Answer only the internally held challenge; no new authentication policy or retry loop.
    pub fn respond(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedAvcRequest, LiveArchiveFailure> {
        self.admit(now, authority)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .respond(credentials, cnonce, now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Independently supplied media timing. Rejected timing keeps the same picture in capture.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedCapture, LiveArchiveFailure> {
        self.admit(now, authority)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .supply_timing(timing, now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Prepare a completed prefix without inventing a frame boundary. Poll admits that exact plan.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<bool, LiveArchiveFailure> {
        self.admit(now, authority)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .seal(now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Index the acknowledged tail without ending input. Repeated calls cannot restart a pause.
    pub fn flush(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), LiveArchiveFailure> {
        self.admit(now, authority)?;
        self.require_input()?;
        self.writer
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .flush();
        self.pause(now);
        Ok(())
    }
    /// Stop input without pretending it reached EOF. Unsealed/untimed work transfers immediately;
    /// poll then drains ONLY recordings already admitted to the writer and its final catalog page.
    /// No implicit seal, TEARDOWN, deletion, or reset of an existing storage pause occurs.
    pub fn finish_capture(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Option<LiveRecordingRetirement>, LiveArchiveFailure> {
        self.admit(now, authority)?;
        if self.completion.is_some() {
            return Err(safe(LiveArchiveError::Closed));
        }
        let retired = self.recording.take().and_then(|mut r| r.cancel());
        self.completion = Some(LiveArchiveCompletion::OwnerStopped);
        self.writer
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .finish();
        self.pause(now);
        Ok(retired)
    }

    /// One storage step OR one existing capture step, never both kinds of I/O in one call.
    /// Publication cancellation must probe the live storage owner; network grants do not imply it.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<LiveArchiveStep, LiveArchiveFailure> {
        if self.finished || self.writer.is_none() {
            return Ok(LiveArchiveStep::Ended);
        }
        self.admit(now, authority)?;
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(self.fatal(
                LiveArchiveError::Archive(ArchiveError::Cancelled),
                None,
                None,
            ));
        }
        if !self.ready {
            let progress = match self
                .writer
                .as_mut()
                .ok_or_else(|| safe(LiveArchiveError::Closed))?
                .step(now, cancel)
            {
                Ok(progress) => progress,
                Err(error) => return Err(self.fatal(LiveArchiveError::Archive(error), None, None)),
            };
            if matches!(&progress, ArchiveWriteProgress::Ready { .. }) {
                self.ready = true;
                self.storage_since_ns = None;
            }
            if matches!(&progress, ArchiveWriteProgress::Finished { .. }) {
                let Some(cause) = self.completion else {
                    return Err(self.fatal(LiveArchiveError::Invariant, None, None));
                };
                self.finished = true;
                return Ok(LiveArchiveStep::Finished {
                    archive: progress,
                    cause,
                });
            }
            return Ok(LiveArchiveStep::Archive(progress));
        }
        let step = match self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveArchiveError::Closed))?
            .poll(readiness, now, authority)
        {
            Ok(step) => step,
            Err(error) => return Err(self.capture_failure(error)),
        };
        match step {
            LiveRecordingStep::Capture {
                event,
                connection: None,
            } if matches!(*event, CapturePoll::Window(_)) => {
                let CapturePoll::Window(window) = *event else {
                    return Err(self.fatal(LiveArchiveError::Invariant, None, None));
                };
                let result = self
                    .writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveArchiveError::Closed))?
                    .offer(window, self.max_window_bytes, now);
                match result {
                    Ok(admission) => {
                        self.pause(now);
                        Ok(LiveArchiveStep::WindowAccepted(admission))
                    }
                    Err(refusal) => Err(self.fatal(
                        LiveArchiveError::Archive(*refusal.reason),
                        None,
                        Some(*refusal.recording),
                    )),
                }
            }
            step @ LiveRecordingStep::Capture { .. }
                if matches!(step.capture_event(), Some(CapturePoll::Ended { .. })) =>
            {
                self.completion = Some(LiveArchiveCompletion::InputEnded);
                self.recording = None; // terminal step already owns all recording retirement
                self.writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveArchiveError::Closed))?
                    .finish();
                self.pause(now);
                Ok(LiveArchiveStep::Recording(Box::new(step)))
            }
            step if matches!(
                step,
                LiveRecordingStep::Stopped { .. } | LiveRecordingStep::Ended
            ) || matches!(step.capture_event(), Some(CapturePoll::Stopped { .. })) =>
            {
                let retained = self.retire(None, None);
                Ok(LiveArchiveStep::Stopped {
                    trigger: Box::new(step),
                    retained: Box::new(retained),
                })
            }
            other => Ok(LiveArchiveStep::Recording(Box::new(other))),
        }
    }

    /// Explicitly transfer pending work and close the socket. Never writes, repairs, or deletes.
    pub fn cancel(&mut self) -> Option<LiveArchiveRetirement> {
        if self.writer.is_none() && self.recording.is_none() {
            return None;
        }
        Some(self.retire(None, None))
    }
    fn require_input(&self) -> Result<(), LiveArchiveFailure> {
        if self.completion.is_some() {
            return Err(safe(LiveArchiveError::Closed));
        }
        if !self.ready {
            return Err(safe(LiveArchiveError::Backpressure));
        }
        Ok(())
    }
    fn pause(&mut self, now: u64) {
        self.ready = false;
        self.storage_since_ns = self.storage_since_ns.or(Some(now));
    }
    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveArchiveFailure> {
        if self.finished || self.writer.is_none() {
            return Err(safe(LiveArchiveError::Closed));
        }
        if now < self.last_ns {
            return Err(safe(LiveArchiveError::ClockReversed));
        }
        if self.remaining_steps == 0 {
            return Err(self.fatal(LiveArchiveError::WorkBudget, None, None));
        }
        self.remaining_steps -= 1;
        self.last_ns = now;
        if now >= self.publication_deadline_ns {
            return Err(self.fatal(LiveArchiveError::Deadline, None, None));
        }
        if self
            .storage_since_ns
            .is_some_and(|since| now - since >= self.max_storage_pause_ns)
        {
            return Err(self.fatal(LiveArchiveError::StoragePauseExpired, None, None));
        }
        // Input retirement ends network obligations, NOT storage authority. Final publication is
        // independently admitted by PublishCancellation and the absolute publication deadline.
        if self.completion.is_none() {
            let allowed = if now >= self.live_deadline_ns {
                Err(TcpDenial::Deadline)
            } else {
                authority.checkpoint(
                    &self.binding,
                    TcpOperation::Poll,
                    now,
                    self.live_deadline_ns,
                )
            };
            if let Err(error) = allowed {
                return Err(self.fatal(LiveArchiveError::Authority(error), None, None));
            }
        }
        Ok(())
    }
    fn capture_failure(&mut self, error: LiveRecordingFailure) -> LiveArchiveFailure {
        match error.retirement {
            Some(retired) => self.fatal(
                LiveArchiveError::Recording(Box::new(error.reason)),
                Some(*retired),
                None,
            ),
            None => safe(LiveArchiveError::Recording(Box::new(error.reason))),
        }
    }
    fn fatal(
        &mut self,
        reason: LiveArchiveError,
        recording: Option<LiveRecordingRetirement>,
        window: Option<PreparedRecording>,
    ) -> LiveArchiveFailure {
        LiveArchiveFailure {
            reason,
            retirement: Some(Box::new(self.retire(recording, window))),
        }
    }
    fn retire(
        &mut self,
        recording: Option<LiveRecordingRetirement>,
        window: Option<PreparedRecording>,
    ) -> LiveArchiveRetirement {
        let owned = self.recording.take().and_then(|mut r| r.cancel());
        self.finished = true;
        LiveArchiveRetirement {
            recording: recording.or(owned),
            archive: self.writer.take().map(|w| w.retire()),
            unoffered_window: window,
        }
    }
}
fn safe(reason: LiveArchiveError) -> LiveArchiveFailure {
    LiveArchiveFailure {
        reason,
        retirement: None,
    }
}

#[cfg(test)]
mod tests;

/// Opt-in live capture with independently pinned write-ahead work barriers.
pub mod checkpointed;
