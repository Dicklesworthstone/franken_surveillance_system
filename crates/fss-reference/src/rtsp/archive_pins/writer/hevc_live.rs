#![forbid(unsafe_code)]
//! Native automatic HEVC acquisition with independently journaled source protection.
//!
//! One existing recording owner feeds one existing HEVC archive writer. A pending
//! window or catalog blocks all subsequent camera work until candidate persistence,
//! work publication, confirmation and normal publication have drained. No source
//! queue, codec, durable format, recovery policy or credential store is introduced.

use std::fmt;

use super::{JournaledArchiveProgress, JournaledHevcArchiveRetirement, JournaledHevcArchiveWriter};
use crate::rtsp::archive_pins::{
    ArchivePinAnchor, ArchivePinError, ArchivePinState, HevcArchivePinJournal,
};
use crate::rtsp::authentication::DigestCredentials;
use crate::rtsp::client::ClientState;
use crate::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep, AutomaticLiveHevcRecording, LiveHevcRecordingConfig,
    LiveHevcRecordingError, LiveHevcRecordingFailure, LiveHevcRecordingRetirement,
};
use crate::rtsp::hevc_recording_capture::{HevcCapturePoll, TimedHevcCapture};
use crate::rtsp::hevc_recording_collector::HevcCollectionSeal;
use crate::rtsp::live_hevc::{LiveHevcConfig, SocketReadiness};
use crate::rtsp::recording::MAX_RECORDING_BYTES;
use crate::rtsp::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
use crate::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use crate::rtsp::recording_archive::hevc::{HevcArchiveNamespace, HevcArchiveSnapshot};
use crate::rtsp::recording_archive::{ArchiveAdmission, ArchiveLimits, ArchiveWriteProgress};
use crate::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpTotals};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

/// Finite policy for one native session and its independently authorized storage drain.
/// No default chooses a camera, permits plaintext, or grants retention authority.
#[derive(Clone, Debug)]
pub struct LiveHevcArchiveConfig {
    /// Exact HEVC sensor/generation/receive-clock/decode-clock/timescale namespace.
    pub namespace: HevcArchiveNamespace,
    /// Existing bounded discovery, inventory and immutable page limits.
    pub limits: ArchiveLimits,
    /// Maximum complete prepared window, not just encoded media bytes.
    pub max_window_bytes: usize,
    /// Finite outer admissions AND an independent ceiling on underlying writer calls.
    /// Timing, sealing and no-readiness polls also consume the outer allowance.
    pub max_steps: u64,
    /// Absolute storage lease, including final catalog draining after input has stopped.
    pub publication_deadline_ns: u64,
    /// Maximum continuous storage pause, including both independent pin phases.
    /// In 1 ns..=60 seconds; intermediate progress never renews this deadline.
    pub max_storage_pause_ns: u64,
}

/// Typed failures without private filesystem, credential or media diagnostics.
#[derive(Debug)]
pub enum LiveHevcArchiveError {
    /// Invalid cross-owner scope, ceilings or initial deadlines; no connection was attempted.
    Configuration,
    /// Existing recording/RTSP/TCP refusal, with terminal work transferred separately.
    Recording(Box<LiveHevcRecordingError>),
    /// Existing independent pin or source-publication error, possibly after a durable effect.
    Storage(ArchivePinError),
    /// The exact original network authority was withdrawn while input remained open.
    Authority(TcpDenial),
    /// Non-mutating refusal: admission time regressed.
    ClockReversed,
    /// The absolute publication lease expired.
    Deadline,
    /// A continuous storage pause exceeded its original bound.
    StoragePauseExpired,
    /// The outer finite work allowance was exhausted, not an EOF.
    WorkBudget,
    /// Drain the retained storage work before timing, sealing or flushing.
    Backpressure,
    /// Input or the complete driver has already ended.
    Closed,
    /// An impossible ordering was observed; no success or EOF is fabricated.
    Invariant,
}
impl fmt::Display for LiveHevcArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid live HEVC archive configuration",
            Self::Recording(_) => "live HEVC recording refused",
            Self::Storage(_) => "live HEVC archive requires storage reconciliation",
            Self::Authority(_) => "live HEVC archive authority refused",
            Self::ClockReversed => "live HEVC archive clock regressed",
            Self::Deadline => "live HEVC archive deadline expired",
            Self::StoragePauseExpired => "live HEVC archive storage pause expired",
            Self::WorkBudget => "live HEVC archive work allowance exhausted",
            Self::Backpressure => "live HEVC archive storage must drain first",
            Self::Closed => "live HEVC archive admission closed",
            Self::Invariant => "live HEVC archive ordering refused",
        })
    }
}
impl std::error::Error for LiveHevcArchiveError {}

/// Constructor failure, before any RTSP command or credential borrowing.
#[derive(Debug)]
pub struct LiveHevcArchiveConnectFailure {
    /// Payload-free failure stage.
    pub reason: LiveHevcArchiveError,
    /// A native connection attempt occurred, not a successful camera session.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveHevcArchiveConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveHevcArchiveConnectFailure {}

/// Complete unacknowledged work. Published objects and pin history are never rolled back.
#[must_use]
#[derive(Debug)]
pub struct LiveHevcArchiveRetirement {
    /// Socket uncertainty, unsealed source and the exact held capture event.
    /// Absent after a previously returned terminal step or explicit input stop transferred it.
    pub recording: Option<LiveHevcRecordingRetirement>,
    /// Pending source/catalog, both pin phases and any durable-but-unrecorded confirmation.
    pub archive: Option<JournaledHevcArchiveRetirement>,
    /// Original capture output rejected by archive admission or a failed finalization.
    /// This preserves even an EOF retirement when finishing the storage owner fails.
    pub unreturned_step: Option<Box<AutomaticHevcRecordingStep>>,
}

/// Safe timing/clock/backpressure refusals retain the live driver. Fatal failures transfer
/// every source, request, pending window and independent recovery obligation exactly once.
#[derive(Debug)]
pub struct LiveHevcArchiveFailure {
    /// Failure stage; never permission to retry an uncertain effect automatically.
    pub reason: LiveHevcArchiveError,
    /// Present only when this operation retired the complete driver.
    pub retirement: Option<Box<LiveHevcArchiveRetirement>>,
}
impl fmt::Display for LiveHevcArchiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveHevcArchiveFailure {}

/// Why the already admitted archive work was finally drained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveHevcArchiveCompletion {
    /// The recording owner ended. Its original events distinguish TCP EOF and bitstream EOB;
    /// this label alone asserts neither remote EOF nor a verified tail picture.
    RecordingEnded,
    /// The owner deliberately stopped input. Unsealed work was returned, NOT archived.
    OwnerStopped,
}

/// Distinct native, admission, pin, durability, indexing and finalization boundaries.
#[must_use]
#[derive(Debug)]
pub enum JournaledLiveHevcArchiveStep {
    /// Unchanged wire, challenge, control, timing, released source or terminal capture output.
    /// Prepared windows alone are intercepted and moved to the archive writer instead.
    Recording(Box<AutomaticHevcRecordingStep>),
    /// The exact prepared window was accepted in memory; it is not yet durable.
    WindowAccepted(ArchiveAdmission),
    /// Candidate synchronized, work confirmed, or ordinary archive progress, unchanged.
    Storage(JournaledArchiveProgress),
    /// All accepted windows and their final catalog drained; not a coverage certificate.
    Finished {
        /// The original writer's single completion receipt.
        archive: ArchiveWriteProgress,
        /// Recording termination and deliberate owner stop remain distinct.
        cause: LiveHevcArchiveCompletion,
    },
    /// Original source invalidation; no final catalog or synthetic EOF is manufactured.
    Stopped {
        /// Owns the original failed capture event and its terminal source/network receipts.
        trigger: Box<AutomaticHevcRecordingStep>,
        /// All remaining source, storage and independently journaled recovery work.
        retained: Box<LiveHevcArchiveRetirement>,
    },
    /// Terminal progress was already transferred; no repeated completion or publication.
    Ended,
}

/// Automatic native HEVC -> source-linked windows -> independently pinned durable archive.
///
/// The caller provides two already-open exclusive storage owners. The pin journal must be
/// protected independently of footage. Open verifies settled prior pins and recovers the
/// exact archive before connecting; pending recovery catalog work drains before DESCRIBE.
/// Every input admission revalidates the independent journal tip. Losing that owner closes
/// the camera even while ordinary archive storage is still available.
///
/// Poll performs one storage progress step OR one original recording step. It never advances
/// the socket while storage is pending, retries ambiguous publication, reconnects, guesses
/// picture timing, retains credentials or silently acknowledges a recovery pin. All original
/// outputs outside selected windows still require an explicit retention/omission decision.
#[must_use]
pub struct JournaledLiveHevcArchive<'a, 'p> {
    recording: Option<AutomaticLiveHevcRecording>,
    writer: Option<JournaledHevcArchiveWriter<'a, 'p>>,
    binding: TcpBinding,
    live_deadline_ns: u64,
    publication_deadline_ns: u64,
    max_window_bytes: usize,
    max_storage_pause_ns: u64,
    storage_since_ns: Option<u64>,
    remaining_steps: u64,
    last_ns: u64,
    ready: bool,
    completion: Option<LiveHevcArchiveCompletion>,
    finished: bool,
}
impl fmt::Debug for JournaledLiveHevcArchive<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledLiveHevcArchive")
            .field("ready", &self.ready)
            .field("completion", &self.completion)
            .field("remaining_steps", &self.remaining_steps)
            .finish_non_exhaustive()
    }
}
impl<'a, 'p> JournaledLiveHevcArchive<'a, 'p> {
    /// Validate exact scopes and all storage bounds before recovery or network access.
    /// Construction sends no RTSP command and borrows no credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        live: LiveHevcConfig,
        recording: LiveHevcRecordingConfig,
        archive: LiveHevcArchiveConfig,
        work: ArchiveWorkLimits,
        publisher: &'a mut LocalRootPublisher,
        pins: &'p mut HevcArchivePinJournal,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<Self, LiveHevcArchiveConnectFailure> {
        let refused = |reason| LiveHevcArchiveConnectFailure {
            reason,
            connection_attempted: false,
        };
        if archive.namespace.scope().recording != recording.scope
            || archive.namespace.scope().time_scale != recording.time_scale
            || recording.scope.generation != live.binding.key().generation
            || recording.limits.validate().is_err()
            || recording.payload_type > 127
            || archive.limits.validate().is_err()
            || work.validate(archive.limits).is_err()
            || archive.max_window_bytes > work.max_pending_bytes
            || work.max_new_bytes == 0
            || archive.max_steps == 0
            || live.max_steps == 0
            || !(1..=MAX_RECORDING_BYTES).contains(&archive.max_window_bytes)
            || !(1..=60_000_000_000).contains(&archive.max_storage_pause_ns)
            || now >= archive.publication_deadline_ns
            || now >= live.deadline_ns
        {
            return Err(refused(LiveHevcArchiveError::Configuration));
        }
        let binding = live.binding.clone();
        let live_deadline_ns = live.deadline_ns;
        let writer = JournaledHevcArchiveWriter::open(
            publisher,
            pins,
            archive.namespace,
            archive.limits,
            work,
            archive.max_steps,
            now,
            archive.publication_deadline_ns,
            cancel,
        )
        .map_err(|e| refused(LiveHevcArchiveError::Storage(e)))?;
        let recording = AutomaticLiveHevcRecording::connect(live, recording, now, authority)
            .map_err(|e| LiveHevcArchiveConnectFailure {
                reason: LiveHevcArchiveError::Recording(Box::new(e.reason)),
                connection_attempted: e.connection_attempted,
            })?;
        Ok(Self {
            recording: Some(recording),
            writer: Some(writer),
            binding,
            live_deadline_ns,
            publication_deadline_ns: archive.publication_deadline_ns,
            max_window_bytes: archive.max_window_bytes,
            max_storage_pause_ns: archive.max_storage_pause_ns,
            storage_since_ns: Some(now),
            remaining_steps: archive.max_steps,
            last_ns: now,
            ready: false,
            completion: None,
            finished: false,
        })
    }

    /// Existing protocol state, not recording, camera health or remote teardown proof.
    pub fn state(&self) -> ClientState {
        self.recording
            .as_ref()
            .map_or(ClientState::Closed, |r| r.state())
    }
    /// Actual transport accounting; final totals transfer in the original terminal outputs.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.recording.as_ref().and_then(|r| r.totals())
    }
    /// Only acknowledged ordinary HEVC windows and published catalog pages.
    pub fn snapshot(&self) -> Option<&HevcArchiveSnapshot> {
        self.writer.as_ref().map(|w| w.snapshot())
    }
    /// The sole pending immutable window, not a second source cache or durability receipt.
    pub fn pending(&self) -> Option<&PreparedHevcRecording> {
        self.writer.as_ref().and_then(|w| w.pending())
    }
    /// Independently retain this minimum journal prefix for cold recovery.
    pub fn journal_anchor(&self) -> Option<ArchivePinAnchor> {
        self.writer.as_ref().map(|w| w.journal_anchor())
    }
    /// Acknowledged candidate and predecessor; a candidate may still need recovery.
    pub fn pin_state(&self) -> Option<&ArchivePinState> {
        self.writer.as_ref().map(|w| w.pin_state())
    }
    /// Finite remaining outer calls, never replenished by progress or safe refusals.
    pub fn remaining_steps(&self) -> u64 {
        self.remaining_steps
    }
    /// True only when storage permits the original automatic control to borrow credentials.
    pub fn needs_credentials(&self) -> bool {
        self.ready
            && !self.finished
            && self.completion.is_none()
            && self
                .recording
                .as_ref()
                .is_some_and(|r| r.needs_credentials())
    }
    /// Storage is immediately runnable; otherwise retain the original capture/protocol wake.
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

    /// One original recording step OR one independently journaled publication step.
    /// A storage pause does not touch credentials, advance codec work or perform socket I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<JournaledLiveHevcArchiveStep, LiveHevcArchiveFailure> {
        if self.finished || self.writer.is_none() {
            return Ok(JournaledLiveHevcArchiveStep::Ended);
        }
        self.admit(now, authority, cancel)?;
        if !self.ready {
            let progress = match self
                .writer
                .as_mut()
                .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
                .step(now, cancel)
            {
                Ok(progress) => progress,
                Err(error) => {
                    return Err(self.fatal(LiveHevcArchiveError::Storage(error), None, None));
                }
            };
            if matches!(
                &progress,
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::Ready { .. })
            ) {
                if self.completion.is_some() {
                    return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
                }
                self.ready = true;
                self.storage_since_ns = None;
            }
            if let JournaledArchiveProgress::Archive(
                archive @ ArchiveWriteProgress::Finished { .. },
            ) = progress
            {
                let Some(cause) = self.completion else {
                    return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
                };
                self.finished = true;
                return Ok(JournaledLiveHevcArchiveStep::Finished { archive, cause });
            }
            if matches!(
                &progress,
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::Exhausted)
            ) {
                return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
            }
            return Ok(JournaledLiveHevcArchiveStep::Storage(progress));
        }
        let step = match self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .poll(readiness, credentials, cnonce, now, authority)
        {
            Ok(step) => step,
            Err(error) => return Err(self.capture_failure(error)),
        };
        match step {
            AutomaticHevcRecordingStep::Capture {
                event,
                connection: None,
            } if matches!(event.as_ref(), HevcCapturePoll::Window(_)) => {
                let window = match *event {
                    HevcCapturePoll::Window(window) => window,
                    other => {
                        let original = AutomaticHevcRecordingStep::Capture {
                            event: Box::new(other),
                            connection: None,
                        };
                        return Err(self.fatal(
                            LiveHevcArchiveError::Invariant,
                            None,
                            Some(Box::new(original)),
                        ));
                    }
                };
                let result = self
                    .writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
                    .offer(*window, self.max_window_bytes, now);
                match result {
                    Ok(admission) => {
                        self.pause(now);
                        Ok(JournaledLiveHevcArchiveStep::WindowAccepted(admission))
                    }
                    Err(refusal) => {
                        let original = AutomaticHevcRecordingStep::Capture {
                            event: Box::new(HevcCapturePoll::Window(refusal.recording)),
                            connection: None,
                        };
                        Err(self.fatal(
                            LiveHevcArchiveError::Storage(ArchivePinError::Archive(
                                *refusal.reason,
                            )),
                            None,
                            Some(Box::new(original)),
                        ))
                    }
                }
            }
            original @ AutomaticHevcRecordingStep::Capture { .. }
                if matches!(
                    capture_event(&original),
                    Some(HevcCapturePoll::Ended { .. })
                ) =>
            {
                let result = self
                    .writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
                    .finish(now);
                if let Err(error) = result {
                    return Err(self.fatal(
                        LiveHevcArchiveError::Storage(error),
                        None,
                        Some(Box::new(original)),
                    ));
                }
                self.recording = None; // The original terminal output owns all capture retirement.
                self.completion = Some(LiveHevcArchiveCompletion::RecordingEnded);
                self.pause(now);
                Ok(JournaledLiveHevcArchiveStep::Recording(Box::new(original)))
            }
            original @ AutomaticHevcRecordingStep::Capture { .. }
                if matches!(
                    capture_event(&original),
                    Some(HevcCapturePoll::Stopped { .. })
                ) =>
            {
                let retained = self.retire(None, None);
                Ok(JournaledLiveHevcArchiveStep::Stopped {
                    trigger: Box::new(original),
                    retained: Box::new(retained),
                })
            }
            original @ AutomaticHevcRecordingStep::Ended => Err(self.fatal(
                LiveHevcArchiveError::Invariant,
                None,
                Some(Box::new(original)),
            )),
            original if matches!(capture_event(&original), Some(HevcCapturePoll::Window(_))) => {
                // A window with terminal connection ownership cannot silently lose that owner.
                Err(self.fatal(
                    LiveHevcArchiveError::Invariant,
                    None,
                    Some(Box::new(original)),
                ))
            }
            original => Ok(JournaledLiveHevcArchiveStep::Recording(Box::new(original))),
        }
    }

    /// Supply explicit timing only to the existing held picture. No RTP/arrival-time guessing.
    pub fn supply_timing(
        &mut self,
        timing: HevcRecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<TimedHevcCapture, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .supply_timing(timing, now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Seal an actually completed prefix. Released source still requires caller custody;
    /// the prepared window reaches pin protection only on a subsequent poll.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<HevcCollectionSeal, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        self.require_input()?;
        let result = self
            .recording
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .seal(now, authority);
        result.map_err(|e| self.capture_failure(e))
    }
    /// Flush an acknowledged tail through its own pin/work barrier without ending input.
    pub fn flush(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<(), LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        self.require_input()?;
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .flush(now);
        if let Err(error) = result {
            return Err(self.fatal(LiveHevcArchiveError::Storage(error), None, None));
        }
        self.pause(now);
        Ok(())
    }
    /// Deliberately stop the socket and transfer all unsealed/unadmitted work immediately.
    /// Poll drains ONLY previously admitted windows/catalogs; no automatic seal or fake EOF.
    pub fn finish_capture(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<Option<LiveHevcRecordingRetirement>, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        if self.completion.is_some() {
            return Err(safe(LiveHevcArchiveError::Closed));
        }
        // Finish can refuse on a writer budget. Keep capture ownership until it succeeds.
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .finish(now);
        if let Err(error) = result {
            return Err(self.fatal(LiveHevcArchiveError::Storage(error), None, None));
        }
        let retired = self.recording.take().and_then(|mut r| r.cancel());
        self.completion = Some(LiveHevcArchiveCompletion::OwnerStopped);
        self.pause(now);
        Ok(retired)
    }
    /// Transfer every remaining original and recovery receipt without I/O, even after revocation.
    /// Published storage and independent pin history remain untouched. Repetition returns None.
    pub fn cancel(&mut self) -> Option<LiveHevcArchiveRetirement> {
        if self.writer.is_none() && self.recording.is_none() {
            return None;
        }
        Some(self.retire(None, None))
    }
    fn require_input(&self) -> Result<(), LiveHevcArchiveFailure> {
        if self.completion.is_some() || self.recording.is_none() {
            return Err(safe(LiveHevcArchiveError::Closed));
        }
        if !self.ready {
            return Err(safe(LiveHevcArchiveError::Backpressure));
        }
        Ok(())
    }
    fn pause(&mut self, now: u64) {
        self.ready = false;
        self.storage_since_ns = self.storage_since_ns.or(Some(now));
    }
    fn admit(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<(), LiveHevcArchiveFailure> {
        if self.finished || self.writer.is_none() {
            return Err(safe(LiveHevcArchiveError::Closed));
        }
        if now < self.last_ns {
            return Err(safe(LiveHevcArchiveError::ClockReversed));
        }
        if self.remaining_steps == 0 {
            return Err(self.fatal(LiveHevcArchiveError::WorkBudget, None, None));
        }
        self.remaining_steps -= 1;
        self.last_ns = now;
        if now >= self.publication_deadline_ns {
            return Err(self.fatal(LiveHevcArchiveError::Deadline, None, None));
        }
        if self
            .storage_since_ns
            .is_some_and(|since| now - since >= self.max_storage_pause_ns)
        {
            return Err(self.fatal(LiveHevcArchiveError::StoragePauseExpired, None, None));
        }
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
                return Err(self.fatal(LiveHevcArchiveError::Authority(error), None, None));
            }
        }
        // Storage authority continues after input retirement. Network permission never grants it.
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(self.fatal(
                LiveHevcArchiveError::Storage(ArchivePinError::Cancelled),
                None,
                None,
            ));
        }
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .verify_pins(cancel);
        result.map_err(|e| self.fatal(LiveHevcArchiveError::Storage(e), None, None))
    }
    fn capture_failure(&mut self, error: LiveHevcRecordingFailure) -> LiveHevcArchiveFailure {
        match error.retirement {
            Some(retired) => self.fatal(
                LiveHevcArchiveError::Recording(Box::new(error.reason)),
                Some(*retired),
                None,
            ),
            None => safe(LiveHevcArchiveError::Recording(Box::new(error.reason))),
        }
    }
    fn fatal(
        &mut self,
        reason: LiveHevcArchiveError,
        recording: Option<LiveHevcRecordingRetirement>,
        unreturned_step: Option<Box<AutomaticHevcRecordingStep>>,
    ) -> LiveHevcArchiveFailure {
        LiveHevcArchiveFailure {
            reason,
            retirement: Some(Box::new(self.retire(recording, unreturned_step))),
        }
    }
    fn retire(
        &mut self,
        recording: Option<LiveHevcRecordingRetirement>,
        unreturned_step: Option<Box<AutomaticHevcRecordingStep>>,
    ) -> LiveHevcArchiveRetirement {
        let owned = self.recording.take().and_then(|mut r| r.cancel());
        self.finished = true;
        LiveHevcArchiveRetirement {
            recording: recording.or(owned),
            archive: self.writer.take().map(|w| w.retire()),
            unreturned_step,
        }
    }
}
fn capture_event(step: &AutomaticHevcRecordingStep) -> Option<&HevcCapturePoll> {
    match step {
        AutomaticHevcRecordingStep::Capture { event, .. } => Some(event),
        _ => None,
    }
}
fn safe(reason: LiveHevcArchiveError) -> LiveHevcArchiveFailure {
    LiveHevcArchiveFailure {
        reason,
        retirement: None,
    }
}
