#![forbid(unsafe_code)]
//! Native selected-SDP HEVC capture with independent source-protection journal barriers.
//!
//! One immutable configuration belongs to one accepted media offer. Completed pictures retain
//! their real prefix/AUD/end witnesses; markers and socket EOF never fabricate a boundary.
//! Storage pauses the whole live path. Explicit input retirement can precede checkpoint I/O,
//! after which only already-admitted windows drain under the separate publication deadline.

use std::fmt;

use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};
use fss_publication::{LocalRootPublisher, PublishCancellation};

use super::archive_pins::{
    ArchivePinAnchor, ArchivePinError, ArchivePinState, HevcArchivePinJournal,
    JournaledArchiveProgress, JournaledHevcArchiveRetirement, JournaledHevcArchiveWriter,
};
use super::authentication::DigestCredentials;
use super::client::{ClientCommand, ClientState};
use super::hevc_client::HevcClientError;
use super::hevc_client::pictures::{HevcPictureClientError, HevcPictureClientPoll as Event};
use super::hevc_recording_capture::live::{AutomaticHevcRecordingStep, Control, control};
use super::hevc_recording_capture::{
    CaptureError, HevcCapturePoll, HevcCaptureRetirement, HevcRecordingCapture, TimedHevcCapture,
};
use super::hevc_recording_collector::{HevcCollectionSeal, HevcRecordingCollector};
use super::live_archive::LiveArchiveCompletion;
use super::live_hevc::{
    LiveHevcConfig, LiveHevcConnection, LiveHevcError, LiveHevcFailure, LiveHevcRetirement,
    LiveHevcStep, SocketReadiness,
};
use super::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
use super::recording::{MAX_RECORDING_BYTES, RecordingScope};
use super::recording_archive::checkpoint::ArchiveWorkLimits;
use super::recording_archive::hevc::{HevcArchiveNamespace, HevcArchiveSnapshot};
use super::recording_archive::{
    ArchiveAdmission, ArchiveError, ArchiveLimits, ArchiveWriteProgress,
};
use super::recording_collector::CollectorLimits;
use super::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpOperation, TcpRetirement, TcpTotals};

/// Owner limits and identity for a configuration obtained from the exact selected description.
/// The current HEVC session profile admits one payload offer, and this owner additionally requires
/// exactly one VPS, SPS and PPS. Missing or ambiguous configuration is refused before SETUP/PLAY.
#[derive(Clone, Debug)]
pub struct SelectedHevcRecordingConfig {
    /// Canonical sensor, stream, generation and receive-clock provenance.
    pub scope: RecordingScope,
    /// Exact expected RTP payload type; no fallback to another offer or payload is allowed.
    pub payload_type: u8,
    /// Explicit media timescale; neither arrival time nor RTP supplies decode timing.
    pub time_scale: u32,
    /// Independent original-source, picture, age and metadata bounds.
    pub limits: CollectorLimits,
    /// Owner-supplied parameter, coded-dimension and luma bounds applied before installing
    /// the selected recording configuration. The session's SDP bounds also remain in force.
    pub configuration_limits: HevcConfigurationLimits,
}

/// Finite storage policy for the codec-specific archive and its protected final drain.
#[derive(Clone, Debug)]
pub struct LiveHevcArchiveConfig {
    /// HEVC-only immutable window/catalog routing and explicit recording/decode-clock scope.
    pub namespace: HevcArchiveNamespace,
    /// Bounded inventory and immutable page sizes.
    pub limits: ArchiveLimits,
    /// Complete prepared recording allowance, including original source and all children.
    pub max_window_bytes: usize,
    /// Finite outer request, poll, timing, sealing and finalization admissions.
    pub max_steps: u64,
    /// Absolute storage deadline, including the drain after input closes.
    pub publication_deadline_ns: u64,
    /// Maximum continuous storage pause, in 1 ns..=60 seconds; no progress resets this pause.
    pub max_storage_pause_ns: u64,
}

/// Payload-free stage information; none of these outcomes authorizes an implicit retry.
#[derive(Debug)]
pub enum LiveHevcArchiveError {
    /// Invalid scope, policy, bounds or initial lease; no connection is attempted.
    Configuration,
    /// Selected SDP payload or exact VPS/SPS/PPS tuple was absent, ambiguous or unsupported.
    Selection,
    /// Original native transport, protocol or HEVC acquisition refusal.
    Network(LiveHevcError),
    /// Original timing, collection or sealing refusal.
    Capture(CaptureError),
    /// Ordinary recording/catalog publication or admission failure.
    Archive(ArchiveError),
    /// Independent journal or write-ahead protection failed and needs reconciliation.
    Pins(ArchivePinError),
    /// The live route's grant expired or was withdrawn before input retirement.
    Authority(TcpDenial),
    /// Monotonic admission time reversed; this refusal changes no state.
    ClockReversed,
    /// Absolute publication deadline expired.
    Deadline,
    /// The current continuous storage pause reached its bound.
    StoragePauseExpired,
    /// Finite outer work allowance was exhausted.
    WorkBudget,
    /// Previously admitted storage must drain before another timing, seal or flush.
    Backpressure,
    /// Input or terminal ownership has already closed.
    Closed,
    /// An impossible transition was refused without inventing EOF or completion.
    Invariant,
}
impl fmt::Display for LiveHevcArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid live HEVC archive configuration",
            Self::Selection => "selected HEVC configuration refused",
            Self::Network(_) => "live HEVC archive input refused",
            Self::Capture(_) => "live HEVC archive collection refused",
            Self::Archive(_) => "live HEVC archive publication requires reconciliation",
            Self::Pins(_) => "live HEVC archive protection requires reconciliation",
            Self::Authority(_) => "live HEVC archive authority refused",
            Self::ClockReversed => "live HEVC archive clock regressed",
            Self::Deadline => "live HEVC archive publication deadline expired",
            Self::StoragePauseExpired => "live HEVC archive storage pause expired",
            Self::WorkBudget => "live HEVC archive work allowance exhausted",
            Self::Backpressure => "live HEVC archive storage must drain first",
            Self::Closed => "live HEVC archive admission closed",
            Self::Invariant => "live HEVC archive state refused",
        })
    }
}
impl std::error::Error for LiveHevcArchiveError {}

/// Recovery and policy preflight precede any native connection attempt.
#[derive(Debug)]
pub struct LiveHevcArchiveConnectFailure {
    /// Typed failure without payload, credential, address or path disclosure.
    pub reason: LiveHevcArchiveError,
    /// A connection was attempted, not a successful RTSP session or capture.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveHevcArchiveConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveHevcArchiveConnectFailure {}

/// Input ownership, including failures before the selected description created a collector.
#[must_use]
#[derive(Debug)]
pub struct SelectedHevcRecordingRetirement {
    /// Buffered wire, remote-session uncertainty and unfinished packet/picture work.
    /// Absent when an earlier native terminal event already transferred this ownership.
    pub connection: Option<LiveHevcRetirement>,
    /// Exact unsealed originals and any held picture; absent before SDP initialization.
    pub capture: Option<HevcCaptureRetirement>,
    /// Original event refused before the capture owner accepted it.
    pub unoffered_event: Option<Box<Event>>,
    /// Terminal socket receipt accompanying such an unoffered event.
    pub terminal_transport: Option<Box<TcpRetirement>>,
}

/// Exact unacknowledged source plus independently retained work-root candidates.
#[must_use]
#[derive(Debug)]
pub struct LiveHevcArchiveRetirement {
    /// Remaining input, unless a returned terminal event already owns it.
    pub recording: Option<SelectedHevcRecordingRetirement>,
    /// Native HEVC pending work, acknowledged inventory, journal pins and uncertain confirmation.
    pub archive: Option<JournaledHevcArchiveRetirement>,
    /// An exact window refused before the writer took ownership; never a durability claim.
    pub unoffered_window: Option<PreparedHevcRecording>,
}

/// Safe timing corrections preserve the owner; fatal failures transfer all remaining work once.
#[derive(Debug)]
pub struct LiveHevcArchiveFailure {
    /// Original failure stage, not authorization to retry an ambiguous effect.
    pub reason: LiveHevcArchiveError,
    /// Present only if this call closed the owner and transferred its complete remaining state.
    pub retirement: Option<Box<LiveHevcArchiveRetirement>>,
}
impl fmt::Display for LiveHevcArchiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveHevcArchiveFailure {}

/// Capture, admission, protected publication and indexing are separate observations.
#[must_use]
#[derive(Debug)]
pub enum LiveHevcArchiveStep {
    /// Original acquisition/capture output, except a successful prepared window owned by the writer.
    /// Before SDP initialization, protocol/auth originals are returned as Network::Protocol.
    Recording(Box<AutomaticHevcRecordingStep>),
    /// In-memory admission of the exact native HEVC recording; no storage receipt yet.
    WindowAccepted(ArchiveAdmission),
    /// Independent pin/work synchronization or ordinary archive publication progress.
    Archive(Box<JournaledArchiveProgress>),
    /// Accepted windows and final catalog finished under the independent storage deadline.
    Finished {
        /// Exact existing writer completion, including snapshot and inventory counts.
        archive: ArchiveWriteProgress,
        /// Observed source termination (EOF/EOB) and explicit owner stop remain distinguishable.
        cause: LiveArchiveCompletion,
    },
    /// Input invalidation stopped progress without sealing unsafe work or fabricating EOF.
    Stopped {
        /// Original source-bearing trigger, which may itself own terminal input.
        trigger: Box<AutomaticHevcRecordingStep>,
        /// All other remaining capture, archive and pin obligations.
        retained: Box<LiveHevcArchiveRetirement>,
    },
    /// Terminal output already transferred; no repeated completion or publication receipt.
    Ended,
}

/// One authorized socket, one selected configuration, one capture slot and one protected writer.
///
/// Storage work never reads the socket. Input is closed immediately by finish_capture, even
/// after WindowAccepted and before its first checkpoint. Source admitted to the writer remains
/// protected by the same pin -> work -> confirmation -> window/page barriers as cold HEVC work.
#[must_use]
pub struct JournaledLiveHevcArchive<'a, 'p> {
    connection: Option<LiveHevcConnection>,
    capture: Option<HevcRecordingCapture>,
    selected: Option<SelectedHevcRecordingConfig>,
    writer: Option<JournaledHevcArchiveWriter<'a, 'p>>,
    binding: TcpBinding,
    live_deadline_ns: u64,
    publication_deadline_ns: u64,
    max_window_bytes: usize,
    remaining_steps: u64,
    max_storage_pause_ns: u64,
    storage_since_ns: Option<u64>,
    last_ns: u64,
    ready: bool,
    next: Option<Control>,
    control_blocked: bool,
    network_ended: bool,
    completion: Option<LiveArchiveCompletion>,
    finished: bool,
    last_anchor: ArchivePinAnchor,
    last_pins: ArchivePinState,
}
impl fmt::Debug for JournaledLiveHevcArchive<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledLiveHevcArchive")
            .field("state", &self.state())
            .field("configured", &self.capture.is_some())
            .field("ready", &self.ready)
            .field("completion", &self.completion)
            .field("remaining_steps", &self.remaining_steps)
            .finish_non_exhaustive()
    }
}
impl<'a, 'p> JournaledLiveHevcArchive<'a, 'p> {
    /// Validate all owner ceilings and settled protected HEVC history before connecting once.
    /// SDP supplies only the exact selected configuration, never authority or capture timing.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        live: LiveHevcConfig,
        recording: SelectedHevcRecordingConfig,
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
            || live.binding.key().ingress == 0
            || live.binding.key().generation == 0
            || recording.payload_type > 127
            || recording.time_scale == 0
            || recording.limits.validate().is_err()
            || recording.configuration_limits.validate().is_err()
            || archive.limits.validate().is_err()
            || work.validate(archive.limits).is_err()
            || work.max_new_bytes == 0
            || archive.max_window_bytes > work.max_pending_bytes
            || !(1..=MAX_RECORDING_BYTES).contains(&archive.max_window_bytes)
            || !(1..=60_000_000_000).contains(&archive.max_storage_pause_ns)
            || archive.max_steps == 0
            || now >= live.deadline_ns
            || live.deadline_ns > archive.publication_deadline_ns
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
        .map_err(|e| refused(LiveHevcArchiveError::Pins(e)))?;
        let connection = LiveHevcConnection::connect(live, now, authority).map_err(|e| {
            LiveHevcArchiveConnectFailure {
                reason: LiveHevcArchiveError::Network(e.reason),
                connection_attempted: e.connection_attempted,
            }
        })?;
        let last_anchor = writer.journal_anchor();
        let last_pins = writer.pin_state().clone();
        Ok(Self {
            connection: Some(connection),
            capture: None,
            selected: Some(recording),
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
            next: Some(Control::Request(ClientCommand::Describe)),
            control_blocked: false,
            network_ended: false,
            completion: None,
            finished: false,
            last_anchor,
            last_pins,
        })
    }
    /// Acknowledged native HEVC inventory only, absent after terminal ownership transfers.
    pub fn snapshot(&self) -> Option<&HevcArchiveSnapshot> {
        self.writer.as_ref().map(|w| w.snapshot())
    }
    /// Exact accepted pending window, without copying original source payload.
    pub fn pending(&self) -> Option<&PreparedHevcRecording> {
        self.writer.as_ref().and_then(|w| w.pending())
    }
    /// Native protocol state; Playing does not prove complete pictures or custody.
    pub fn state(&self) -> ClientState {
        self.connection
            .as_ref()
            .map_or(ClientState::Closed, |c| c.state())
    }
    /// Actual transport observations, absent after input retirement transfers them.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.connection.as_ref().and_then(|c| c.totals())
    }
    /// Last acknowledged protected journal prefix, also retained after terminal transfer.
    pub fn journal_anchor(&self) -> ArchivePinAnchor {
        self.writer
            .as_ref()
            .map_or(self.last_anchor, |w| w.journal_anchor())
    }
    /// Candidate/predecessor metadata, never a substitute for current source verification.
    pub fn pin_state(&self) -> &ArchivePinState {
        self.writer
            .as_ref()
            .map_or(&self.last_pins, |w| w.pin_state())
    }
    /// Whether the next poll can borrow credentials for one automatic preparation.
    /// No credentials or cnonce are retained during storage/capture backpressure.
    pub fn needs_credentials(&self) -> bool {
        !self.finished
            && self.completion.is_none()
            && !self.network_ended
            && self.ready
            && self.next.is_some()
            && !self.control_blocked
            && !self.capture_busy()
    }
    /// Whether an actual held challenge awaits the owner. Callers without credential authority
    /// must stop here instead of supplying placeholder secrets to a subsequent automatic poll.
    pub fn requires_authentication(&self) -> bool {
        self.completion.is_none() && !self.finished && matches!(self.next, Some(Control::Respond))
    }
    /// Earliest useful owner wake. Storage is immediately runnable; blocked input does not
    /// manufacture a busy wake or renew collection, protocol, live or publication deadlines.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.finished || self.writer.is_none() {
            return None;
        }
        let mut at = self.publication_deadline_ns;
        if let Some(since) = self.storage_since_ns {
            at = at.min(since.saturating_add(self.max_storage_pause_ns));
        }
        if !self.ready {
            return Some(at.min(self.last_ns));
        }
        // EOF sealing still has a ready window and final capture retirement to transfer.
        // Its collector is closed, so this wake cannot retain an expired source deadline.
        if let Some(wake) = self.capture.as_ref().and_then(|c| c.next_wake_ns()) {
            at = at.min(wake);
        }
        if self.completion.is_none() {
            at = at.min(self.live_deadline_ns);
            if self.needs_credentials() {
                at = at.min(self.last_ns);
            } else if !self.capture_busy()
                && !self.network_ended
                && let Some(wake) = self.connection.as_ref().and_then(|c| c.next_wake_ns())
            {
                at = at.min(wake);
            }
        }
        Some(at)
    }
    /// Supply independent timing for the exact held, source-closed HEVC picture.
    /// Safe timing errors keep the original picture and its fixed residence deadline intact.
    pub fn supply_timing(
        &mut self,
        timing: HevcRecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<TimedHevcCapture, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        self.require_input()?;
        self.capture
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Selection))?
            .supply_timing(timing, now)
            .map_err(|e| safe(LiveHevcArchiveError::Capture(e)))
    }
    /// Seal only an actually completed prefix with its real final boundary witness packet.
    /// Released original packets remain caller-owned; some may already occur in prepared custody.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<HevcCollectionSeal, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        self.require_input()?;
        self.capture
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Selection))?
            .seal(now)
            .map_err(|e| safe(LiveHevcArchiveError::Capture(e)))
    }
    /// Request an immutable catalog page through its independent pin/work protection.
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
            return Err(self.fatal(LiveHevcArchiveError::Pins(error), None, None));
        }
        self.pause(now);
        Ok(())
    }
    /// Close input now, including at WindowAccepted before any checkpoint publication.
    /// No seal, EOF or remote TEARDOWN is fabricated. Accepted windows drain independently;
    /// untimed, incomplete and unsealed source transfers immediately and is not called archived.
    pub fn finish_capture(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<Option<SelectedHevcRecordingRetirement>, LiveHevcArchiveFailure> {
        self.admit(now, authority, cancel)?;
        if self.completion.is_some() {
            return Err(safe(LiveHevcArchiveError::Closed));
        }
        let recording = self.retire_input(None, None, None);
        self.completion = Some(LiveArchiveCompletion::OwnerStopped);
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .finish(now);
        if let Err(error) = result {
            return Err(self.fatal(LiveHevcArchiveError::Pins(error), recording, None));
        }
        self.pause(now);
        Ok(recording)
    }
    /// One protected storage step OR one existing capture/control/socket step.
    /// Borrow fresh cnonce entropy only when needs_credentials is true. The caller owns secret
    /// acquisition policy and must refuse a held challenge if it lacks credential authority.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        if self.finished || self.writer.is_none() {
            return Ok(LiveHevcArchiveStep::Ended);
        }
        self.admit(now, authority, cancel)?;
        if !self.ready {
            return self.storage_step(now, cancel);
        }
        if let Some(capture) = self.capture.as_mut() {
            match capture.poll(now) {
                Ok(HevcCapturePoll::Pending { .. }) => {}
                Ok(event) => return self.capture_step(event, now),
                Err(error) => {
                    return Err(self.fatal(LiveHevcArchiveError::Capture(error), None, None));
                }
            }
        }
        if self.network_ended || self.completion.is_some() {
            return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
        }
        if let Some(action) = self.next.filter(|_| !self.control_blocked) {
            let connection = self
                .connection
                .as_mut()
                .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?;
            let result = match action {
                Control::Request(command) => {
                    connection.request(command, credentials, cnonce, now, authority)
                }
                Control::Respond => connection.respond(credentials, cnonce, now, authority),
            };
            return match result {
                Ok(queued) => {
                    self.next = None;
                    Ok(LiveHevcArchiveStep::Recording(Box::new(
                        AutomaticHevcRecordingStep::Queued(queued),
                    )))
                }
                Err(failure) => {
                    if failure.retirement.is_none()
                        && matches!(
                            &failure.reason,
                            LiveHevcError::Backpressure
                                | LiveHevcError::Protocol(HevcPictureClientError::Backpressure)
                                | LiveHevcError::Protocol(HevcPictureClientError::Client(
                                    HevcClientError::Backpressure
                                ))
                        )
                    {
                        self.control_blocked = true;
                    }
                    Err(self.network_failure(failure))
                }
            };
        }
        let result = self
            .connection
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .poll(readiness, now, authority);
        let step = match result {
            Ok(step) => step,
            Err(failure) => return Err(self.network_failure(failure)),
        };
        match step {
            LiveHevcStep::Protocol { event, transport } => {
                self.protocol_step(event, transport, now)
            }
            LiveHevcStep::Pending(mut wait) => {
                self.control_blocked = false;
                wait.wake_at_ns = self.next_wake_ns();
                Ok(LiveHevcArchiveStep::Recording(Box::new(
                    AutomaticHevcRecordingStep::Network(LiveHevcStep::Pending(wait)),
                )))
            }
            LiveHevcStep::Ended => Err(self.fatal(LiveHevcArchiveError::Invariant, None, None)),
            other => Ok(LiveHevcArchiveStep::Recording(Box::new(
                AutomaticHevcRecordingStep::Network(other),
            ))),
        }
    }
    /// Close and transfer work without any storage write, source deletion or implicit recovery.
    pub fn cancel(&mut self) -> Option<LiveHevcArchiveRetirement> {
        if self.writer.is_none() && self.connection.is_none() && self.capture.is_none() {
            return None;
        }
        Some(self.retire(None, None))
    }
    fn capture_busy(&self) -> bool {
        self.capture.as_ref().is_some_and(|c| c.busy())
    }
    fn require_input(&self) -> Result<(), LiveHevcArchiveFailure> {
        if self.completion.is_some() {
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
        // Once input ownership transfers, only publication authority/deadlines remain relevant.
        if self.completion.is_none() {
            let result = if now >= self.live_deadline_ns {
                Err(TcpDenial::Deadline)
            } else {
                authority.checkpoint(
                    &self.binding,
                    TcpOperation::Poll,
                    now,
                    self.live_deadline_ns,
                )
            };
            if let Err(error) = result {
                return Err(self.fatal(LiveHevcArchiveError::Authority(error), None, None));
            }
        }
        let checked = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .verify_pins(cancel);
        if let Err(error) = checked {
            return Err(self.fatal(LiveHevcArchiveError::Pins(error), None, None));
        }
        Ok(())
    }
    fn storage_step(
        &mut self,
        now: u64,
        cancel: &dyn PublishCancellation,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        let result = self
            .writer
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
            .step(now, cancel);
        let progress = match result {
            Ok(progress) => progress,
            Err(error) => return Err(self.fatal(LiveHevcArchiveError::Pins(error), None, None)),
        };
        if matches!(
            &progress,
            JournaledArchiveProgress::Archive(ArchiveWriteProgress::Ready { .. })
        ) {
            self.ready = true;
            self.storage_since_ns = None;
        }
        match progress {
            JournaledArchiveProgress::Archive(archive @ ArchiveWriteProgress::Finished { .. }) => {
                let Some(cause) = self.completion else {
                    return Err(self.fatal(LiveHevcArchiveError::Invariant, None, None));
                };
                self.finished = true;
                Ok(LiveHevcArchiveStep::Finished { archive, cause })
            }
            progress => Ok(LiveHevcArchiveStep::Archive(Box::new(progress))),
        }
    }
    fn capture_step(
        &mut self,
        event: HevcCapturePoll,
        now: u64,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        match event {
            HevcCapturePoll::Window(window) => {
                let result = self
                    .writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
                    .offer(*window, self.max_window_bytes, now);
                match result {
                    Ok(admission) => {
                        self.pause(now);
                        Ok(LiveHevcArchiveStep::WindowAccepted(admission))
                    }
                    Err(refusal) => Err(self.fatal(
                        LiveHevcArchiveError::Archive(*refusal.reason),
                        None,
                        Some(*refusal.recording),
                    )),
                }
            }
            HevcCapturePoll::Sealed(seal) => {
                // Only collector.finish emits this event: admitted source input has drained
                // after an observed EOF or EOB. This does not assert physical TCP EOF.
                // Retire the live grant before the final window crosses its checkpoint barrier,
                // but keep capture ownership until Window and Ended transfer its exact source.
                self.completion = Some(LiveArchiveCompletion::InputEnded);
                self.next = None;
                self.control_blocked = false;
                self.network_ended = true;
                let connection = self
                    .connection
                    .take()
                    .and_then(|mut c| c.cancel())
                    .map(Box::new);
                Ok(LiveHevcArchiveStep::Recording(Box::new(
                    AutomaticHevcRecordingStep::Capture {
                        event: Box::new(HevcCapturePoll::Sealed(seal)),
                        connection,
                    },
                )))
            }
            HevcCapturePoll::Ended { retained } => {
                self.capture = None; // the returned event already owns its exact final capture state
                let connection = self.connection.take().and_then(|mut c| c.cancel());
                self.next = None;
                self.completion = Some(LiveArchiveCompletion::InputEnded);
                let result = self
                    .writer
                    .as_mut()
                    .ok_or_else(|| safe(LiveHevcArchiveError::Closed))?
                    .finish(now);
                if let Err(error) = result {
                    let recording = Some(SelectedHevcRecordingRetirement {
                        connection,
                        capture: retained.map(|c| *c),
                        unoffered_event: None,
                        terminal_transport: None,
                    });
                    return Err(self.fatal(LiveHevcArchiveError::Pins(error), recording, None));
                }
                self.pause(now);
                Ok(LiveHevcArchiveStep::Recording(Box::new(
                    AutomaticHevcRecordingStep::Capture {
                        event: Box::new(HevcCapturePoll::Ended { retained }),
                        connection: connection.map(Box::new),
                    },
                )))
            }
            event @ HevcCapturePoll::Stopped { .. } => {
                self.capture = None; // Stopped owns the complete capture retirement
                let connection = self
                    .connection
                    .take()
                    .and_then(|mut c| c.cancel())
                    .map(Box::new);
                let retained = self.retire(None, None);
                Ok(LiveHevcArchiveStep::Stopped {
                    trigger: Box::new(AutomaticHevcRecordingStep::Capture {
                        event: Box::new(event),
                        connection,
                    }),
                    retained: Box::new(retained),
                })
            }
            other => {
                if let HevcCapturePoll::Receiver(source) = &other
                    && let Some(next) = control(source)
                {
                    self.next = Some(next);
                }
                Ok(LiveHevcArchiveStep::Recording(Box::new(
                    AutomaticHevcRecordingStep::Capture {
                        event: Box::new(other),
                        connection: None,
                    },
                )))
            }
        }
    }
    fn protocol_step(
        &mut self,
        event: Event,
        transport: Option<Box<TcpRetirement>>,
        now: u64,
    ) -> Result<LiveHevcArchiveStep, LiveHevcArchiveFailure> {
        self.network_ended |= transport.is_some();
        if self.capture.is_none() {
            if matches!(
                control(&event),
                Some(Control::Request(ClientCommand::Setup))
            ) {
                if let Err(reason) = self.initialize_capture() {
                    let recording = self.retire_input(None, Some(Box::new(event)), transport);
                    return Err(self.fatal(reason, recording, None));
                }
            } else {
                if let Some(next) = control(&event) {
                    self.next = Some(next);
                }
                let trigger = AutomaticHevcRecordingStep::Network(LiveHevcStep::Protocol {
                    event,
                    transport,
                });
                if self.network_ended {
                    let retained = self.retire(None, None);
                    return Ok(LiveHevcArchiveStep::Stopped {
                        trigger: Box::new(trigger),
                        retained: Box::new(retained),
                    });
                }
                return Ok(LiveHevcArchiveStep::Recording(Box::new(trigger)));
            }
        }
        match self
            .capture
            .as_mut()
            .ok_or_else(|| safe(LiveHevcArchiveError::Invariant))?
            .offer(event, now)
        {
            Ok(()) => Ok(LiveHevcArchiveStep::Recording(Box::new(
                AutomaticHevcRecordingStep::ProtocolQueued { transport },
            ))),
            Err(refusal) => {
                let recording = self.retire_input(None, Some(refusal.event), transport);
                Err(self.fatal(
                    LiveHevcArchiveError::Capture(refusal.reason),
                    recording,
                    None,
                ))
            }
        }
    }
    fn initialize_capture(&mut self) -> Result<(), LiveHevcArchiveError> {
        let selected = self
            .selected
            .as_ref()
            .ok_or(LiveHevcArchiveError::Invariant)?;
        let media = self
            .connection
            .as_ref()
            .and_then(|c| c.media())
            .ok_or(LiveHevcArchiveError::Selection)?;
        if media.payload_type() != selected.payload_type
            || media.vps().len() != 1
            || media.sps().len() != 1
            || media.pps().len() != 1
        {
            return Err(LiveHevcArchiveError::Selection);
        }
        let configuration = HevcConfiguration::parse(
            &media.vps()[0],
            &media.sps()[0],
            &media.pps()[0],
            selected.configuration_limits,
        )
        .map_err(|_| LiveHevcArchiveError::Selection)?;
        let selected = self
            .selected
            .take()
            .ok_or(LiveHevcArchiveError::Invariant)?;
        let collector = HevcRecordingCollector::new(
            selected.scope,
            self.binding.key(),
            selected.payload_type,
            configuration,
            selected.time_scale,
            selected.limits,
        )
        .map_err(|e| LiveHevcArchiveError::Capture(CaptureError::Collection(e)))?;
        self.capture = Some(HevcRecordingCapture::new(collector));
        Ok(())
    }
    fn network_failure(&mut self, failure: LiveHevcFailure) -> LiveHevcArchiveFailure {
        let reason = LiveHevcArchiveError::Network(failure.reason);
        match failure.retirement {
            Some(connection) => {
                let recording = self.retire_input(Some(*connection), None, None);
                self.fatal(reason, recording, None)
            }
            None => safe(reason),
        }
    }
    fn retire_input(
        &mut self,
        connection: Option<LiveHevcRetirement>,
        event: Option<Box<Event>>,
        transport: Option<Box<TcpRetirement>>,
    ) -> Option<SelectedHevcRecordingRetirement> {
        let owned_connection = self.connection.take().and_then(|mut c| c.cancel());
        let capture = self.capture.take().map(|mut c| c.cancel());
        self.selected = None;
        self.next = None;
        self.network_ended = true;
        let connection = connection.or(owned_connection);
        if connection.is_none() && capture.is_none() && event.is_none() && transport.is_none() {
            return None;
        }
        Some(SelectedHevcRecordingRetirement {
            connection,
            capture,
            unoffered_event: event,
            terminal_transport: transport,
        })
    }
    fn fatal(
        &mut self,
        reason: LiveHevcArchiveError,
        recording: Option<SelectedHevcRecordingRetirement>,
        window: Option<PreparedHevcRecording>,
    ) -> LiveHevcArchiveFailure {
        LiveHevcArchiveFailure {
            reason,
            retirement: Some(Box::new(self.retire(recording, window))),
        }
    }
    fn retire(
        &mut self,
        recording: Option<SelectedHevcRecordingRetirement>,
        window: Option<PreparedHevcRecording>,
    ) -> LiveHevcArchiveRetirement {
        let owned = self.retire_input(None, None, None);
        self.finished = true;
        let archive = self.writer.take().map(|w| w.retire());
        if let Some(archive) = &archive {
            self.last_anchor = archive.journal_anchor;
            self.last_pins = archive.pins.clone();
        }
        LiveHevcArchiveRetirement {
            recording: recording.or(owned),
            archive,
            unoffered_window: window,
        }
    }
}
fn safe(reason: LiveHevcArchiveError) -> LiveHevcArchiveFailure {
    LiveHevcArchiveFailure {
        reason,
        retirement: None,
    }
}
