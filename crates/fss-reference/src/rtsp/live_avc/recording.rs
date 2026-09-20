#![forbid(unsafe_code)]
//! Exclusive live camera -> loss-aware recording collection, without guessed media timing.
//!
//! Preparation is not publication. Wire chunks, unselected originals, prepared windows and
//! retirements transfer to the caller, which must retain or explicitly account for each before
//! polling again. The existing root-last recording publisher consumes prepared windows unchanged.

use fss_packet::avc::AvcReceivePoll;

use super::*;
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording_capture::{
    CaptureError, CapturePoll, CaptureRetirement, RecordingCapture, TimedCapture,
};
use crate::rtsp::recording_collector::{CollectorError, CollectorLimits, RecordingCollector, RecordingTiming};

/// Independent recording scope/ceilings. A source packet must match the declared payload type;
/// time scale and per-picture timing are explicit owner choices, never inferred from arrival.
#[derive(Clone, Debug)]
pub struct LiveRecordingConfig {
    /// Canonical sensor/stream/generation and clock provenance, not an authority grant.
    pub scope: RecordingScope,
    /// Exact RTP payload mapping expected by the recording owner.
    pub payload_type: u8,
    /// Explicit media tick rate used by the recording muxer.
    pub time_scale: u32,
    /// Independent source, picture, span, and residence ceilings.
    pub limits: CollectorLimits,
}

/// Payload-free live recording failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveRecordingError {
    /// Network, authentication, lease, or bounded live driver failed.
    Network(LiveAvcError),
    /// Recording admission/timing/sealing refused; input ownership is preserved.
    Capture(CaptureError),
}
impl fmt::Display for LiveRecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "live recording refusal: {self:?}") }
}
impl std::error::Error for LiveRecordingError {}

/// Before any RTSP request. Invalid recording configuration never opens a socket.
#[derive(Debug)]
pub struct LiveRecordingConnectFailure {
    /// Typed refusal, never a private source path or address.
    pub reason: LiveRecordingError,
    /// Whether a TCP attempt was made, not whether a camera session exists.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveRecordingConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for LiveRecordingConnectFailure {}

/// Every retained layer at cancellation or a fatal call failure. A prior terminal network event
/// can already have transferred connection ownership; that is why connection is optional.
#[must_use]
pub struct LiveRecordingRetirement {
    /// Exact network/protocol retirement, absent only after a terminal network event transferred it.
    pub connection: Option<LiveAvcRetirement>,
    /// Prepared output, unsealed originals, untimed picture and unconsumed capture event.
    pub capture: CaptureRetirement,
    /// An event rejected before capture admission, never silently discarded on a failed offer.
    pub unoffered_media: Option<Box<AvcReceivePoll>>,
}
impl fmt::Debug for LiveRecordingRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveRecordingRetirement").field("connection", &self.connection.is_some())
            .field("unoffered_media", &self.unoffered_media.is_some()).finish_non_exhaustive()
    }
}

/// Safe correction (for example invalid timing) leaves retirement absent. Fatal network/driver
/// or capture-poll failures stop the socket and transfer all remaining source and derivative work.
#[derive(Debug)]
pub struct LiveRecordingFailure {
    /// Payload-free classification.
    pub reason: LiveRecordingError,
    /// Present when this call ended the recording owner.
    pub retirement: Option<Box<LiveRecordingRetirement>>,
}
impl fmt::Display for LiveRecordingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for LiveRecordingFailure {}

/// One bounded output. Process transferred originals/windows before polling again.
#[must_use]
pub enum LiveRecordingStep {
    /// Original TCP/control/RTP/RTCP output. Final EOF media, when present, has been moved into
    /// capture before returning its separate protocol/transport retirement in this event.
    Network(LiveAvcStep),
    /// An ordered receiver event moved into capture; no further socket read happened.
    MediaQueued,
    /// Existing collection output: explicit timing request, prepared window, original receiver
    /// event, tail, backpressure, or end. On capture stop the socket is closed in the same call.
    Capture {
        /// Existing typed capture result, never a new recording or boundary dialect.
        event: CapturePoll,
        /// Transferred only when collection stopped before the network retired independently.
        connection: Option<Box<LiveAvcRetirement>>,
    },
    /// Network fault/restart stopped collection. The trigger owns its network retirement;
    /// retained owns all unsealed capture state. No EOF boundary is invented from this fault.
    Stopped {
        /// Exact original fatal network/protocol event.
        trigger: Box<LiveAvcStep>,
        /// Prepared/unsealed recording work, without retroactive cancellation of published output.
        retained: Box<CaptureRetirement>,
    },
    /// All terminal ownership already transferred.
    Ended,
}
impl fmt::Debug for LiveRecordingStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Network(_) => "LiveRecordingStep::Network", Self::MediaQueued => "LiveRecordingStep::MediaQueued",
            Self::Capture { .. } => "LiveRecordingStep::Capture", Self::Stopped { .. } => "LiveRecordingStep::Stopped",
            Self::Ended => "LiveRecordingStep::Ended",
        })
    }
}

/// One bounded owner for native network, authentication, media reconstruction and recording.
///
/// Capture always drains before more network input is polled. Missing timing, publication work,
/// and collector pressure never trigger a read-ahead queue. While waiting, every call still checks
/// the exact live authority and original lease. Explicit loss/restart/fault stops the connection;
/// only actual receiver EOF may finish a recording. No source bytes, timestamps or success
/// receipts are fabricated to turn a failed camera into an apparently complete recording.
#[must_use]
pub struct LiveAvcRecording {
    connection: LiveAvcConnection,
    capture: RecordingCapture,
    binding: TcpBinding,
    deadline_ns: u64,
    last_ns: u64,
    remaining_steps: u64,
    network_ended: bool,
    closed: bool,
}
impl fmt::Debug for LiveAvcRecording {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveAvcRecording").field("state", &self.connection.state())
            .field("closed", &self.closed).field("remaining_steps", &self.remaining_steps).finish_non_exhaustive()
    }
}
impl LiveAvcRecording {
    /// Validate recording binding before any connect attempt. Network/authentication still use
    /// the exact existing live connection and caller-owned TcpAuthority; no alternate peer or codec.
    pub fn connect(config: LiveAvcConfig, recording: LiveRecordingConfig, now: u64, authority: &dyn TcpAuthority)
        -> Result<Self, LiveRecordingConnectFailure>
    {
        let collector = RecordingCollector::new(recording.scope, config.binding.key(), recording.payload_type,
            recording.time_scale, recording.limits).map_err(|e: CollectorError| LiveRecordingConnectFailure {
                reason: LiveRecordingError::Capture(CaptureError::Collection(e)), connection_attempted: false,
            })?;
        let binding = config.binding.clone();
        let deadline_ns = config.deadline_ns;
        let remaining_steps = config.max_steps;
        let connection = LiveAvcConnection::connect(config, now, authority).map_err(|e| LiveRecordingConnectFailure {
            reason: LiveRecordingError::Network(e.reason), connection_attempted: e.connection_attempted,
        })?;
        Ok(Self { connection, capture: RecordingCapture::new(collector), binding, deadline_ns,
            remaining_steps, last_ns: now, network_ended: false, closed: false })
    }
    /// Negotiation state only. Playing is not a frame, custody, or continuity certificate.
    pub fn state(&self) -> ClientState { self.connection.state() }
    /// Immutable collection accounting, without an injection or mutable bypass of event order.
    pub fn collector(&self) -> &RecordingCollector { self.capture.collector() }
    /// Live transport observations; final values transfer with terminal network ownership.
    pub fn totals(&self) -> Option<TcpTotals> { self.connection.totals() }
    /// Arrange timers even while the socket is silent or explicit picture timing is outstanding.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        earlier(Some(self.deadline_ns), earlier(self.capture.next_wake_ns(), self.connection.next_wake_ns()))
    }
    /// Explicit protocol command. No autonomous capture-start, keepalive, or teardown effects.
    pub fn request(&mut self, command: ClientCommand, credentials: &DigestCredentials<'_>, cnonce: [u8; 16],
        now: u64, authority: &dyn TcpAuthority) -> Result<QueuedAvcRequest, LiveRecordingFailure>
    {
        self.admit(now, authority)?;
        let result = self.connection.request(command, credentials, cnonce, now, authority);
        result.map_err(|e| self.network_failure(e))
    }
    /// Answer the internally retained exact challenge using a borrowed credential owner.
    pub fn respond(&mut self, credentials: &DigestCredentials<'_>, cnonce: [u8; 16], now: u64,
        authority: &dyn TcpAuthority) -> Result<QueuedAvcRequest, LiveRecordingFailure>
    {
        self.admit(now, authority)?;
        let result = self.connection.respond(credentials, cnonce, now, authority);
        result.map_err(|e| self.network_failure(e))
    }
    /// Supply independent media timing. Rejected timing keeps the same picture available for
    /// correction; any unselected startup picture/source returned on success remains caller-owned.
    pub fn supply_timing(&mut self, timing: RecordingTiming, now: u64, authority: &dyn TcpAuthority)
        -> Result<TimedCapture, LiveRecordingFailure>
    {
        self.admit(now, authority)?;
        self.capture.supply_timing(timing, now).map_err(|e| LiveRecordingFailure {
            reason: LiveRecordingError::Capture(e), retirement: None,
        })
    }
    /// Seal a completed prefix to relieve collection pressure. Poll to transfer the prepared
    /// window and publish/reconcile it through the existing recording owner before continuing.
    pub fn seal(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<bool, LiveRecordingFailure> {
        self.admit(now, authority)?;
        self.capture.seal(now).map_err(|e| LiveRecordingFailure { reason: LiveRecordingError::Capture(e), retirement: None })
    }
    /// One capture step and, only when capture is drained, at most one live network step.
    pub fn poll(&mut self, readiness: SocketReadiness, now: u64, authority: &dyn TcpAuthority)
        -> Result<LiveRecordingStep, LiveRecordingFailure>
    {
        if self.closed { return Ok(LiveRecordingStep::Ended); }
        self.admit(now, authority)?;
        match self.capture.poll(now) {
            Ok(CapturePoll::Pending { .. }) => {},
            Ok(event) => {
                let terminal = matches!(&event, CapturePoll::Stopped { .. } | CapturePoll::Ended { .. });
                let connection = if terminal { self.closed = true; self.connection.cancel().map(Box::new) } else { None };
                return Ok(LiveRecordingStep::Capture { event, connection });
            }
            Err(error) => return Err(self.fatal(LiveRecordingError::Capture(error), None, None)),
        }
        if self.network_ended {
            // EOF was offered exactly once. Pending after that is an invariant failure, not
            // permission to declare the remaining recording work drained or poll a dead socket.
            return Err(self.fatal(LiveRecordingError::Capture(CaptureError::Closed), None, None));
        }
        let step = match self.connection.poll(readiness, now, authority) {
            Ok(step) => step,
            Err(error) => return Err(self.network_failure(error)),
        };
        match step {
            LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, wire_retirement }, transport } => {
                match *event {
                    AvcClientPoll::Media(media) if transport.is_none() && wire_retirement.is_none() => {
                        self.offer(media, now)?;
                        Ok(LiveRecordingStep::MediaQueued)
                    }
                    AvcClientPoll::Ended { media: Some(media), retirement }
                        if matches!(&media, AvcReceivePoll::Ended { .. }) => {
                        // Receiver EOF is real, not synthesized from an I/O or protocol error.
                        // Offer only after capture reached Pending; a refused offer preserves all
                        // network retirement in the trigger rather than losing it through `?`.
                        match self.capture.offer(media, now) {
                            Ok(()) => {
                                self.network_ended = true;
                                Ok(LiveRecordingStep::Network(LiveAvcStep::Protocol {
                                    event: DigestAvcPoll::Client { event: Box::new(AvcClientPoll::Ended {
                                        media: None, retirement }), wire_retirement }, transport,
                                }))
                            }
                            Err(refusal) => Ok(self.stop_event(LiveAvcStep::Protocol {
                                event: DigestAvcPoll::Client { event: Box::new(AvcClientPoll::Ended {
                                    media: Some(*refusal.event), retirement }), wire_retirement }, transport,
                            })),
                        }
                    }
                    event => {
                        let terminal = transport.is_some() || wire_retirement.is_some();
                        let step = LiveAvcStep::Protocol { event: DigestAvcPoll::Client {
                            event: Box::new(event), wire_retirement }, transport };
                        if terminal { Ok(self.stop_event(step)) } else { Ok(LiveRecordingStep::Network(step)) }
                    }
                }
            }
            step @ LiveAvcStep::Protocol { event: DigestAvcPoll::Fault { .. }, .. } => Ok(self.stop_event(step)),
            LiveAvcStep::Pending(mut wait) => {
                wait.wake_at_ns = earlier(wait.wake_at_ns, self.capture.next_wake_ns());
                Ok(LiveRecordingStep::Network(LiveAvcStep::Pending(wait)))
            }
            LiveAvcStep::Ended => Ok(self.stop_event(LiveAvcStep::Ended)),
            step => Ok(LiveRecordingStep::Network(step)),
        }
    }
    /// Stop all local owners without I/O. Sealed windows and unsealed/untimed input transfer
    /// separately. This never asserts remote teardown, source deletion, or publication success.
    pub fn cancel(&mut self) -> Option<LiveRecordingRetirement> {
        if self.closed { return None; }
        Some(self.retire(None, None))
    }
    fn offer(&mut self, media: AvcReceivePoll, now: u64) -> Result<(), LiveRecordingFailure> {
        self.capture.offer(media, now).map_err(|e| self.fatal(LiveRecordingError::Capture(e.reason), None, Some(e.event)))
    }
    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveRecordingFailure> {
        let safe = |e| LiveRecordingFailure { reason: LiveRecordingError::Network(e), retirement: None };
        if self.closed { return Err(safe(LiveAvcError::Closed)); }
        if now < self.last_ns { return Err(safe(LiveAvcError::ClockReversed)); }
        if self.remaining_steps == 0 { return Err(self.fatal(LiveRecordingError::Network(LiveAvcError::WorkBudget), None, None)); }
        self.remaining_steps -= 1; self.last_ns = now;
        let result = if now >= self.deadline_ns { Err(TcpError::Deadline) }
            else { authority.checkpoint(&self.binding, TcpOperation::Poll, now, self.deadline_ns).map_err(TcpError::Denied) };
        result.map_err(|e| self.fatal(LiveRecordingError::Network(LiveAvcError::Transport(e)), None, None))
    }
    fn network_failure(&mut self, error: LiveAvcFailure) -> LiveRecordingFailure {
        let reason = LiveRecordingError::Network(error.reason);
        match error.retirement {
            Some(retirement) => self.fatal(reason, Some(*retirement), None),
            None => LiveRecordingFailure { reason, retirement: None },
        }
    }
    fn stop_event(&mut self, trigger: LiveAvcStep) -> LiveRecordingStep {
        // Terminal LiveAvcStep already took the network retirement. No second close receipt.
        self.closed = true;
        LiveRecordingStep::Stopped { trigger: Box::new(trigger), retained: Box::new(self.capture.cancel()) }
    }
    fn fatal(&mut self, reason: LiveRecordingError, connection: Option<LiveAvcRetirement>,
        media: Option<Box<AvcReceivePoll>>) -> LiveRecordingFailure
    {
        LiveRecordingFailure { reason, retirement: Some(Box::new(self.retire(connection, media))) }
    }
    fn retire(&mut self, connection: Option<LiveAvcRetirement>, media: Option<Box<AvcReceivePoll>>)
        -> LiveRecordingRetirement
    {
        self.closed = true;
        LiveRecordingRetirement { connection: connection.or_else(|| self.connection.cancel()),
            capture: self.capture.cancel(), unoffered_media: media }
    }
}

#[cfg(test)]
mod tests;
