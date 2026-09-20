#![forbid(unsafe_code)]
//! One live, owner-authorized TCP connection composed with the existing Digest/AVC pump.
//!
//! This owner connects real I/O to protocol negotiation and loss-aware picture assembly.
//! It adds no runtime, retry, DNS lookup, credential store, or guessed media clock. Every
//! received TCP chunk is transferred to the caller, including control/authentication bytes;
//! that transfer is NOT durable source custody. Do not log those bytes.

/// Native connection and loss-aware recording collection under one exclusive owner.
pub mod recording;

use std::fmt;

use fss_packet::avc::AvcReceiveLimits;

use super::authentication::{DigestCredentials, DigestPolicy};
use super::avc_client::AvcClientPoll;
use super::avc_client::authenticated::{
    DigestAvcClient, DigestAvcError, DigestAvcFailure, DigestAvcPoll, DigestAvcRetirement,
};
use super::client::{ClientCommand, ClientConfig, ClientRequest, ClientState};
use super::tcp::{
    RtspTcpLink, TcpAuthority, TcpBinding, TcpError, TcpLimits, TcpOperation,
    TcpReadChunk, TcpReadStep, TcpRetirement, TcpTotals, TcpWriteStep,
};

/// Immutable caller-owned route, protocol selection, resource limits, and lease.
/// None of these fields authenticates a principal or grants network permission.
pub struct LiveAvcConfig {
    /// Exact presentation and control subtree on the bound RTSP authority.
    pub protocol: ClientConfig,
    /// Caller-resolved peer and explicit plaintext approval; never selected by the server.
    pub binding: TcpBinding,
    /// Independent transport byte, call, and allocation ceilings.
    pub transport: TcpLimits,
    /// Existing RTP/reorder/AVC assembly ceilings.
    pub media: AvcReceiveLimits,
    /// Exact realm accepted by the separate Digest owner; not a secret or a wildcard.
    pub realm: String,
    /// Explicit accepted authentication algorithms; no automatic downgrade.
    pub digest_policy: DigestPolicy,
    /// Absolute owner-clock lease covering negotiation, media, and EOF draining.
    pub deadline_ns: u64,
    /// Maximum request/respond/poll admissions, including polls without socket readiness.
    pub max_steps: u64,
}
impl fmt::Debug for LiveAvcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveAvcConfig").field("binding", &self.binding)
            .field("deadline_ns", &self.deadline_ns).field("max_steps", &self.max_steps)
            .finish_non_exhaustive()
    }
}

/// Readiness from the owning reactor or caller. False never attempts that socket operation.
/// Readiness is advisory: WouldBlock still returns a bounded pending result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketReadiness {
    /// Permit at most one nonblocking read when protocol input is drained.
    pub readable: bool,
    /// Permit at most one nonblocking write of the current request suffix.
    pub writable: bool,
}

/// What the caller should wait for. Protocol deadlines must run even on a silent socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveAvcWait {
    /// More input can be admitted; do not read outside this owner.
    pub readable: bool,
    /// An already prepared request has an unsent suffix.
    pub writable: bool,
    /// Earliest protocol/transport wake; Some(now) means bounded local work remains.
    pub wake_at_ns: Option<u64>,
}

/// Local queue receipt. This is neither a socket-send receipt nor a remote acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedAvcRequest {
    /// Existing typed protocol command, not a new effect dialect.
    pub command: ClientCommand,
    /// Exact correlation assigned by the protocol owner.
    pub cseq: u32,
    /// Whole request bytes reserved by the transport before any send.
    pub bytes: usize,
}

/// Refusal categories contain no URI, realm, challenge, credential, or media payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveAvcError {
    /// Invalid limits, or presentation/control authority differs from the exact TCP binding.
    Configuration,
    /// Native transport/authority/lease refused progress.
    Transport(TcpError),
    /// Existing authenticated protocol owner refused progress.
    Protocol(DigestAvcError),
    /// Resolve the current prepared request before preparing another one.
    Backpressure,
    /// Owner-clock regression; state and remaining work budget are unchanged.
    ClockReversed,
    /// The independent connection-wide driver work budget was exhausted.
    WorkBudget,
    /// Connection has already retired; it cannot be reused or reconnected in place.
    Closed,
}
impl fmt::Display for LiveAvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "live RTSP AVC refusal: {self:?}")
    }
}
impl std::error::Error for LiveAvcError {}

/// Construction failure; no RTSP bytes were sent and no credentials were borrowed.
#[derive(Debug)]
pub struct LiveAvcConnectFailure {
    /// Typed configuration, protocol, or native connection refusal.
    pub reason: LiveAvcError,
    /// The peer may have observed a TCP connection, not a successful RTSP session.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveAvcConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for LiveAvcConnectFailure {}

/// Exact terminal ownership. Originals may contain secrets; Debug deliberately omits them.
#[must_use]
pub struct LiveAvcRetirement {
    /// Partial request dispatch, unread TCP bytes, and exact transport accounting.
    pub transport: TcpRetirement,
    /// Existing remote-session uncertainty and all unprocessed protocol/codec state.
    pub protocol: DigestAvcRetirement,
    /// Prepared request rejected before transport queue admission. Never silently resend it.
    pub unqueued_request: Option<ClientRequest>,
}
impl fmt::Debug for LiveAvcRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveAvcRetirement").field("totals", &self.transport.totals)
            .field("request_sent_bytes", &self.transport.request_sent_bytes)
            .field("unqueued_request", &self.unqueued_request.is_some())
            .finish_non_exhaustive()
    }
}

/// Failure from an existing connection. Safe refusals have no retirement; fatal failures
/// transfer all local ownership exactly once. No automatic TEARDOWN or retry is performed.
#[derive(Debug)]
pub struct LiveAvcFailure {
    /// Payload-free reason.
    pub reason: LiveAvcError,
    /// Present only when this call closed both owners.
    pub retirement: Option<Box<LiveAvcRetirement>>,
}
impl fmt::Display for LiveAvcFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for LiveAvcFailure {}

/// One bounded live connection step. Preserve Wire/retirement outputs before polling again.
#[must_use]
pub enum LiveAvcStep {
    /// Exact original TCP bytes accepted by the protocol owner in this call. The caller
    /// now owns their retention/omission decision; this does not certify stored evidence.
    Wire(TcpReadChunk),
    /// One native write attempt. Sent is local socket acceptance, not an RTSP ACK.
    Write(TcpWriteStep),
    /// Unmodified protocol/media event. A terminal event owns its protocol retirement;
    /// the accompanying transport retirement closes the socket and owns its remaining bytes.
    Protocol {
        /// Existing authentication, control, RTP/RTCP, or loss-aware AVC event.
        event: DigestAvcPoll,
        /// Present exactly once when the protocol terminates this connection.
        transport: Option<Box<TcpRetirement>>,
    },
    /// The socket returned EOF. Accepted protocol/media input still requires draining.
    InputEnded,
    /// No immediate semantic output. Honor readiness AND the absolute wake.
    Pending(LiveAvcWait),
    /// Repeated terminal poll; no ownership or remote-completion claim is produced again.
    Ended,
}
impl fmt::Debug for LiveAvcStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(chunk) => f.debug_tuple("Wire").field(chunk).finish(),
            Self::Write(step) => f.debug_tuple("Write").field(step).finish(),
            Self::Protocol { transport, .. } => f.debug_struct("Protocol")
                .field("terminal", &transport.is_some()).finish_non_exhaustive(),
            Self::Pending(wait) => f.debug_tuple("Pending").field(wait).finish(),
            Self::InputEnded => f.write_str("InputEnded"),
            Self::Ended => f.write_str("Ended"),
        }
    }
}

struct ActiveConnection {
    transport: RtspTcpLink,
    protocol: DigestAvcClient,
    eof: bool,
}

/// Exclusive live socket -> Digest/RTSP -> RTP/RTCP -> AVC owner.
///
/// Construct with one exact route and a live TcpAuthority, explicitly prepare commands,
/// and poll using caller readiness/time. A call performs at most one socket operation
/// and one protocol poll; it does not loop until idle, read ahead behind backpressure,
/// guess DTS/capture time, reconnect, or store credentials. Media outputs plug directly
/// into RecordingCapture, whose explicit timing and source-publication duties remain.
#[must_use]
pub struct LiveAvcConnection {
    active: Option<ActiveConnection>,
    deadline_ns: u64,
    last_ns: u64,
    remaining_steps: u64,
}
impl fmt::Debug for LiveAvcConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveAvcConnection").field("state", &self.state())
            .field("remaining_steps", &self.remaining_steps).finish_non_exhaustive()
    }
}
impl LiveAvcConnection {
    /// Validate both owners and their exact authority mapping before the single connect attempt.
    pub fn connect(config: LiveAvcConfig, now: u64, authority: &dyn TcpAuthority)
        -> Result<Self, LiveAvcConnectFailure>
    {
        let refused = |reason| LiveAvcConnectFailure { reason, connection_attempted: false };
        if config.max_steps == 0 || now >= config.deadline_ns {
            return Err(refused(LiveAvcError::Configuration));
        }
        // DigestAvcClient validates the full URI grammar and subtree. This additional check
        // binds its independently validated authority to the exact native network route.
        let presentation = uri_authority(&config.protocol.presentation_uri);
        let control = uri_authority(&config.protocol.control_root_uri);
        if presentation != Some(config.binding.authority()) || control != presentation {
            return Err(refused(LiveAvcError::Configuration));
        }
        let protocol = DigestAvcClient::new(config.protocol, config.binding.key(), config.media,
            &config.realm, config.digest_policy).map_err(|e| refused(LiveAvcError::Protocol(e)))?;
        let transport = RtspTcpLink::connect(config.binding, config.transport, now, config.deadline_ns, authority)
            .map_err(|e| LiveAvcConnectFailure {
                reason: LiveAvcError::Transport(e.reason), connection_attempted: e.connection_attempted,
            })?;
        Ok(Self { active: Some(ActiveConnection { transport, protocol, eof: false }),
            deadline_ns: config.deadline_ns, last_ns: now, remaining_steps: config.max_steps })
    }

    /// Local protocol state. Closed after terminal ownership has been transferred.
    pub fn state(&self) -> ClientState {
        self.active.as_ref().map_or(ClientState::Closed, |a| a.protocol.state())
    }
    /// Remaining bounded driver calls, independent of transport I/O and byte ceilings.
    pub fn remaining_steps(&self) -> u64 { self.remaining_steps }
    /// Live transport observations, or None after retirement (which owns the final totals).
    pub fn totals(&self) -> Option<TcpTotals> { self.active.as_ref().map(|a| a.transport.totals()) }
    /// Earliest hard/useful wake. Pending writes require writability, not an invented busy timer.
    pub fn next_wake_ns(&self) -> Option<u64> {
        let active = self.active.as_ref()?;
        let wake = earlier(Some(self.deadline_ns), active.protocol.next_wake_ns());
        earlier(wake, active.transport.next_deadline_ns())
    }

    /// Prepare and queue one exact command after live authority admission. Credentials are
    /// borrowed only for preparation and never retained. A queue failure retires the prepared
    /// request rather than pretending protocol state can be rolled back safely.
    pub fn request(&mut self, command: ClientCommand, credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16], now: u64, authority: &dyn TcpAuthority)
        -> Result<QueuedAvcRequest, LiveAvcFailure>
    {
        self.admit(now, authority)?;
        if self.active.as_ref().is_some_and(|a| a.transport.has_pending_request()) {
            return Err(safe(LiveAvcError::Backpressure));
        }
        let result = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
            .protocol.request(command, credentials, cnonce, now);
        self.queue_prepared(result, now, authority)
    }

    /// Answer only the protocol owner's held matching Digest challenge. No implicit credential
    /// lookup, cnonce generation, retry deadline extension, or fallback algorithm occurs.
    pub fn respond(&mut self, credentials: &DigestCredentials<'_>, cnonce: [u8; 16],
        now: u64, authority: &dyn TcpAuthority) -> Result<QueuedAvcRequest, LiveAvcFailure>
    {
        self.admit(now, authority)?;
        if self.active.as_ref().is_some_and(|a| a.transport.has_pending_request()) {
            return Err(safe(LiveAvcError::Backpressure));
        }
        let result = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
            .protocol.respond(credentials, cnonce, now);
        self.queue_prepared(result, now, authority)
    }

    /// Drive timers/queued protocol work before attempting at most one ready socket operation.
    /// Exact read bytes are fed at their original admission time within this same call, then
    /// transferred to the caller before any resulting parsed event is returned. Failed ingest
    /// retains the unread original in terminal transport ownership; it is never retried.
    pub fn poll(&mut self, readiness: SocketReadiness, now: u64, authority: &dyn TcpAuthority)
        -> Result<LiveAvcStep, LiveAvcFailure>
    {
        if self.active.is_none() { return Ok(LiveAvcStep::Ended); }
        self.admit(now, authority)?;
        let event = match self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?.protocol.poll(now) {
            Ok(event) => event,
            Err(error) => return Err(self.fail(LiveAvcError::Protocol(error), None, None)),
        };
        // Immediate internal parser work, held challenges, keepalive, RTP queue pressure, and
        // every terminal event must be surfaced rather than treating them as permission to read.
        let idle = matches!(&event, DigestAvcPoll::Client { event, wire_retirement: None }
            if matches!(event.as_ref(), AvcClientPoll::Pending { wake_at_ns }
                if wake_at_ns.is_none_or(|at| at > now)));
        if !idle { return Ok(self.protocol_step(event)); }
        let active = self.active.as_ref().ok_or_else(|| safe(LiveAvcError::Closed))?;
        if active.eof {
            return Ok(LiveAvcStep::Pending(LiveAvcWait { readable: false, writable: false,
                wake_at_ns: earlier(self.next_wake_ns(), Some(now)) }));
        }
        if active.transport.has_pending_request() {
            if !readiness.writable { return Ok(self.pending(false, true)); }
            let step = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
                .transport.write_step(now, authority);
            return match step {
                Ok(TcpWriteStep::Pending) => Ok(self.pending(false, true)),
                Ok(step) => Ok(LiveAvcStep::Write(step)),
                Err(error) => Err(self.fail(LiveAvcError::Transport(error), None, None)),
            };
        }
        if !readiness.readable { return Ok(self.pending(true, false)); }
        let step = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
            .transport.read_step(now, authority);
        match step {
            Ok(TcpReadStep::Pending) => Ok(self.pending(true, false)),
            Ok(TcpReadStep::Eof) => {
                let active = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?;
                active.eof = true;
                active.protocol.finish();
                Ok(LiveAvcStep::InputEnded)
            }
            Ok(TcpReadStep::Buffered) => {
                let active = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?;
                let chunk = active.transport.pending_read().ok_or_else(|| safe(LiveAvcError::Closed))?;
                let result = active.protocol.ingest(chunk.expose(), chunk.admitted_ns());
                if let Err(failure) = result {
                    return Err(self.fail(LiveAvcError::Protocol(failure.reason),
                        failure.retirement.map(|r| *r), None));
                }
                let chunk = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
                    .transport.acknowledge_read().ok_or_else(|| safe(LiveAvcError::Closed))?;
                Ok(LiveAvcStep::Wire(chunk))
            }
            Err(error) => Err(self.fail(LiveAvcError::Transport(error), None, None)),
        }
    }

    /// Release the socket and transfer every retained layer, even after authority revocation.
    /// Repeated cancellation returns None. No network operation or implicit TEARDOWN is issued.
    pub fn cancel(&mut self) -> Option<LiveAvcRetirement> { self.retire(None, None) }

    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveAvcFailure> {
        if self.active.is_none() { return Err(safe(LiveAvcError::Closed)); }
        if now < self.last_ns { return Err(safe(LiveAvcError::ClockReversed)); }
        if self.remaining_steps == 0 { return Err(self.fail(LiveAvcError::WorkBudget, None, None)); }
        self.remaining_steps -= 1;
        self.last_ns = now;
        let active = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?;
        let result = if active.eof {
            // The TCP owner has already closed its socket. EOF is not permission to bypass
            // live revocation, work, or lease checks while draining accepted protocol input.
            if now >= self.deadline_ns { Err(TcpError::Deadline) }
            else { authority.checkpoint(active.transport.binding(), TcpOperation::Poll, now, self.deadline_ns)
                .map_err(TcpError::Denied) }
        } else { active.transport.check(now, authority) };
        result.map_err(|error| self.fail(LiveAvcError::Transport(error), None, None))
    }

    fn queue_prepared(&mut self, result: Result<ClientRequest, DigestAvcFailure>, now: u64,
        authority: &dyn TcpAuthority) -> Result<QueuedAvcRequest, LiveAvcFailure>
    {
        let request = match result {
            Ok(request) => request,
            Err(failure) => return match failure.retirement {
                Some(retirement) => Err(self.fail(LiveAvcError::Protocol(failure.reason), Some(*retirement), None)),
                None => Err(safe(LiveAvcError::Protocol(failure.reason))),
            },
        };
        let receipt = QueuedAvcRequest { command: request.command(), cseq: request.cseq(), bytes: request.bytes().len() };
        let result = self.active.as_mut().ok_or_else(|| safe(LiveAvcError::Closed))?
            .transport.queue_request(request, now, authority);
        match result {
            Ok(()) => Ok(receipt),
            Err(refusal) => Err(self.fail(LiveAvcError::Transport(refusal.reason), None, Some(refusal.request))),
        }
    }

    fn protocol_step(&mut self, event: DigestAvcPoll) -> LiveAvcStep {
        let terminal = match &event {
            DigestAvcPoll::Fault { .. } => true,
            DigestAvcPoll::Client { event, wire_retirement } => wire_retirement.is_some()
                || matches!(event.as_ref(), AvcClientPoll::Ended { .. } | AvcClientPoll::Fault { .. }
                    | AvcClientPoll::Rtp { retirement: Some(_), .. }),
            DigestAvcPoll::AuthenticationRequired { .. } => false,
        };
        let transport = if terminal { self.active.take().map(|a| Box::new(a.transport.retire())) } else { None };
        LiveAvcStep::Protocol { event, transport }
    }
    fn pending(&self, readable: bool, writable: bool) -> LiveAvcStep {
        LiveAvcStep::Pending(LiveAvcWait { readable, writable, wake_at_ns: self.next_wake_ns() })
    }
    fn fail(&mut self, reason: LiveAvcError, protocol: Option<DigestAvcRetirement>,
        request: Option<ClientRequest>) -> LiveAvcFailure
    {
        LiveAvcFailure { reason, retirement: self.retire(protocol, request).map(Box::new) }
    }
    fn retire(&mut self, protocol: Option<DigestAvcRetirement>, request: Option<ClientRequest>)
        -> Option<LiveAvcRetirement>
    {
        let mut active = self.active.take()?;
        Some(LiveAvcRetirement { transport: active.transport.retire(),
            protocol: protocol.unwrap_or_else(|| active.protocol.cancel()), unqueued_request: request })
    }
}

fn safe(reason: LiveAvcError) -> LiveAvcFailure { LiveAvcFailure { reason, retirement: None } }
fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) }
}
fn uri_authority(uri: &str) -> Option<&str> { uri.strip_prefix("rtsp://")?.split('/').next() }

#[cfg(test)]
mod tests;
