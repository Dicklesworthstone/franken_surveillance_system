#![forbid(unsafe_code)]
//! Native owner-authorized TCP -> RTSP/Digest -> RTP/JPEG image reception.
//!
//! Every accepted original TCP chunk transfers before parsed protocol outputs. This
//! is source ownership, not durable custody. The caller supplies live authority,
//! readiness, clocks, credentials and cnonce entropy; no reconnect, DNS lookup,
//! implicit downgrade, cleanup TEARDOWN or source-authentication claim is added.

use std::fmt;

use fss_packet::ReorderLimits;
use fss_packet::jpeg::JpegLimits;

use super::authentication::{DigestCredentials, DigestPolicy};
use super::client::{ClientCommand, ClientConfig, ClientRequest, ClientState};
use super::framed::RtspWireFrame;
use super::jpeg_client::{
    JpegClientError, JpegClientFailure, JpegClientPoll, JpegClientRetirement, RtspJpegClient,
};
/// The same native readiness contract shared by AVC, HEVC and jpeg owners.
pub use super::tcp::SocketReadiness;
use super::tcp::{
    RtspTcpLink, TcpAuthority, TcpBinding, TcpError, TcpLimits, TcpOperation, TcpReadChunk,
    TcpReadStep, TcpRetirement, TcpTotals, TcpWriteStep,
};

/// Exact caller-owned route, RTP/JPEG work ceilings and authentication policy.
/// Construction grants no authority; every operation still probes `TcpAuthority`.
pub struct LiveJpegConfig {
    /// Exact presentation and permitted control subtree; the server cannot redirect them.
    pub protocol: ClientConfig,
    /// Caller-resolved peer, stream epoch, expected SSRC and explicit plaintext approval.
    pub binding: TcpBinding,
    /// Independent socket byte, allocation and call limits.
    pub transport: TcpLimits,
    /// Independent RTP queue and sequence bounds.
    pub reorder: ReorderLimits,
    /// Exact owner-selected JPEG payload type (26 or 96..=127).
    pub payload_type: u8,
    /// Independent jpeg image byte, fragment and residence bounds.
    pub jpeg: JpegLimits,
    /// Exact accepted Digest realm, not a wildcard or a credential.
    pub realm: String,
    /// Explicit algorithm policy; default policy does not downgrade to legacy Digest.
    pub digest_policy: DigestPolicy,
    /// Absolute owner-clock lifetime, including negotiation and EOF draining.
    pub deadline_ns: u64,
    /// Total request/respond/poll admissions, including calls without socket readiness.
    pub max_steps: u64,
}
impl fmt::Debug for LiveJpegConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveJpegConfig")
            .field("binding", &self.binding)
            .field("deadline_ns", &self.deadline_ns)
            .field("max_steps", &self.max_steps)
            .finish_non_exhaustive()
    }
}

/// Payload-free outer refusal. Existing owners retain their typed failure categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveJpegError {
    /// Invalid limits or a protocol authority not identical to the bound native route.
    Configuration,
    /// Native socket, lease or live authority refused progress.
    Transport(TcpError),
    /// Shared RTSP, Digest, packet or image owner refused progress.
    Protocol(JpegClientError),
    /// Resolve the current queued request before preparing another one.
    Backpressure,
    /// Monotonic admission time reversed; no state or budget changed.
    ClockReversed,
    /// Connection-wide work allowance is exhausted, not clean EOF.
    WorkBudget,
    /// Terminal ownership has already transferred.
    Closed,
}
impl fmt::Display for LiveJpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "live RTSP RTP/JPEG refusal: {self:?}")
    }
}
impl std::error::Error for LiveJpegError {}

/// Construction refused before any RTSP request was sent or any secret borrowed.
#[derive(Debug)]
pub struct LiveJpegConnectFailure {
    /// Typed refusal without a URL, credential or media payload.
    pub reason: LiveJpegError,
    /// Whether the peer may have observed a TCP connection attempt.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveJpegConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveJpegConnectFailure {}

/// One locally queued request, not a socket-send or server-acceptance receipt.
#[must_use]
#[derive(Debug)]
pub struct QueuedJpegRequest {
    /// Original protocol command.
    pub command: ClientCommand,
    /// Fresh protocol-owned request correlation.
    pub cseq: u32,
    /// Complete request bytes reserved before any socket write.
    pub bytes: usize,
    /// Exact challenge consumed by `respond`; raw bytes may be sensitive.
    /// This ownership is also preserved if subsequent queue admission fails.
    pub challenge: Option<RtspWireFrame>,
}

/// Every retained layer on fatal failure or explicit cancellation.
#[must_use]
#[derive(Debug)]
pub struct LiveJpegRetirement {
    /// Buffered original TCP bytes, queued request and exact already-sent prefix.
    pub transport: TcpRetirement,
    /// Original challenges, packet/fragment/image work and remote-session uncertainty.
    pub protocol: JpegClientRetirement,
    /// Prepared request rejected before transport queue admission. Never resend implicitly.
    pub unqueued_request: Option<ClientRequest>,
    /// Challenge consumed before a failed queue admission, returned intact instead of lost.
    pub answered_challenge: Option<RtspWireFrame>,
}

/// Safe refusals preserve the live owner; fatal ones transfer every layer exactly once.
#[derive(Debug)]
pub struct LiveJpegFailure {
    /// Payload-free failure category.
    pub reason: LiveJpegError,
    /// Present only when this call closed the connection.
    pub retirement: Option<Box<LiveJpegRetirement>>,
}
impl fmt::Display for LiveJpegFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveJpegFailure {}

/// Readiness and timer work needed by this exclusive owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveJpegWait {
    /// The next progress step may attempt one nonblocking read.
    pub readable: bool,
    /// The prepared request has an unsent suffix requiring writability.
    pub writable: bool,
    /// Earliest owner wake; a due local wake is not permission for read-ahead.
    pub wake_at_ns: Option<u64>,
}

/// One bounded output; process transferred originals before polling again.
#[must_use]
#[derive(Debug)]
pub enum LiveJpegStep {
    /// Exact original TCP bytes accepted at their original admission time.
    /// Transfer does not establish durable custody; Debug omits their contents.
    Wire(TcpReadChunk),
    /// One existing native write result; socket acceptance is not remote execution.
    Write(TcpWriteStep),
    /// Unchanged source-bearing protocol/RTP/JPEG image event.
    Protocol {
        /// Existing typed control, packet, image, failure or EOF result.
        event: Box<JpegClientPoll>,
        /// Transferred once when this event closes the native connection.
        transport: Option<Box<TcpRetirement>>,
    },
    /// Actual socket EOF. Accepted input must still drain under the original lease.
    InputEnded,
    /// No immediate semantic output; honor readiness and the earliest timer.
    Pending(LiveJpegWait),
    /// All terminal ownership has already transferred; no repeated success receipt.
    Ended,
}

struct Active {
    transport: RtspTcpLink,
    protocol: RtspJpegClient,
    eof: bool,
}

/// Exclusive native RTP/JPEG connection. A call polls at most one protocol step and attempts
/// at most one socket operation. Queued source, Digest challenges, image work and RTP
/// backpressure drain before further socket input. No request is retried automatically.
#[must_use]
pub struct LiveJpegConnection {
    active: Option<Active>,
    deadline_ns: u64,
    last_ns: u64,
    remaining_steps: u64,
}
impl fmt::Debug for LiveJpegConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveJpegConnection")
            .field("state", &self.state())
            .field("remaining_steps", &self.remaining_steps)
            .finish_non_exhaustive()
    }
}
impl LiveJpegConnection {
    /// Validate both semantic owners and exact route equality before a single connect.
    pub fn connect(
        config: LiveJpegConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, LiveJpegConnectFailure> {
        Self::connect_mode(config, now, authority, true)
    }
    /// Open an explicitly unauthenticated connection. A challenge is refused by the
    /// plain session; there is no dummy credential, secret read, or automatic upgrade.
    /// The route, native transport, lifetime and image bounds remain identical.
    pub fn connect_unauthenticated(
        config: LiveJpegConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, LiveJpegConnectFailure> {
        Self::connect_mode(config, now, authority, false)
    }
    fn connect_mode(
        config: LiveJpegConfig,
        now: u64,
        authority: &dyn TcpAuthority,
        digest: bool,
    ) -> Result<Self, LiveJpegConnectFailure> {
        let refused = |reason| LiveJpegConnectFailure {
            reason,
            connection_attempted: false,
        };
        if config.max_steps == 0 || now >= config.deadline_ns {
            return Err(refused(LiveJpegError::Configuration));
        }
        let presentation = uri_authority(&config.protocol.presentation_uri);
        if presentation != Some(config.binding.authority())
            || uri_authority(&config.protocol.control_root_uri) != presentation
        {
            return Err(refused(LiveJpegError::Configuration));
        }
        let protocol = if digest {
            RtspJpegClient::with_digest(
                config.protocol,
                config.binding.key(),
                config.payload_type,
                config.reorder,
                config.jpeg,
                &config.realm,
                config.digest_policy,
            )
        } else {
            RtspJpegClient::new(
                config.protocol,
                config.binding.key(),
                config.payload_type,
                config.reorder,
                config.jpeg,
            )
        }
        .map_err(|e| refused(LiveJpegError::Protocol(e)))?;
        let transport = RtspTcpLink::connect(
            config.binding,
            config.transport,
            now,
            config.deadline_ns,
            authority,
        )
        .map_err(|e| LiveJpegConnectFailure {
            reason: LiveJpegError::Transport(e.reason),
            connection_attempted: e.connection_attempted,
        })?;
        Ok(Self {
            active: Some(Active {
                transport,
                protocol,
                eof: false,
            }),
            deadline_ns: config.deadline_ns,
            last_ns: now,
            remaining_steps: config.max_steps,
        })
    }
    /// Local protocol state only. Playing is not proof of a complete or retained image.
    pub fn state(&self) -> ClientState {
        self.active
            .as_ref()
            .map_or(ClientState::Closed, |a| a.protocol.state())
    }
    /// Immutable parameters from the accepted, selected RTP/JPEG description. This is not
    /// permission to borrow configuration from another media offer or stream generation.
    pub fn media(&self) -> Option<&super::client::jpeg::JpegClientMedia> {
        self.active.as_ref().and_then(|a| a.protocol.media())
    }
    /// Remaining connection-wide work, independent of socket-call and byte ceilings.
    pub fn remaining_steps(&self) -> u64 {
        self.remaining_steps
    }
    /// Actual native transport observations, absent after retirement.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.active.as_ref().map(|a| a.transport.totals())
    }
    /// Earliest hard or useful wake, including while the socket is silent.
    pub fn next_wake_ns(&self) -> Option<u64> {
        let active = self.active.as_ref()?;
        earlier(
            earlier(Some(self.deadline_ns), active.protocol.next_wake_ns()),
            active.transport.next_deadline_ns(),
        )
    }
    /// Prepare one command under live authority. Credentials are borrowed, not retained.
    /// Supply fresh owner-generated cnonce entropy for every admitted preparation.
    pub fn request(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedJpegRequest, LiveJpegFailure> {
        self.admit(now, authority)?;
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.transport.has_pending_request())
        {
            return Err(safe(LiveJpegError::Backpressure));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .protocol
            .request_digest(command, credentials, cnonce, now);
        let request = result.map_err(|e| self.protocol_failure(e))?;
        self.queue(request, None, now, authority)
    }
    /// Prepare one plain command. Digest-enabled sessions reject this method;
    /// callers must choose unauthenticated mode before opening the connection.
    pub fn request_unauthenticated(
        &mut self,
        command: ClientCommand,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedJpegRequest, LiveJpegFailure> {
        self.admit(now, authority)?;
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.transport.has_pending_request())
        {
            return Err(safe(LiveJpegError::Backpressure));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .protocol
            .request(command, now);
        let request = result.map_err(|e| self.protocol_failure(e))?;
        self.queue(request, None, now, authority)
    }
    /// Answer only the internally held matching challenge. Return its exact original wire
    /// even if transport queue admission fails after the protocol has prepared the answer.
    pub fn respond(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedJpegRequest, LiveJpegFailure> {
        self.admit(now, authority)?;
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.transport.has_pending_request())
        {
            return Err(safe(LiveJpegError::Backpressure));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .protocol
            .respond_digest(credentials, cnonce, now);
        let response = result.map_err(|e| self.protocol_failure(e))?;
        self.queue(response.request, Some(response.source), now, authority)
    }
    /// Run timers and queued semantic work before attempting one ready socket operation.
    /// A refused read remains intact in transport retirement; it is never fed a second time.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<LiveJpegStep, LiveJpegFailure> {
        if self.active.is_none() {
            return Ok(LiveJpegStep::Ended);
        }
        self.admit(now, authority)?;
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .protocol
            .poll(now);
        let event = match result {
            Ok(event) => event,
            Err(error) => {
                return Err(self.fail(LiveJpegError::Protocol(error), None, None, None));
            }
        };
        if !matches!(&event, JpegClientPoll::Pending { wake_at_ns }
            if wake_at_ns.is_none_or(|at| at > now))
        {
            let transport = if terminal(&event) {
                self.active.take().map(|a| Box::new(a.transport.retire()))
            } else {
                None
            };
            return Ok(LiveJpegStep::Protocol {
                event: Box::new(event),
                transport,
            });
        }
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| safe(LiveJpegError::Closed))?;
        if active.eof {
            return Ok(LiveJpegStep::Pending(LiveJpegWait {
                readable: false,
                writable: false,
                wake_at_ns: earlier(self.next_wake_ns(), Some(now)),
            }));
        }
        if active.transport.has_pending_request() {
            if !readiness.writable {
                return Ok(self.pending(false, true));
            }
            let result = self
                .active
                .as_mut()
                .ok_or_else(|| safe(LiveJpegError::Closed))?
                .transport
                .write_step(now, authority);
            return match result {
                Ok(TcpWriteStep::Pending) => Ok(self.pending(false, true)),
                Ok(step) => Ok(LiveJpegStep::Write(step)),
                Err(error) => Err(self.fail(LiveJpegError::Transport(error), None, None, None)),
            };
        }
        if !readiness.readable {
            return Ok(self.pending(true, false));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .transport
            .read_step(now, authority);
        match result {
            Ok(TcpReadStep::Pending) => Ok(self.pending(true, false)),
            Ok(TcpReadStep::Eof) => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveJpegError::Closed))?;
                active.eof = true;
                active.protocol.finish();
                Ok(LiveJpegStep::InputEnded)
            }
            Ok(TcpReadStep::Buffered) => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveJpegError::Closed))?;
                let chunk = active
                    .transport
                    .pending_read()
                    .ok_or_else(|| safe(LiveJpegError::Closed))?;
                let result = active.protocol.ingest(chunk.expose(), chunk.admitted_ns());
                if let Err(failure) = result {
                    return Err(self.fail(
                        LiveJpegError::Protocol(failure.reason),
                        failure.retirement.map(|r| *r),
                        None,
                        None,
                    ));
                }
                let chunk = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveJpegError::Closed))?
                    .transport
                    .acknowledge_read()
                    .ok_or_else(|| safe(LiveJpegError::Closed))?;
                Ok(LiveJpegStep::Wire(chunk))
            }
            Err(error) => Err(self.fail(LiveJpegError::Transport(error), None, None, None)),
        }
    }
    /// Close without I/O, even after revocation. No automatic TEARDOWN or remote proof.
    pub fn cancel(&mut self) -> Option<LiveJpegRetirement> {
        self.retire(None, None, None)
    }
    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveJpegFailure> {
        if self.active.is_none() {
            return Err(safe(LiveJpegError::Closed));
        }
        if now < self.last_ns {
            return Err(safe(LiveJpegError::ClockReversed));
        }
        if self.remaining_steps == 0 {
            return Err(self.fail(LiveJpegError::WorkBudget, None, None, None));
        }
        self.remaining_steps -= 1;
        self.last_ns = now;
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?;
        let allowed = if active.eof {
            if now >= self.deadline_ns {
                Err(TcpError::Deadline)
            } else {
                authority
                    .checkpoint(
                        active.transport.binding(),
                        TcpOperation::Poll,
                        now,
                        self.deadline_ns,
                    )
                    .map_err(TcpError::Denied)
            }
        } else {
            active.transport.check(now, authority)
        };
        allowed.map_err(|e| self.fail(LiveJpegError::Transport(e), None, None, None))
    }
    fn queue(
        &mut self,
        request: ClientRequest,
        challenge: Option<RtspWireFrame>,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedJpegRequest, LiveJpegFailure> {
        let command = request.command();
        let cseq = request.cseq();
        let bytes = request.bytes().len();
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveJpegError::Closed))?
            .transport
            .queue_request(request, now, authority);
        match result {
            Ok(()) => Ok(QueuedJpegRequest {
                command,
                cseq,
                bytes,
                challenge,
            }),
            Err(refusal) => Err(self.fail(
                LiveJpegError::Transport(refusal.reason),
                None,
                Some(refusal.request),
                challenge,
            )),
        }
    }
    fn protocol_failure(&mut self, failure: JpegClientFailure) -> LiveJpegFailure {
        match failure.retirement {
            Some(retired) => self.fail(
                LiveJpegError::Protocol(failure.reason),
                Some(*retired),
                None,
                None,
            ),
            None => safe(LiveJpegError::Protocol(failure.reason)),
        }
    }
    fn pending(&self, readable: bool, writable: bool) -> LiveJpegStep {
        LiveJpegStep::Pending(LiveJpegWait {
            readable,
            writable,
            wake_at_ns: self.next_wake_ns(),
        })
    }
    fn fail(
        &mut self,
        reason: LiveJpegError,
        protocol: Option<JpegClientRetirement>,
        request: Option<ClientRequest>,
        challenge: Option<RtspWireFrame>,
    ) -> LiveJpegFailure {
        LiveJpegFailure {
            reason,
            retirement: self.retire(protocol, request, challenge).map(Box::new),
        }
    }
    fn retire(
        &mut self,
        protocol: Option<JpegClientRetirement>,
        request: Option<ClientRequest>,
        challenge: Option<RtspWireFrame>,
    ) -> Option<LiveJpegRetirement> {
        let mut active = self.active.take()?;
        Some(LiveJpegRetirement {
            transport: active.transport.retire(),
            protocol: protocol.unwrap_or_else(|| active.protocol.cancel()),
            unqueued_request: request,
            answered_challenge: challenge,
        })
    }
}
fn terminal(event: &JpegClientPoll) -> bool {
    matches!(
        event,
        JpegClientPoll::Fault { .. }
            | JpegClientPoll::Ended { .. }
            | JpegClientPoll::Rtp {
                retirement: Some(_),
                ..
            }
    )
}
fn safe(reason: LiveJpegError) -> LiveJpegFailure {
    LiveJpegFailure {
        reason,
        retirement: None,
    }
}
fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn uri_authority(uri: &str) -> Option<&str> {
    uri.strip_prefix("rtsp://")?.split('/').next()
}
