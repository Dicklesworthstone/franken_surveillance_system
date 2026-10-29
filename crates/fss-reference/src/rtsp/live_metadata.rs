#![forbid(unsafe_code)]
//! Native owner-authorized TCP -> RTSP/Digest -> ONVIF metadata document reception.
//!
//! Every accepted original TCP chunk transfers before parsed protocol outputs. This
//! is source ownership, not durable custody. The caller supplies live authority,
//! readiness, clocks, credentials and cnonce entropy; no reconnect, DNS lookup,
//! implicit downgrade, cleanup TEARDOWN or source-authentication claim is added.

use std::fmt;

use fss_packet::{OnvifMetadataLimits, ReorderLimits};

use super::authentication::{DigestCredentials, DigestPolicy};
use super::client::{ClientCommand, ClientConfig, ClientRequest, ClientState};
use super::framed::RtspWireFrame;
use super::metadata_client::{
    MetadataClientError, MetadataClientFailure, MetadataClientPoll, MetadataClientRetirement,
    RtspMetadataClient,
};
/// The same native readiness contract shared by AVC, HEVC and metadata owners.
pub use super::tcp::SocketReadiness;
use super::tcp::{
    RtspTcpLink, TcpAuthority, TcpBinding, TcpError, TcpLimits, TcpOperation, TcpReadChunk,
    TcpReadStep, TcpRetirement, TcpTotals, TcpWriteStep,
};

/// Exact caller-owned route, ONVIF metadata work ceilings and authentication policy.
/// Construction grants no authority; every operation still probes `TcpAuthority`.
pub struct LiveMetadataConfig {
    /// Exact presentation and permitted control subtree; the server cannot redirect them.
    pub protocol: ClientConfig,
    /// Caller-resolved peer, stream epoch, expected SSRC and explicit plaintext approval.
    pub binding: TcpBinding,
    /// Independent socket byte, allocation and call limits.
    pub transport: TcpLimits,
    /// Independent RTP queue and sequence bounds.
    pub reorder: ReorderLimits,
    /// Exact owner-selected dynamic payload type (96..=127).
    pub payload_type: u8,
    /// Independent metadata document byte, fragment and residence bounds.
    pub metadata: OnvifMetadataLimits,
    /// Exact accepted Digest realm, not a wildcard or a credential.
    pub realm: String,
    /// Explicit algorithm policy; default policy does not downgrade to legacy Digest.
    pub digest_policy: DigestPolicy,
    /// Absolute owner-clock lifetime, including negotiation and EOF draining.
    pub deadline_ns: u64,
    /// Total request/respond/poll admissions, including calls without socket readiness.
    pub max_steps: u64,
}
impl fmt::Debug for LiveMetadataConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveMetadataConfig")
            .field("binding", &self.binding)
            .field("deadline_ns", &self.deadline_ns)
            .field("max_steps", &self.max_steps)
            .finish_non_exhaustive()
    }
}

/// Payload-free outer refusal. Existing owners retain their typed failure categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveMetadataError {
    /// Invalid limits or a protocol authority not identical to the bound native route.
    Configuration,
    /// Native socket, lease or live authority refused progress.
    Transport(TcpError),
    /// Shared RTSP, Digest, packet or document owner refused progress.
    Protocol(MetadataClientError),
    /// Resolve the current queued request before preparing another one.
    Backpressure,
    /// Monotonic admission time reversed; no state or budget changed.
    ClockReversed,
    /// Connection-wide work allowance is exhausted, not clean EOF.
    WorkBudget,
    /// Terminal ownership has already transferred.
    Closed,
}
impl fmt::Display for LiveMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "live RTSP ONVIF metadata refusal: {self:?}")
    }
}
impl std::error::Error for LiveMetadataError {}

/// Construction refused before any RTSP request was sent or any secret borrowed.
#[derive(Debug)]
pub struct LiveMetadataConnectFailure {
    /// Typed refusal without a URL, credential or media payload.
    pub reason: LiveMetadataError,
    /// Whether the peer may have observed a TCP connection attempt.
    pub connection_attempted: bool,
}
impl fmt::Display for LiveMetadataConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveMetadataConnectFailure {}

/// One locally queued request, not a socket-send or server-acceptance receipt.
#[must_use]
#[derive(Debug)]
pub struct QueuedMetadataRequest {
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
pub struct LiveMetadataRetirement {
    /// Buffered original TCP bytes, queued request and exact already-sent prefix.
    pub transport: TcpRetirement,
    /// Original challenges, packet/fragment/document work and remote-session uncertainty.
    pub protocol: MetadataClientRetirement,
    /// Prepared request rejected before transport queue admission. Never resend implicitly.
    pub unqueued_request: Option<ClientRequest>,
    /// Challenge consumed before a failed queue admission, returned intact instead of lost.
    pub answered_challenge: Option<RtspWireFrame>,
}

/// Safe refusals preserve the live owner; fatal ones transfer every layer exactly once.
#[derive(Debug)]
pub struct LiveMetadataFailure {
    /// Payload-free failure category.
    pub reason: LiveMetadataError,
    /// Present only when this call closed the connection.
    pub retirement: Option<Box<LiveMetadataRetirement>>,
}
impl fmt::Display for LiveMetadataFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for LiveMetadataFailure {}

/// Readiness and timer work needed by this exclusive owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveMetadataWait {
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
pub enum LiveMetadataStep {
    /// Exact original TCP bytes accepted at their original admission time.
    /// Transfer does not establish durable custody; Debug omits their contents.
    Wire(TcpReadChunk),
    /// One existing native write result; socket acceptance is not remote execution.
    Write(TcpWriteStep),
    /// Unchanged source-bearing protocol/ONVIF metadata document event.
    Protocol {
        /// Existing typed control, packet, document, failure or EOF result.
        event: MetadataClientPoll,
        /// Transferred once when this event closes the native connection.
        transport: Option<Box<TcpRetirement>>,
    },
    /// Actual socket EOF. Accepted input must still drain under the original lease.
    InputEnded,
    /// No immediate semantic output; honor readiness and the earliest timer.
    Pending(LiveMetadataWait),
    /// All terminal ownership has already transferred; no repeated success receipt.
    Ended,
}

struct Active {
    transport: RtspTcpLink,
    protocol: RtspMetadataClient,
    eof: bool,
}

/// Exclusive native ONVIF metadata connection. A call polls at most one protocol step and attempts
/// at most one socket operation. Queued source, Digest challenges, document work and RTP
/// backpressure drain before further socket input. No request is retried automatically.
#[must_use]
pub struct LiveMetadataConnection {
    active: Option<Active>,
    deadline_ns: u64,
    last_ns: u64,
    remaining_steps: u64,
}
impl fmt::Debug for LiveMetadataConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveMetadataConnection")
            .field("state", &self.state())
            .field("remaining_steps", &self.remaining_steps)
            .finish_non_exhaustive()
    }
}
impl LiveMetadataConnection {
    /// Validate both semantic owners and exact route equality before a single connect.
    pub fn connect(
        config: LiveMetadataConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, LiveMetadataConnectFailure> {
        let refused = |reason| LiveMetadataConnectFailure {
            reason,
            connection_attempted: false,
        };
        if config.max_steps == 0 || now >= config.deadline_ns {
            return Err(refused(LiveMetadataError::Configuration));
        }
        let presentation = uri_authority(&config.protocol.presentation_uri);
        if presentation != Some(config.binding.authority())
            || uri_authority(&config.protocol.control_root_uri) != presentation
        {
            return Err(refused(LiveMetadataError::Configuration));
        }
        let protocol = RtspMetadataClient::with_digest(
            config.protocol,
            config.binding.key(),
            config.payload_type,
            config.reorder,
            config.metadata,
            &config.realm,
            config.digest_policy,
        )
        .map_err(|e| refused(LiveMetadataError::Protocol(e)))?;
        let transport = RtspTcpLink::connect(
            config.binding,
            config.transport,
            now,
            config.deadline_ns,
            authority,
        )
        .map_err(|e| LiveMetadataConnectFailure {
            reason: LiveMetadataError::Transport(e.reason),
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
    /// Local protocol state only. Playing is not proof of a complete or retained document.
    pub fn state(&self) -> ClientState {
        self.active
            .as_ref()
            .map_or(ClientState::Closed, |a| a.protocol.state())
    }
    /// Immutable parameters from the accepted, selected ONVIF metadata description. This is not
    /// permission to borrow configuration from another media offer or stream generation.
    pub fn media(&self) -> Option<&super::client::metadata::MetadataClientMedia> {
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
    ) -> Result<QueuedMetadataRequest, LiveMetadataFailure> {
        self.admit(now, authority)?;
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.transport.has_pending_request())
        {
            return Err(safe(LiveMetadataError::Backpressure));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?
            .protocol
            .request_digest(command, credentials, cnonce, now);
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
    ) -> Result<QueuedMetadataRequest, LiveMetadataFailure> {
        self.admit(now, authority)?;
        if self
            .active
            .as_ref()
            .is_some_and(|a| a.transport.has_pending_request())
        {
            return Err(safe(LiveMetadataError::Backpressure));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?
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
    ) -> Result<LiveMetadataStep, LiveMetadataFailure> {
        if self.active.is_none() {
            return Ok(LiveMetadataStep::Ended);
        }
        self.admit(now, authority)?;
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?
            .protocol
            .poll(now);
        let event = match result {
            Ok(event) => event,
            Err(error) => {
                return Err(self.fail(LiveMetadataError::Protocol(error), None, None, None));
            }
        };
        if !matches!(&event, MetadataClientPoll::Pending { wake_at_ns }
            if wake_at_ns.is_none_or(|at| at > now))
        {
            let transport = if terminal(&event) {
                self.active.take().map(|a| Box::new(a.transport.retire()))
            } else {
                None
            };
            return Ok(LiveMetadataStep::Protocol { event, transport });
        }
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?;
        if active.eof {
            return Ok(LiveMetadataStep::Pending(LiveMetadataWait {
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
                .ok_or_else(|| safe(LiveMetadataError::Closed))?
                .transport
                .write_step(now, authority);
            return match result {
                Ok(TcpWriteStep::Pending) => Ok(self.pending(false, true)),
                Ok(step) => Ok(LiveMetadataStep::Write(step)),
                Err(error) => Err(self.fail(LiveMetadataError::Transport(error), None, None, None)),
            };
        }
        if !readiness.readable {
            return Ok(self.pending(true, false));
        }
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?
            .transport
            .read_step(now, authority);
        match result {
            Ok(TcpReadStep::Pending) => Ok(self.pending(true, false)),
            Ok(TcpReadStep::Eof) => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveMetadataError::Closed))?;
                active.eof = true;
                active.protocol.finish();
                Ok(LiveMetadataStep::InputEnded)
            }
            Ok(TcpReadStep::Buffered) => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveMetadataError::Closed))?;
                let chunk = active
                    .transport
                    .pending_read()
                    .ok_or_else(|| safe(LiveMetadataError::Closed))?;
                let result = active.protocol.ingest(chunk.expose(), chunk.admitted_ns());
                if let Err(failure) = result {
                    return Err(self.fail(
                        LiveMetadataError::Protocol(failure.reason),
                        failure.retirement.map(|r| *r),
                        None,
                        None,
                    ));
                }
                let chunk = self
                    .active
                    .as_mut()
                    .ok_or_else(|| safe(LiveMetadataError::Closed))?
                    .transport
                    .acknowledge_read()
                    .ok_or_else(|| safe(LiveMetadataError::Closed))?;
                Ok(LiveMetadataStep::Wire(chunk))
            }
            Err(error) => Err(self.fail(LiveMetadataError::Transport(error), None, None, None)),
        }
    }
    /// Close without I/O, even after revocation. No automatic TEARDOWN or remote proof.
    pub fn cancel(&mut self) -> Option<LiveMetadataRetirement> {
        self.retire(None, None, None)
    }
    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveMetadataFailure> {
        if self.active.is_none() {
            return Err(safe(LiveMetadataError::Closed));
        }
        if now < self.last_ns {
            return Err(safe(LiveMetadataError::ClockReversed));
        }
        if self.remaining_steps == 0 {
            return Err(self.fail(LiveMetadataError::WorkBudget, None, None, None));
        }
        self.remaining_steps -= 1;
        self.last_ns = now;
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?;
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
        allowed.map_err(|e| self.fail(LiveMetadataError::Transport(e), None, None, None))
    }
    fn queue(
        &mut self,
        request: ClientRequest,
        challenge: Option<RtspWireFrame>,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<QueuedMetadataRequest, LiveMetadataFailure> {
        let command = request.command();
        let cseq = request.cseq();
        let bytes = request.bytes().len();
        let result = self
            .active
            .as_mut()
            .ok_or_else(|| safe(LiveMetadataError::Closed))?
            .transport
            .queue_request(request, now, authority);
        match result {
            Ok(()) => Ok(QueuedMetadataRequest {
                command,
                cseq,
                bytes,
                challenge,
            }),
            Err(refusal) => Err(self.fail(
                LiveMetadataError::Transport(refusal.reason),
                None,
                Some(refusal.request),
                challenge,
            )),
        }
    }
    fn protocol_failure(&mut self, failure: MetadataClientFailure) -> LiveMetadataFailure {
        match failure.retirement {
            Some(retired) => self.fail(
                LiveMetadataError::Protocol(failure.reason),
                Some(*retired),
                None,
                None,
            ),
            None => safe(LiveMetadataError::Protocol(failure.reason)),
        }
    }
    fn pending(&self, readable: bool, writable: bool) -> LiveMetadataStep {
        LiveMetadataStep::Pending(LiveMetadataWait {
            readable,
            writable,
            wake_at_ns: self.next_wake_ns(),
        })
    }
    fn fail(
        &mut self,
        reason: LiveMetadataError,
        protocol: Option<MetadataClientRetirement>,
        request: Option<ClientRequest>,
        challenge: Option<RtspWireFrame>,
    ) -> LiveMetadataFailure {
        LiveMetadataFailure {
            reason,
            retirement: self.retire(protocol, request, challenge).map(Box::new),
        }
    }
    fn retire(
        &mut self,
        protocol: Option<MetadataClientRetirement>,
        request: Option<ClientRequest>,
        challenge: Option<RtspWireFrame>,
    ) -> Option<LiveMetadataRetirement> {
        let mut active = self.active.take()?;
        Some(LiveMetadataRetirement {
            transport: active.transport.retire(),
            protocol: protocol.unwrap_or_else(|| active.protocol.cancel()),
            unqueued_request: request,
            answered_challenge: challenge,
        })
    }
}
fn terminal(event: &MetadataClientPoll) -> bool {
    matches!(
        event,
        MetadataClientPoll::Fault { .. }
            | MetadataClientPoll::Ended { .. }
            | MetadataClientPoll::Rtp {
                retirement: Some(_),
                ..
            }
    )
}
fn safe(reason: LiveMetadataError) -> LiveMetadataFailure {
    LiveMetadataFailure {
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
