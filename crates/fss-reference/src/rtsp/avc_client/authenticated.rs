#![forbid(unsafe_code)]
//! Digest challenge handling composed with the existing loss-aware AVC client.
//!
//! No passwords, HA1 keys, outgoing Authorization values, sockets or entropy
//! sources are owned here. A transport owner supplies credentials and fresh
//! cnonce bytes only when preparing a request. All responses still enter through
//! the real RTSP parser, and every media event comes from the existing AVC pump.

#[path = "selection.rs"]
mod selection;

use super::*;
use crate::rtsp::{AuthScheme, authentication::{AuthenticationError, DigestCredentials, DigestPolicy},
    client::authenticated::DigestClientError, framed::{RetainedRtspWire, RtspWireFrame,
        RtspWireIntake, WireIntakeError, MAX_WIRE_CHUNK, MAX_WIRE_BUFFER}};

/// Payload-free refusal; credential text and wire bytes are never included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestAvcError {
    /// Existing session/authentication owner refused a request or challenge.
    Authentication(DigestClientError),
    /// Existing AVC pump, negotiated source binding, or owner clock failed.
    Client(AvcClientError),
    /// Exact-frame intake failed or expired.
    Wire(WireIntakeError),
    /// Drain output or answer the held challenge first. New input was not consumed.
    Backpressure,
    /// No complete, matching Digest challenge is waiting for credentials.
    NoChallenge,
    /// EOF arrived while authentication still required an outgoing response.
    AuthenticationAtEof,
    /// This connection is already closed or draining EOF.
    Closed,
}
impl fmt::Display for DigestAvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "RTSP authenticated AVC refusal: {self:?}") }
}
impl std::error::Error for DigestAvcError {}

/// Retained TCP input transferred exactly once at closure. Debug never prints it.
#[derive(Debug)]
pub struct DigestWireRetirement {
    /// Unprocessed wire suffix, including a partial or queued next frame.
    pub pending: RetainedRtspWire,
    /// Complete challenge/refused control frame not consumed by authentication.
    pub challenge: Option<RtspWireFrame>,
}
/// Local shutdown of the existing client plus exact unprocessed TCP ownership.
#[derive(Debug)]
pub struct DigestAvcRetirement {
    /// Existing session uncertainty and codec/packet retirement receipts.
    pub client: AvcClientRetirement,
    /// Unconsumed TCP input. Already delivered originals remain the outer owner's duty.
    pub wire: DigestWireRetirement,
}
/// Request/input failure. A missing retirement indicates a safe, unconsumed refusal.
#[derive(Debug)]
pub struct DigestAvcFailure {
    /// Typed reason; no secret-bearing strings.
    pub reason: DigestAvcError,
    /// Present when every local layer was closed by this operation.
    pub retirement: Option<Box<DigestAvcRetirement>>,
}
impl fmt::Display for DigestAvcFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for DigestAvcFailure {}

/// One bounded step, with original AVC outputs preserved rather than reimplemented.
#[derive(Debug)]
pub enum DigestAvcPoll {
    /// The existing client event. A terminal event owns its original client
    /// retirement; the separate wire receipt accounts for this adapter's input.
    Client {
        /// Control, RTP/RTCP, reconstruction, backpressure, or terminal event.
        event: Box<AvcClientPoll>,
        /// Present only on the first client-initiated terminal event/restart.
        wire_retirement: Option<DigestWireRetirement>,
    },
    /// A complete 401 matched the outstanding CSeq. It remains held until respond
    /// or cancellation. No credentials are requested for an unsolicited CSeq or Basic.
    AuthenticationRequired {
        /// Correlation of the challenged request, not the new retry CSeq.
        cseq: u32,
        /// Earliest original request/session/wire/codec deadline; never reset by polling.
        wake_at_ns: Option<u64>,
    },
    /// Intake/authentication stopped the attempt before any further media admission.
    Fault {
        /// Typed reason.
        reason: DigestAvcError,
        /// All local layers retired, with retained challenge and wire ownership.
        retirement: Box<DigestAvcRetirement>,
    },
}

/// Opt-in authenticated TCP-to-AVC connection. The original unauthenticated
/// RtspAvcClient API is unchanged and cannot be reached mutably through this type.
///
/// Poll to Pending between feeds. Answer AuthenticationRequired with respond;
/// authenticated keepalive and TEARDOWN use request. Prepared requests must be
/// written once or the transport closed: preparation is not a socket-send receipt.
/// The same parser/session/media implementations handle both public client paths.
pub struct DigestAvcClient {
    inner: RtspAvcClient,
    intake: RtspWireIntake,
    challenge: Option<RtspWireFrame>,
    challenge_deadline_ns: Option<u64>,
    pending_cseq: Option<u32>,
    input_ready: bool,
    input_ended: bool,
    closed: bool,
}
impl fmt::Debug for DigestAvcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestAvcClient").field("state", &self.inner.state())
            .field("wire_bytes", &self.buffered_wire_bytes())
            .field("challenge_pending", &self.challenge.is_some())
            .field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl DigestAvcClient {
    /// Pin owner URL scope, stream epoch, media limits, credential realm and policy
    /// before any request. SHA-256 remains the default; no automatic legacy fallback.
    pub fn new(config: ClientConfig, key: StreamKey, limits: AvcReceiveLimits,
        realm: &str, policy: DigestPolicy) -> Result<Self, DigestAvcError>
    {
        let mut inner = RtspAvcClient::new(config, key, limits).map_err(DigestAvcError::Client)?;
        inner.session.enable_digest(realm, policy).map_err(DigestAvcError::Authentication)?;
        Ok(Self { inner, intake: RtspWireIntake::new(), challenge: None,
            challenge_deadline_ns: None, pending_cseq: None, input_ready: true,
            input_ended: false, closed: false })
    }
    /// Negotiation only, never authentication of received frames or camera health.
    pub fn state(&self) -> ClientState { self.inner.state() }
    /// Exact retained TCP bytes, including a challenge awaiting an explicit owner.
    pub fn buffered_wire_bytes(&self) -> usize {
        self.intake.buffered_bytes() + self.challenge.as_ref().map_or(0, |c| c.expose_wire().len())
    }
    /// Existing receiver's retained reconstructed NAL bytes.
    pub fn retained_nal_bytes(&self) -> usize { self.inner.retained_nal_bytes() }
    /// Earliest useful progress/deadline. A held challenge does not busy-poll its lookahead.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        let wire_wake = if self.challenge.is_some() { self.intake.deadline_ns() } else { self.intake.next_wake_ns() };
        earlier(earlier(self.inner.next_wake_ns(), wire_wake), self.challenge_deadline_ns)
    }
    /// Borrow credentials for this request only. The first request is unsigned;
    /// later commands reuse the validated challenge with increasing nonce counts.
    pub fn request(&mut self, command: ClientCommand, credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16], now: u64) -> Result<ClientRequest, DigestAvcFailure>
    {
        self.admit_operation(now)?;
        if self.challenge.is_some() || self.intake.buffered_bytes() != 0 || self.inner.events.len() != 0 || self.inner.retry.is_some() {
            return Err(safe(DigestAvcError::Backpressure));
        }
        match self.inner.session.request_digest(command, credentials, cnonce, now) {
            Ok(request) => { self.pending_cseq = Some(request.cseq()); Ok(request) }
            Err(error) => Err(self.request_failure(error)),
        }
    }
    /// Answer the internally retained exact 401, without asking the caller to
    /// reconstruct discarded headers. The existing Digest session enforces realm,
    /// scope, retry/stale-nonce limits, fresh CSeq and the ORIGINAL request deadline.
    /// Any refused challenge closes the attempt; the rejected raw response is returned.
    pub fn respond(&mut self, credentials: &DigestCredentials<'_>, cnonce: [u8; 16], now: u64)
        -> Result<ClientRequest, DigestAvcFailure>
    {
        self.admit_operation(now)?;
        let challenge = self.challenge.as_ref().ok_or_else(|| safe(DigestAvcError::NoChallenge))?;
        match self.inner.session.retry_digest_response(challenge.expose_wire(), credentials, cnonce, now) {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                self.challenge = None; self.challenge_deadline_ns = None;
                Ok(request)
            }
            Err(error) => Err(self.fatal(DigestAvcError::Authentication(error))),
        }
    }
    /// Feed one bounded TCP chunk. Backpressure/limit refusals consume no new
    /// bytes. Fatal failures return prior retained wire; caller still owns this chunk.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<(), DigestAvcFailure> {
        self.admit_operation(now)?;
        if !self.input_ready || self.challenge.is_some() || self.inner.events.len() != 0 || self.inner.retry.is_some() {
            return Err(safe(DigestAvcError::Backpressure));
        }
        if bytes.len() > MAX_WIRE_CHUNK || bytes.len() > MAX_WIRE_BUFFER.saturating_sub(self.intake.buffered_bytes()) {
            return Err(safe(DigestAvcError::Wire(WireIntakeError::Limit)));
        }
        match self.intake.ingest(bytes, now) {
            Ok(()) => { self.input_ready = false; Ok(()) }
            Err(error) if matches!(error, WireIntakeError::Backpressure | WireIntakeError::Limit | WireIntakeError::Allocation) => {
                Err(safe(DigestAvcError::Wire(error)))
            }
            Err(error) => Err(self.fatal(DigestAvcError::Wire(error))),
        }
    }
    /// Drive timers/media even while credentials are pending. Authentication
    /// messages are never fed to the unauthenticated accept path or admitted twice.
    pub fn poll(&mut self, now: u64) -> Result<DigestAvcPoll, DigestAvcError> {
        self.inner.check_time(now).map_err(DigestAvcError::Client)?;
        if self.closed { return Ok(DigestAvcPoll::Client {
            event: Box::new(AvcClientPoll::Ended { media: None, retirement: None }), wire_retirement: None }); }
        self.inner.last_ns = now;
        if let Some(error) = self.deadline_error(now) { return Ok(self.fault(error)); }
        let event = match self.inner.poll(now) {
            Ok(event) => event,
            Err(error) => return Ok(self.fault(DigestAvcError::Client(error))),
        };
        let keepalive_due = matches!(&event, AvcClientPoll::Control(ClientProgress::KeepAliveDue));
        if self.inner.draining || !matches!(&event, AvcClientPoll::Pending { .. } | AvcClientPoll::Control(ClientProgress::KeepAliveDue)) {
            return Ok(self.client_event(event));
        }
        if self.challenge.is_some() {
            if self.input_ended { return Ok(self.fault(DigestAvcError::AuthenticationAtEof)); }
            return Ok(DigestAvcPoll::AuthenticationRequired { cseq: self.pending_cseq.ok_or(DigestAvcError::NoChallenge)?,
                wake_at_ns: self.next_wake_ns() });
        }
        // Save the oldest-byte deadline BEFORE the frame leaves intake. Waiting
        // for a credential owner cannot restart that frame's residence budget.
        let frame_deadline = self.intake.deadline_ns();
        match self.intake.poll(now) {
            Err(error) => return Ok(self.fault(DigestAvcError::Wire(error))),
            Ok(Some(frame)) => {
                self.input_ready = false;
                if let RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. } = frame.event()
                    && matches!(response.status_code, 401 | 407) {
                        let matching = response.headers.cseq().is_some_and(|c| c.ok() == self.pending_cseq) && self.pending_cseq.is_some();
                        let supported = response.status_code == 401 && response.auth_challenge == Some(AuthScheme::Digest);
                        self.challenge = Some(frame); self.challenge_deadline_ns = frame_deadline;
                        if !matching { return Ok(self.fault(DigestAvcError::Client(AvcClientError::Session(ClientError::CseqMismatch)))); }
                        if !supported { return Ok(self.fault(DigestAvcError::Authentication(DigestClientError::Authentication(AuthenticationError::Unsupported)))); }
                        if self.input_ended { return Ok(self.fault(DigestAvcError::AuthenticationAtEof)); }
                        return Ok(DigestAvcPoll::AuthenticationRequired { cseq: self.pending_cseq.ok_or(DigestAvcError::NoChallenge)?,
                            wake_at_ns: self.next_wake_ns() });
                }
                let (event, _original, received_ns) = frame.into_parts();
                // No public event injection API: only this child module can hand
                // an event validated by exact-frame intake to the existing pump.
                self.inner.events = vec![event].into_iter(); self.inner.event_time_ns = received_ns;
                return match self.inner.poll(now) {
                    Ok(event) => Ok(self.client_event(event)),
                    Err(error) => Ok(self.fault(DigestAvcError::Client(error))),
                };
            }
            Ok(None) => self.input_ready = true,
        }
        if self.intake.is_ended() {
            self.inner.finish();
            return match self.inner.poll(now) {
                Ok(event) => Ok(self.client_event(event)),
                Err(error) => Ok(self.fault(DigestAvcError::Client(error))),
            };
        }
        if keepalive_due { return Ok(self.client_event(event)); }
        Ok(self.client_event(AvcClientPoll::Pending { wake_at_ns: self.next_wake_ns() }))
    }
    /// EOF drains prior complete frames, then the existing receiver. A pending
    /// challenge cannot be answered after EOF or turned into successful negotiation.
    pub fn finish(&mut self) { self.input_ended = true; self.intake.finish(); }
    /// Cancel this connection and transfer all local retirement/source ownership.
    /// No implicit TEARDOWN request or claim of remote cancellation is made.
    pub fn cancel(&mut self) -> DigestAvcRetirement {
        let client = self.inner.cancel();
        DigestAvcRetirement { client, wire: self.close_wire() }
    }
    fn close_wire(&mut self) -> DigestWireRetirement {
        self.closed = true; self.input_ready = false; self.challenge_deadline_ns = None;
        DigestWireRetirement { pending: self.intake.cancel(), challenge: self.challenge.take() }
    }
    fn client_event(&mut self, event: AvcClientPoll) -> DigestAvcPoll {
        if matches!(&event, AvcClientPoll::Control(ClientProgress::Accepted(_))) { self.pending_cseq = None; }
        if self.inner.draining { self.input_ended = true; }
        let wire_retirement = if self.inner.closed { Some(self.close_wire()) } else { None };
        DigestAvcPoll::Client { event: Box::new(event), wire_retirement }
    }
    fn deadline_error(&self, now: u64) -> Option<DigestAvcError> {
        [self.intake.deadline_ns(), self.challenge_deadline_ns].into_iter().flatten()
            .any(|at| now >= at).then_some(DigestAvcError::Wire(WireIntakeError::Deadline))
    }
    fn admit_operation(&mut self, now: u64) -> Result<(), DigestAvcFailure> {
        self.inner.check_time(now).map_err(|e| safe(DigestAvcError::Client(e)))?;
        if self.closed || self.input_ended || self.inner.input_ended { return Err(safe(DigestAvcError::Closed)); }
        if let Some(error) = self.deadline_error(now) { return Err(self.fatal(error)); }
        self.inner.last_ns = now;
        if let Err(error) = self.inner.session.tick(now) {
            return Err(self.fatal(DigestAvcError::Client(AvcClientError::Session(error))));
        }
        Ok(())
    }
    fn request_failure(&mut self, error: DigestClientError) -> DigestAvcFailure {
        let reason = DigestAvcError::Authentication(error);
        if self.inner.session.state() == ClientState::Failed { self.fatal(reason) } else { safe(reason) }
    }
    fn fatal(&mut self, reason: DigestAvcError) -> DigestAvcFailure {
        DigestAvcFailure { reason, retirement: Some(Box::new(self.cancel())) }
    }
    fn fault(&mut self, reason: DigestAvcError) -> DigestAvcPoll {
        DigestAvcPoll::Fault { reason, retirement: Box::new(self.cancel()) }
    }
}
fn safe(reason: DigestAvcError) -> DigestAvcFailure { DigestAvcFailure { reason, retirement: None } }
