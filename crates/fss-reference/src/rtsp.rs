#![forbid(unsafe_code)]
//! Sans-IO RTSP/1.0 parsing and owner-driven client negotiation for FSS.
//!
//! Public wire parsing redacts credentials. Explicit authentication helpers
//! borrow owner-supplied secrets without I/O. A PLAY response is not proof of
//! frames, source custody, or continuous camera coverage.

/// Bounded opt-in Digest authentication for an explicit credential owner.
pub mod authentication;
/// RTSP framing, negotiated video, and source-linked AVC receiver composition.
pub mod avc_client;
/// Exact bounded wire frames for explicit authentication and source-custody owners.
pub mod framed;
/// Owner-driven TCP framing, optional Digest authentication, and HEVC RTP reception.
pub mod hevc_client;
/// Ordered HEVC client-event capture with explicit timing and automatic failure fencing.
pub mod hevc_recording_capture;
/// Continuous HEVC window collection with original boundary-packet retention.
pub mod hevc_recording_collector;

/// Independently persisted checkpoint references and exact cold pin recovery.
pub mod archive_pins;
/// Exact storage-only resumption of unacknowledged archive windows and catalog pages.
pub mod archive_recovery;
/// Capability-scoped, owner-driven RTSP/1.0 client session reference.
pub mod client;
/// Original RTP/RTCP custody and verified replay before recording windows seal.
pub mod datagram_archive;
/// Cold source-verified AVC reconstruction with explicit configuration and clocks.
pub mod datagram_reconstruction;
/// Live capture backpressured by durable recording and immutable catalog publication.
pub mod live_archive;
/// Selected-SDP native HEVC capture with independently journaled archive protection.
pub mod live_hevc_archive;
/// Exclusive native TCP-to-authenticated-AVC streaming with bounded owner-driven progress.
pub mod live_avc;
pub mod message;
/// Sealed source-linked recording windows and byte-provenance verification.
pub mod recording;
/// Bounded local archive discovery, restart recovery, and cross-page retrieval.
pub mod recording_archive;
/// Bounded receiver-event capture with explicit timing and automatic failure fencing.
pub mod recording_capture;
/// Immutable multi-window discovery and bounded, verified decode-range retrieval.
pub mod recording_catalog;
/// Continuous bounded IDR collection with explicit source ownership and backpressure.
pub mod recording_collector;
/// Portable codec/timing recipes and exact source-verified recording reconstruction.
pub mod recording_recipe;
pub mod sdp;
/// Exact bounded H.264 selection from multi-payload SDP descriptions.
pub mod selection;
/// Native bounded TCP ownership under an exact route and explicit live authority.
pub mod tcp;

pub use message::{
    AuthScheme, ContentLengthConflict, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS,
    DEFAULT_MAX_INTERLEAVED_BYTES, DEFAULT_MAX_LINE_BYTES, DuplicateHeader, HeaderLimitFault,
    HeaderValueFault, LengthLimit, MessageKind, NulSite, NumericFault, PoisonCause,
    REDACTED_CREDENTIAL, RtspError, RtspEvent, RtspHeader, RtspHeaders, RtspLimits, RtspMethod,
    RtspParser, RtspRequest, RtspResponse, RtspTransport, StartLineFault, TransportFault,
    UnsupportedMethod, UserinfoSite, Utf8Fault, VersionFault,
};
pub use sdp::{
    Base64Fault, MAX_BASE64_INPUT_BYTES, MAX_SDP_LINE_BYTES, MAX_SDP_LINES, SdpControlLevel,
    SdpError, SdpFault, SdpLimitFault, SdpMalformed, SdpMedia, SdpSession, decode_base64,
    parse_sdp, parse_sdp_bytes,
};

/// Native, exclusively owned TCP -> RTSP/Digest -> RTP/HEVC picture acquisition.
///
/// This reference path uses the existing protocol, packet and picture owners. It adds no
/// runtime, DNS, reconnect, decoder, secret store or implicit capture clock. Every raw wire
/// chunk must be retained or explicitly omitted by the caller; a picture is not custody.
pub mod live_hevc {
    #![forbid(unsafe_code)]

    use std::fmt;

    use fss_packet::hevc::HevcAssemblyLimits;
    use fss_packet::{H265Limits, ReorderLimits};

    use super::authentication::{DigestCredentials, DigestPolicy};
    use super::client::{ClientCommand, ClientConfig, ClientRequest, ClientState};
    use super::framed::RtspWireFrame;
    use super::hevc_client::HevcClientPoll;
    use super::hevc_client::pictures::{
        HevcPictureClientError, HevcPictureClientFailure, HevcPictureClientPoll,
        HevcPictureClientRetirement, RtspHevcPictureClient,
    };
    /// The same readiness contract as the existing native AVC owner.
    pub use super::live_avc::SocketReadiness;
    use super::tcp::{
        RtspTcpLink, TcpAuthority, TcpBinding, TcpError, TcpLimits, TcpOperation, TcpReadChunk,
        TcpReadStep, TcpRetirement, TcpTotals, TcpWriteStep,
    };

    /// Exact caller-owned route, HEVC work ceilings and authentication policy.
    /// Construction grants no authority; every operation still probes `TcpAuthority`.
    pub struct LiveHevcConfig {
        /// Exact presentation and permitted control subtree; the server cannot redirect them.
        pub protocol: ClientConfig,
        /// Caller-resolved peer, stream epoch, expected SSRC and explicit plaintext approval.
        pub binding: TcpBinding,
        /// Independent socket byte, allocation and call limits.
        pub transport: TcpLimits,
        /// Independent RTP queue and sequence bounds.
        pub reorder: ReorderLimits,
        /// Independent HEVC reconstruction and fragment bounds.
        pub reconstruction: H265Limits,
        /// Independent picture and complete-NAL residence bounds.
        pub assembly: HevcAssemblyLimits,
        /// Exact accepted Digest realm, not a wildcard or a credential.
        pub realm: String,
        /// Explicit algorithm policy; default policy does not downgrade to legacy Digest.
        pub digest_policy: DigestPolicy,
        /// Absolute owner-clock lifetime, including negotiation and EOF draining.
        pub deadline_ns: u64,
        /// Total request/respond/poll admissions, including calls without socket readiness.
        pub max_steps: u64,
    }
    impl fmt::Debug for LiveHevcConfig {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("LiveHevcConfig")
                .field("binding", &self.binding)
                .field("deadline_ns", &self.deadline_ns)
                .field("max_steps", &self.max_steps)
                .finish_non_exhaustive()
        }
    }

    /// Payload-free outer refusal. Existing owners retain their typed failure categories.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum LiveHevcError {
        /// Invalid limits or a protocol authority not identical to the bound native route.
        Configuration,
        /// Native socket, lease or live authority refused progress.
        Transport(TcpError),
        /// Shared RTSP, Digest, packet or picture owner refused progress.
        Protocol(HevcPictureClientError),
        /// Resolve the current queued request before preparing another one.
        Backpressure,
        /// Monotonic admission time reversed; no state or budget changed.
        ClockReversed,
        /// Connection-wide work allowance is exhausted, not clean EOF.
        WorkBudget,
        /// Terminal ownership has already transferred.
        Closed,
    }
    impl fmt::Display for LiveHevcError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "live RTSP HEVC refusal: {self:?}")
        }
    }
    impl std::error::Error for LiveHevcError {}

    /// Construction refused before any RTSP request was sent or any secret borrowed.
    #[derive(Debug)]
    pub struct LiveHevcConnectFailure {
        /// Typed refusal without a URL, credential or media payload.
        pub reason: LiveHevcError,
        /// Whether the peer may have observed a TCP connection attempt.
        pub connection_attempted: bool,
    }
    impl fmt::Display for LiveHevcConnectFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.reason, f)
        }
    }
    impl std::error::Error for LiveHevcConnectFailure {}

    /// One locally queued request, not a socket-send or server-acceptance receipt.
    #[must_use]
    #[derive(Debug)]
    pub struct QueuedHevcRequest {
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
    pub struct LiveHevcRetirement {
        /// Buffered original TCP bytes, queued request and exact already-sent prefix.
        pub transport: TcpRetirement,
        /// Original challenges, packet/fragment/picture work and remote-session uncertainty.
        pub protocol: HevcPictureClientRetirement,
        /// Prepared request rejected before transport queue admission. Never resend implicitly.
        pub unqueued_request: Option<ClientRequest>,
        /// Challenge consumed before a failed queue admission, returned intact instead of lost.
        pub answered_challenge: Option<RtspWireFrame>,
    }

    /// Safe refusals preserve the live owner; fatal ones transfer every layer exactly once.
    #[derive(Debug)]
    pub struct LiveHevcFailure {
        /// Payload-free failure category.
        pub reason: LiveHevcError,
        /// Present only when this call closed the connection.
        pub retirement: Option<Box<LiveHevcRetirement>>,
    }
    impl fmt::Display for LiveHevcFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.reason, f)
        }
    }
    impl std::error::Error for LiveHevcFailure {}

    /// Readiness and timer work needed by this exclusive owner.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct LiveHevcWait {
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
    pub enum LiveHevcStep {
        /// Exact original TCP bytes accepted at their original admission time.
        /// Transfer does not establish durable custody; Debug omits their contents.
        Wire(TcpReadChunk),
        /// One existing native write result; socket acceptance is not remote execution.
        Write(TcpWriteStep),
        /// Unchanged source-bearing protocol/HEVC picture event.
        Protocol {
            /// Existing typed control, packet, picture, failure or EOF result.
            event: HevcPictureClientPoll,
            /// Transferred once when this event closes the native connection.
            transport: Option<Box<TcpRetirement>>,
        },
        /// Actual socket EOF. Accepted input must still drain under the original lease.
        InputEnded,
        /// No immediate semantic output; honor readiness and the earliest timer.
        Pending(LiveHevcWait),
        /// All terminal ownership has already transferred; no repeated success receipt.
        Ended,
    }

    struct Active {
        transport: RtspTcpLink,
        protocol: RtspHevcPictureClient,
        eof: bool,
    }

    /// Exclusive native HEVC connection. A call polls at most one protocol step and attempts
    /// at most one socket operation. Queued source, Digest challenges, picture work and RTP
    /// backpressure drain before further socket input. No request is retried automatically.
    #[must_use]
    pub struct LiveHevcConnection {
        active: Option<Active>,
        deadline_ns: u64,
        last_ns: u64,
        remaining_steps: u64,
    }
    impl fmt::Debug for LiveHevcConnection {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("LiveHevcConnection")
                .field("state", &self.state())
                .field("remaining_steps", &self.remaining_steps)
                .finish_non_exhaustive()
        }
    }
    impl LiveHevcConnection {
        /// Validate both semantic owners and exact route equality before a single connect.
        pub fn connect(
            config: LiveHevcConfig,
            now: u64,
            authority: &dyn TcpAuthority,
        ) -> Result<Self, LiveHevcConnectFailure> {
            let refused = |reason| LiveHevcConnectFailure {
                reason,
                connection_attempted: false,
            };
            if config.max_steps == 0 || now >= config.deadline_ns {
                return Err(refused(LiveHevcError::Configuration));
            }
            let presentation = uri_authority(&config.protocol.presentation_uri);
            if presentation != Some(config.binding.authority())
                || uri_authority(&config.protocol.control_root_uri) != presentation
            {
                return Err(refused(LiveHevcError::Configuration));
            }
            let protocol = RtspHevcPictureClient::with_digest(
                config.protocol,
                config.binding.key(),
                config.reorder,
                config.reconstruction,
                config.assembly,
                &config.realm,
                config.digest_policy,
            )
            .map_err(|e| refused(LiveHevcError::Protocol(e)))?;
            let transport = RtspTcpLink::connect(
                config.binding, config.transport, now, config.deadline_ns, authority,
            )
            .map_err(|e| LiveHevcConnectFailure {
                reason: LiveHevcError::Transport(e.reason),
                connection_attempted: e.connection_attempted,
            })?;
            Ok(Self {
                active: Some(Active { transport, protocol, eof: false }),
                deadline_ns: config.deadline_ns,
                last_ns: now,
                remaining_steps: config.max_steps,
            })
        }
        /// Local protocol state only. Playing is not proof of a complete or retained picture.
        pub fn state(&self) -> ClientState {
            self.active.as_ref().map_or(ClientState::Closed, |a| a.protocol.state())
        }
        /// Immutable parameters from the accepted, selected HEVC description. This is not
        /// permission to borrow configuration from another media offer or stream generation.
        pub fn media(&self) -> Option<&super::client::hevc::HevcClientMedia> {
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
        ) -> Result<QueuedHevcRequest, LiveHevcFailure> {
            self.admit(now, authority)?;
            if self.active.as_ref().is_some_and(|a| a.transport.has_pending_request()) {
                return Err(safe(LiveHevcError::Backpressure));
            }
            let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                .protocol.request_digest(command, credentials, cnonce, now);
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
        ) -> Result<QueuedHevcRequest, LiveHevcFailure> {
            self.admit(now, authority)?;
            if self.active.as_ref().is_some_and(|a| a.transport.has_pending_request()) {
                return Err(safe(LiveHevcError::Backpressure));
            }
            let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                .protocol.respond_digest(credentials, cnonce, now);
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
        ) -> Result<LiveHevcStep, LiveHevcFailure> {
            if self.active.is_none() {
                return Ok(LiveHevcStep::Ended);
            }
            self.admit(now, authority)?;
            let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                .protocol.poll(now);
            let event = match result {
                Ok(event) => event,
                Err(error) => return Err(self.fail(LiveHevcError::Protocol(error), None, None, None)),
            };
            if !matches!(&event, HevcPictureClientPoll::Pending { wake_at_ns }
                if wake_at_ns.is_none_or(|at| at > now))
            {
                let transport = if terminal(&event) {
                    self.active.take().map(|a| Box::new(a.transport.retire()))
                } else {
                    None
                };
                return Ok(LiveHevcStep::Protocol { event, transport });
            }
            let active = self.active.as_ref().ok_or_else(|| safe(LiveHevcError::Closed))?;
            if active.eof {
                return Ok(LiveHevcStep::Pending(LiveHevcWait {
                    readable: false,
                    writable: false,
                    wake_at_ns: earlier(self.next_wake_ns(), Some(now)),
                }));
            }
            if active.transport.has_pending_request() {
                if !readiness.writable {
                    return Ok(self.pending(false, true));
                }
                let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                    .transport.write_step(now, authority);
                return match result {
                    Ok(TcpWriteStep::Pending) => Ok(self.pending(false, true)),
                    Ok(step) => Ok(LiveHevcStep::Write(step)),
                    Err(error) => Err(self.fail(LiveHevcError::Transport(error), None, None, None)),
                };
            }
            if !readiness.readable {
                return Ok(self.pending(true, false));
            }
            let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                .transport.read_step(now, authority);
            match result {
                Ok(TcpReadStep::Pending) => Ok(self.pending(true, false)),
                Ok(TcpReadStep::Eof) => {
                    let active = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?;
                    active.eof = true;
                    active.protocol.finish();
                    Ok(LiveHevcStep::InputEnded)
                }
                Ok(TcpReadStep::Buffered) => {
                    let active = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?;
                    let chunk = active.transport.pending_read()
                        .ok_or_else(|| safe(LiveHevcError::Closed))?;
                    let result = active.protocol.ingest(chunk.expose(), chunk.admitted_ns());
                    if let Err(failure) = result {
                        return Err(self.fail(
                            LiveHevcError::Protocol(failure.reason),
                            failure.retirement.map(|r| *r), None, None,
                        ));
                    }
                    let chunk = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                        .transport.acknowledge_read().ok_or_else(|| safe(LiveHevcError::Closed))?;
                    Ok(LiveHevcStep::Wire(chunk))
                }
                Err(error) => Err(self.fail(LiveHevcError::Transport(error), None, None, None)),
            }
        }
        /// Close without I/O, even after revocation. No automatic TEARDOWN or remote proof.
        pub fn cancel(&mut self) -> Option<LiveHevcRetirement> {
            self.retire(None, None, None)
        }
        fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), LiveHevcFailure> {
            if self.active.is_none() {
                return Err(safe(LiveHevcError::Closed));
            }
            if now < self.last_ns {
                return Err(safe(LiveHevcError::ClockReversed));
            }
            if self.remaining_steps == 0 {
                return Err(self.fail(LiveHevcError::WorkBudget, None, None, None));
            }
            self.remaining_steps -= 1;
            self.last_ns = now;
            let active = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?;
            let allowed = if active.eof {
                if now >= self.deadline_ns {
                    Err(TcpError::Deadline)
                } else {
                    authority.checkpoint(active.transport.binding(), TcpOperation::Poll, now,
                        self.deadline_ns).map_err(TcpError::Denied)
                }
            } else {
                active.transport.check(now, authority)
            };
            allowed.map_err(|e| self.fail(LiveHevcError::Transport(e), None, None, None))
        }
        fn queue(
            &mut self,
            request: ClientRequest,
            challenge: Option<RtspWireFrame>,
            now: u64,
            authority: &dyn TcpAuthority,
        ) -> Result<QueuedHevcRequest, LiveHevcFailure> {
            let command = request.command();
            let cseq = request.cseq();
            let bytes = request.bytes().len();
            let result = self.active.as_mut().ok_or_else(|| safe(LiveHevcError::Closed))?
                .transport.queue_request(request, now, authority);
            match result {
                Ok(()) => Ok(QueuedHevcRequest { command, cseq, bytes, challenge }),
                Err(refusal) => Err(self.fail(LiveHevcError::Transport(refusal.reason), None,
                    Some(refusal.request), challenge)),
            }
        }
        fn protocol_failure(&mut self, failure: HevcPictureClientFailure) -> LiveHevcFailure {
            match failure.retirement {
                Some(retired) => self.fail(LiveHevcError::Protocol(failure.reason),
                    Some(*retired), None, None),
                None => safe(LiveHevcError::Protocol(failure.reason)),
            }
        }
        fn pending(&self, readable: bool, writable: bool) -> LiveHevcStep {
            LiveHevcStep::Pending(LiveHevcWait { readable, writable, wake_at_ns: self.next_wake_ns() })
        }
        fn fail(
            &mut self,
            reason: LiveHevcError,
            protocol: Option<HevcPictureClientRetirement>,
            request: Option<ClientRequest>,
            challenge: Option<RtspWireFrame>,
        ) -> LiveHevcFailure {
            LiveHevcFailure { reason,
                retirement: self.retire(protocol, request, challenge).map(Box::new) }
        }
        fn retire(
            &mut self,
            protocol: Option<HevcPictureClientRetirement>,
            request: Option<ClientRequest>,
            challenge: Option<RtspWireFrame>,
        ) -> Option<LiveHevcRetirement> {
            let mut active = self.active.take()?;
            Some(LiveHevcRetirement {
                transport: active.transport.retire(),
                protocol: protocol.unwrap_or_else(|| active.protocol.cancel()),
                unqueued_request: request,
                answered_challenge: challenge,
            })
        }
    }
    fn terminal(event: &HevcPictureClientPoll) -> bool {
        match event {
            HevcPictureClientPoll::Client { event, work } => work.is_some() || matches!(event.as_ref(),
                HevcClientPoll::Fault { .. } | HevcClientPoll::Ended { .. }
                    | HevcClientPoll::Rtp { retirement: Some(_), .. }),
            HevcPictureClientPoll::Assembly { retirement, .. } => retirement.is_some(),
            HevcPictureClientPoll::Fault { .. } | HevcPictureClientPoll::Ended { .. } => true,
            _ => false,
        }
    }
    fn safe(reason: LiveHevcError) -> LiveHevcFailure {
        LiveHevcFailure { reason, retirement: None }
    }
    fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
        match (a, b) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) }
    }
    fn uri_authority(uri: &str) -> Option<&str> {
        uri.strip_prefix("rtsp://")?.split('/').next()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::rtsp::client::ClientProgress;
        use crate::rtsp::tcp::{TcpDenial, TcpSecurityPolicy};
        use fss_packet::StreamKey;
        use std::cell::Cell;
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
        use std::time::Duration;

        type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
        const LEASE: u64 = 100_000_000_000;
        const TIMEOUT: u64 = 10_000_000_000;
        struct Authority {
            binding: TcpBinding,
            revoked: Cell<bool>,
            reject_queue: Cell<bool>,
            checks: Cell<u64>,
        }
        impl TcpAuthority for Authority {
            fn checkpoint(&self, binding: &TcpBinding, op: TcpOperation, now: u64, until: u64)
                -> Result<(), TcpDenial>
            {
                self.checks.set(self.checks.get() + 1);
                if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
                if self.revoked.get() { return Err(TcpDenial::Revoked); }
                if self.reject_queue.get() && op == TcpOperation::QueueRequest {
                    return Err(TcpDenial::Budget);
                }
                if until != LEASE || now >= until { return Err(TcpDenial::Deadline); }
                Ok(())
            }
        }
        fn config(peer: std::net::SocketAddr) -> Test<(LiveHevcConfig, Authority)> {
            let binding = TcpBinding::new(StreamKey { ingress: 99, generation: 1, ssrc: 7 }, peer,
                "fixture.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
            let authority = Authority { binding: binding.clone(), revoked: Cell::new(false),
                reject_queue: Cell::new(false), checks: Cell::new(0) };
            Ok((LiveHevcConfig {
                protocol: ClientConfig {
                    presentation_uri: "rtsp://fixture.local/live/".into(),
                    control_root_uri: "rtsp://fixture.local/live".into(), media_index: 0,
                    channels: (0, 1), response_timeout_ns: TIMEOUT,
                    default_session_timeout_seconds: 60,
                },
                binding, transport: TcpLimits::default(), reorder: ReorderLimits::default(),
                reconstruction: H265Limits::default(), assembly: HevcAssemblyLimits::default(),
                realm: "test-realm".into(), digest_policy: DigestPolicy::default(),
                deadline_ns: LEASE, max_steps: 100_000,
            }, authority))
        }
        fn credentials() -> Test<DigestCredentials<'static>> {
            Ok(DigestCredentials::new("test-user", "test-password")?)
        }
        fn sdp() -> &'static str {
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=control:track\r\n"
        }
        fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
            format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
                body.len()).into_bytes()
        }
        fn challenge(cseq: u32) -> Vec<u8> {
            format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"test-realm\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
        }
        struct Fixture {
            driver: LiveHevcConnection,
            peer: TcpStream,
            authority: Authority,
            nonce: u128,
        }
        impl Fixture {
            fn new(chunk: usize) -> Test<Self> {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                let (mut config, authority) = config(listener.local_addr()?)?;
                config.transport.chunk_bytes = chunk;
                let driver = LiveHevcConnection::connect(config, 0, &authority)?;
                let (peer, _) = listener.accept()?;
                peer.set_read_timeout(Some(Duration::from_secs(2)))?;
                peer.set_write_timeout(Some(Duration::from_secs(2)))?;
                peer.set_nodelay(true)?;
                Ok(Self { driver, peer, authority, nonce: 0 })
            }
            fn queue(&mut self, command: ClientCommand, now: u64) -> Test<QueuedHevcRequest> {
                self.nonce += 1;
                Ok(self.driver.request(command, &credentials()?, self.nonce.to_be_bytes(), now,
                    &self.authority)?)
            }
            fn flush(&mut self, queued: &QueuedHevcRequest, now: u64) -> Test<Vec<u8>> {
                for _ in 0..32_768 {
                    match self.driver.poll(SocketReadiness { readable: false, writable: true },
                        now, &self.authority)?
                    {
                        LiveHevcStep::Write(TcpWriteStep::Sent { cseq, bytes }) => {
                            assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                            let mut wire = vec![0; bytes];
                            self.peer.read_exact(&mut wire)?;
                            return Ok(wire);
                        }
                        LiveHevcStep::Write(TcpWriteStep::Advanced { .. }) | LiveHevcStep::Pending(_) => {}
                        _ => return Err("unexpected output while sending HEVC request".into()),
                    }
                }
                Err("HEVC request work bound".into())
            }
            fn command(&mut self, command: ClientCommand, now: u64) -> Test<u32> {
                let queued = self.queue(command, now)?;
                self.flush(&queued, now)?;
                Ok(queued.cseq)
            }
            fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<HevcPictureClientPoll>> {
                self.peer.write_all(bytes)?;
                let mut original = Vec::new();
                let mut events = Vec::new();
                for _ in 0..32_768 {
                    match self.driver.poll(SocketReadiness { readable: true, writable: false },
                        now, &self.authority)?
                    {
                        LiveHevcStep::Wire(chunk) => {
                            assert_eq!(chunk.admitted_ns(), now);
                            original.extend_from_slice(chunk.expose());
                        }
                        LiveHevcStep::Protocol { event, transport } => {
                            let blocked = matches!(&event, HevcPictureClientPoll::Client { event, .. }
                                if matches!(event.as_ref(), HevcClientPoll::AuthenticationRequired { .. }));
                            events.push(event);
                            if blocked || transport.is_some() {
                                assert_eq!(original, bytes);
                                return Ok(events);
                            }
                        }
                        LiveHevcStep::Pending(wait) => {
                            if original.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                                assert_eq!(original, bytes);
                                return Ok(events);
                            }
                            std::thread::yield_now();
                        }
                        _ => return Err("unexpected HEVC receive output".into()),
                    }
                }
                Err("HEVC receive work bound".into())
            }
        }
        fn accepted(events: &[HevcPictureClientPoll], state: ClientState) -> bool {
            events.iter().any(|e| matches!(e, HevcPictureClientPoll::Client { event, work: None }
                if matches!(event.as_ref(), HevcClientPoll::Control { progress: ClientProgress::Accepted(s), .. }
                    if *s == state)))
        }

        #[test]
        fn mismatched_route_refuses_before_authority_or_connect() -> Test {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let (mut config, authority) = config(listener.local_addr()?)?;
            config.protocol.presentation_uri = "rtsp://other.local/live/".into();
            let error = LiveHevcConnection::connect(config, 0, &authority).err().ok_or("connected")?;
            assert_eq!(error.reason, LiveHevcError::Configuration);
            assert!(!error.connection_attempted);
            assert_eq!(authority.checks.get(), 0);
            Ok(())
        }
        #[test]
        fn short_io_negotiates_hevc_without_calling_play_a_picture() -> Test {
            for chunk in [1, 7, 4096] {
                let mut f = Fixture::new(chunk)?;
                let seq = f.command(ClientCommand::Describe, 0)?;
                let events = f.receive(&response(seq, "Content-Type: application/sdp\r\n", sdp()), 1)?;
                assert!(accepted(&events, ClientState::Described));
                assert!(!events.iter().any(|e| matches!(e, HevcPictureClientPoll::Assembly { .. })));
                let seq = f.command(ClientCommand::Setup, 2)?;
                assert!(accepted(&f.receive(&response(seq,
                    "Session: test-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?, ClientState::Ready));
                let seq = f.command(ClientCommand::Play, 4)?;
                assert!(accepted(&f.receive(&response(seq, "Session: test-session\r\n", ""), 5)?,
                    ClientState::Playing));
                assert_eq!(f.driver.state(), ClientState::Playing);
                let retired = f.driver.cancel().ok_or("retirement")?;
                assert!(retired.protocol.client.session.remote_session_may_exist);
                assert!(f.driver.cancel().is_none());
            }
            Ok(())
        }
        #[test]
        fn digest_answer_transfers_the_exact_original_challenge() -> Test {
            let mut f = Fixture::new(7)?;
            let seq = f.command(ClientCommand::Describe, 0)?;
            let raw = challenge(seq);
            f.receive(&raw, 1)?;
            let before = f.driver.totals().ok_or("totals")?;
            f.peer.write_all(b"unadmitted-next-response")?;
            let step = f.driver.poll(SocketReadiness { readable: true, writable: true }, 2, &f.authority)?;
            assert!(matches!(step, LiveHevcStep::Protocol { event: HevcPictureClientPoll::Client { event, .. }, transport: None }
                if matches!(*event, HevcClientPoll::AuthenticationRequired { .. })));
            assert_eq!(f.driver.totals(), Some(before));
            let queued = f.driver.respond(&credentials()?, [2; 16], 3, &f.authority)?;
            assert_eq!(queued.challenge.as_ref().ok_or("challenge lost")?.expose_wire(), raw);
            let sent = f.flush(&queued, 3)?;
            let text = std::str::from_utf8(&sent)?;
            assert!(text.contains("Authorization: Digest "));
            assert!(!text.contains("test-password"));
            let _retired = f.driver.cancel().ok_or("retirement")?;
            Ok(())
        }
        #[test]
        fn failed_digest_queue_preserves_both_request_and_consumed_challenge() -> Test {
            let mut f = Fixture::new(4096)?;
            let seq = f.command(ClientCommand::Describe, 0)?;
            let raw = challenge(seq);
            f.receive(&raw, 1)?;
            let before = f.driver.totals().ok_or("totals")?;
            f.authority.reject_queue.set(true);
            let failure = f.driver.respond(&credentials()?, [3; 16], 2, &f.authority)
                .err().ok_or("queue unexpectedly admitted")?;
            let retired = failure.retirement.ok_or("retirement")?;
            assert_eq!(retired.transport.totals.sent_bytes, before.sent_bytes);
            assert_eq!(retired.answered_challenge.ok_or("challenge lost")?.expose_wire(), raw);
            assert!(retired.unqueued_request.is_some());
            assert!(f.driver.cancel().is_none());
            assert!(matches!(f.driver.poll(SocketReadiness::default(), 3, &f.authority)?, LiveHevcStep::Ended));
            Ok(())
        }
        #[test]
        fn partial_write_timeout_is_not_retried() -> Test {
            let mut f = Fixture::new(1)?;
            let _queued = f.queue(ClientCommand::Describe, 0)?;
            assert!(matches!(f.driver.poll(SocketReadiness { readable: false, writable: true }, 0, &f.authority)?,
                LiveHevcStep::Write(TcpWriteStep::Advanced { sent: 1, .. })));
            let step = f.driver.poll(SocketReadiness::default(), TIMEOUT, &f.authority)?;
            let LiveHevcStep::Protocol { transport: Some(retired), .. } = step else {
                return Err("missing timeout retirement".into());
            };
            assert_eq!(retired.request_sent_bytes, 1);
            assert_eq!(retired.totals.sent_bytes, 1);
            assert!(retired.request.is_some());
            assert!(matches!(f.driver.poll(SocketReadiness::default(), TIMEOUT + 1, &f.authority)?, LiveHevcStep::Ended));
            Ok(())
        }
        #[test]
        fn revoked_idle_connection_never_reads_the_waiting_source() -> Test {
            let mut f = Fixture::new(4096)?;
            f.peer.write_all(b"private unread source")?;
            f.authority.revoked.set(true);
            let failure = f.driver.poll(SocketReadiness { readable: true, writable: true }, 1, &f.authority)
                .err().ok_or("revocation ignored")?;
            assert_eq!(failure.reason, LiveHevcError::Transport(TcpError::Denied(TcpDenial::Revoked)));
            let retired = failure.retirement.ok_or("retirement")?;
            assert_eq!(retired.transport.totals.read_calls, 0);
            assert_eq!(retired.transport.totals.sent_bytes, 0);
            assert!(f.driver.cancel().is_none());
            Ok(())
        }
        #[test]
        fn reversed_time_preserves_work_and_pending_request() -> Test {
            let mut f = Fixture::new(4096)?;
            let queued = f.queue(ClientCommand::Describe, 10)?;
            let remaining = f.driver.remaining_steps();
            let totals = f.driver.totals();
            let failure = f.driver.poll(SocketReadiness::default(), 9, &f.authority)
                .err().ok_or("clock reversal admitted")?;
            assert_eq!(failure.reason, LiveHevcError::ClockReversed);
            assert!(failure.retirement.is_none());
            assert_eq!(f.driver.remaining_steps(), remaining);
            assert_eq!(f.driver.totals(), totals);
            f.flush(&queued, 11)?;
            let _retired = f.driver.cancel().ok_or("retirement")?;
            Ok(())
        }
        #[test]
        fn eof_drain_still_requires_live_authority() -> Test {
            let mut f = Fixture::new(4096)?;
            f.peer.shutdown(Shutdown::Write)?;
            let mut eof = false;
            for _ in 0..1000 {
                if matches!(f.driver.poll(SocketReadiness { readable: true, writable: false }, 0, &f.authority)?,
                    LiveHevcStep::InputEnded)
                { eof = true; break; }
            }
            assert!(eof);
            f.authority.revoked.set(true);
            let failure = f.driver.poll(SocketReadiness::default(), 1, &f.authority)
                .err().ok_or("EOF bypassed authority")?;
            assert_eq!(failure.reason, LiveHevcError::Transport(TcpError::Denied(TcpDenial::Revoked)));
            assert!(failure.retirement.ok_or("retirement")?.transport.totals.peer_eof);
            assert_eq!(f.driver.next_wake_ns(), None);
            Ok(())
        }
    }
}
