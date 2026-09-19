#![forbid(unsafe_code)]
//! Owner-driven RTSP TCP -> negotiated HEVC NAL reception, with exact wire ownership.
//!
//! One shared RTSP session owns scope, CSeq, authentication and lifetime. The
//! existing exact-frame intake and H265Receiver own wire and media semantics.
//! This module performs no I/O and does not turn PLAY or a NAL into frame,
//! source-custody, capture-time, decoding, or physical-coverage certification.

use std::fmt;

use fss_packet::{
    H265Limits, H265ReceiveAdmission, H265ReceiveCancellation, H265ReceiveError,
    H265ReceivePoll, H265Receiver, PacketError, ReorderDisposition, ReorderError,
    ReorderLimits, RtcpCompound, RtcpMode, StreamKey,
};

use super::authentication::{AuthenticationError, DigestCredentials, DigestPolicy};
use super::client::authenticated::DigestClientError;
use super::client::hevc::HevcClientMedia;
use super::client::{
    ClientChannel, ClientCloseReceipt, ClientCodec, ClientCommand, ClientConfig,
    ClientError, ClientProgress, ClientRequest, ClientState, RtspClientSession,
};
use super::framed::{
    MAX_WIRE_BUFFER, MAX_WIRE_CHUNK, RetainedRtspWire, RtspWireFrame, RtspWireIntake,
    WireIntakeError,
};
use super::{AuthScheme, RtspEvent};

/// Payload-free refusal categories. No URL, token, challenge or media is printed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HevcClientError {
    /// Shared RTSP scope, correlation, state or lifetime refusal.
    Session(ClientError),
    /// Existing Digest owner refused credentials, challenge or retry policy.
    Authentication(DigestClientError),
    /// Exact-frame intake rejected framing, expiry, EOF or a bounded allocation.
    Wire(WireIntakeError),
    /// Shared RTP admission or HEVC reconstruction configuration failed.
    Video(H265ReceiveError),
    /// Owner epoch is invalid or SETUP asserted a different expected SSRC.
    StreamBinding,
    /// Drain pending input/media or answer the held challenge before retrying.
    Backpressure,
    /// Input exceeds a fixed bound or cannot fit even an empty RTP queue.
    InputLimit,
    /// Server-initiated control requests have no admitted handling contract.
    ServerRequest,
    /// No complete, matching Digest challenge is currently held.
    NoChallenge,
    /// EOF arrived while authentication still required an outgoing response.
    AuthenticationAtEof,
    /// Local input is closed or draining; a new connection requires a new owner epoch.
    Closed,
}

impl fmt::Display for HevcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP HEVC refusal: {self:?}")
    }
}
impl std::error::Error for HevcClientError {}

/// Terminal accounting for every locally retained layer, not remote TEARDOWN proof.
#[derive(Debug)]
pub struct HevcClientRetirement {
    /// Shared session uncertainty and any outstanding request correlation.
    pub session: ClientCloseReceipt,
    /// Separate retirement of queued RTP datagrams and incomplete HEVC fragments.
    pub video: Option<H265ReceiveCancellation>,
    /// All unprocessed TCP bytes, including a malformed or incomplete suffix.
    pub wire: RetainedRtspWire,
    /// A complete challenge that was not successfully consumed by authentication.
    pub challenge: Option<RtspWireFrame>,
    /// A complete RTP frame awaiting queue capacity, never admitted twice.
    pub retry: Option<RtspWireFrame>,
}

/// Failed request/feed. Without a retirement this is a safe, unconsumed refusal.
#[derive(Debug)]
pub struct HevcClientFailure {
    /// Stable category with no source contents or credentials.
    pub reason: HevcClientError,
    /// Present only when this operation closed and retired every local layer.
    pub retirement: Option<Box<HevcClientRetirement>>,
}
impl fmt::Display for HevcClientFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HevcClientFailure {}

/// A prepared retry and the exact challenge it consumed. Neither implies a send.
#[derive(Debug)]
pub struct HevcChallengeResponse {
    /// Scoped request with a fresh CSeq and the original absolute deadline.
    pub request: ClientRequest,
    /// Original challenge transferred to the explicit authentication/custody owner.
    /// Its wire may contain sensitive material; Debug excludes all contents.
    pub source: RtspWireFrame,
}

/// Exactly one bounded progress step. All source-bearing values hide bytes in Debug.
#[derive(Debug)]
pub enum HevcClientPoll {
    /// A complete response accepted by the shared session, not a frame observation.
    Control {
        /// Existing typed session progress.
        progress: ClientProgress,
        /// Exact original response, including SDP or other opaque body bytes.
        source: RtspWireFrame,
    },
    /// Original interleaved RTP frame and its independent transport admission result.
    Rtp {
        /// Original TCP envelope and datagram, even for duplicates and probation.
        source: RtspWireFrame,
        /// Shared sequence/restart accounting; reconstruction comes from Media steps.
        admission: H265ReceiveAdmission,
        /// Present on confirmed source restart, which permanently closes this epoch.
        retirement: Option<Box<HevcClientRetirement>>,
    },
    /// Whole-compound RTCP validation, without inventing wall time or a coverage claim.
    Rtcp {
        /// Exact source bytes survive malformed RTCP too.
        source: RtspWireFrame,
        /// Validated packet count or typed failure; RTCP failure is not a video gap.
        validation: Result<usize, PacketError>,
    },
    /// Existing ordered RTP/HEVC output, including original datagrams on codec failures.
    Media(H265ReceivePoll),
    /// A matching Digest 401 is retained until respond_digest, expiry or cancellation.
    AuthenticationRequired {
        /// Correlation of the challenged request, not the new retry CSeq.
        cseq: u32,
        /// Earliest original request, session, wire or media deadline.
        wake_at_ns: Option<u64>,
    },
    /// Queue pressure retains the unconsumed frame and its original residence deadline.
    Backpressure {
        /// Arrange this wake even when no more TCP input arrives.
        wake_at_ns: Option<u64>,
    },
    /// Owner should explicitly prepare a keepalive; no request was sent automatically.
    KeepAliveDue,
    /// No immediate work; the owner must drive the next timer wake.
    Pending {
        /// Earliest session, intake, held-frame, reorder or fragment wake.
        wake_at_ns: Option<u64>,
    },
    /// Fatal session/input failure with complete retirement and any rejected exact frame.
    Fault {
        /// Payload-free refusal.
        reason: HevcClientError,
        /// Local quiescence, unprocessed source bytes and remote-session uncertainty.
        retirement: Box<HevcClientRetirement>,
        /// A parsed frame returned intact when its control/media admission failed.
        source: Option<RtspWireFrame>,
    },
    /// Local EOF/TEARDOWN draining ended. This never asserts successful remote closure.
    Ended {
        /// Final media EOF event, including any incomplete-fragment retirement.
        media: Option<H265ReceivePoll>,
        /// Present only on the first terminal poll, never repeated.
        retirement: Option<Box<HevcClientRetirement>>,
    },
}

struct HeldFrame {
    frame: RtspWireFrame,
    deadline_ns: u64,
}

/// Bounded, optionally authenticated, owner-driven TCP-to-HEVC reference connection.
///
/// Feed at most MAX_WIRE_CHUNK bytes, then poll until Pending/Backpressure or a
/// held authentication challenge. Honor next_wake_ns even without network input.
/// An explicit stream key binds the expected SSRC and generation; SDP cannot
/// switch the codec or grant network authority. The original TCP source remains
/// separately subject to the owner's custody/privacy policy.
///
/// Outer frame received_ns is final-byte intake time. Ordered RTP received_ns is
/// queue-admission time; backpressure may delay that admission. Neither is camera
/// capture time. All codec work uses monotonic processing time after reordering.
pub struct RtspHevcClient {
    session: RtspClientSession,
    intake: RtspWireIntake,
    key: StreamKey,
    reorder_limits: ReorderLimits,
    h265_limits: H265Limits,
    video: Option<H265Receiver>,
    challenge: Option<HeldFrame>,
    retry: Option<HeldFrame>,
    pending_cseq: Option<u32>,
    last_ns: u64,
    digest_enabled: bool,
    input_ready: bool,
    input_ended: bool,
    draining: bool,
    closed: bool,
}

impl fmt::Debug for RtspHevcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspHevcClient")
            .field("key", &self.key)
            .field("state", &self.state())
            .field("wire_bytes", &self.buffered_wire_bytes())
            .field("pending_nal_bytes", &self.retained_nal_bytes())
            .field("challenge_pending", &self.challenge.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl RtspHevcClient {
    /// Validate scope, expected source and both independent budgets before any request.
    pub fn new(
        config: ClientConfig,
        key: StreamKey,
        reorder_limits: ReorderLimits,
        h265_limits: H265Limits,
    ) -> Result<Self, HevcClientError> {
        if key.ingress == 0 || key.generation == 0 {
            return Err(HevcClientError::StreamBinding);
        }
        let session = RtspClientSession::with_codec(config, ClientCodec::H265)
            .map_err(HevcClientError::Session)?;
        // Validate through the semantic owners. This temporary receiver admits
        // no packet; the actual payload type is bound only after DESCRIBE/SETUP.
        let _ = H265Receiver::new(key, 0, 0, reorder_limits, h265_limits)
            .map_err(HevcClientError::Video)?;
        Ok(Self {
            session, intake: RtspWireIntake::new(), key, reorder_limits, h265_limits,
            video: None, challenge: None, retry: None, pending_cseq: None,
            last_ns: 0, digest_enabled: false, input_ready: true,
            input_ended: false, draining: false, closed: false,
        })
    }

    /// Pin a credential realm/policy before the first request. Passwords and HA1
    /// values are never stored. SHA-256 remains the default; no legacy fallback.
    pub fn with_digest(
        config: ClientConfig,
        key: StreamKey,
        reorder_limits: ReorderLimits,
        h265_limits: H265Limits,
        realm: &str,
        policy: DigestPolicy,
    ) -> Result<Self, HevcClientError> {
        let mut client = Self::new(config, key, reorder_limits, h265_limits)?;
        client.session.enable_digest(realm, policy)
            .map_err(HevcClientError::Authentication)?;
        client.digest_enabled = true;
        Ok(client)
    }

    /// Shared protocol state only, not frame, source-custody or camera health truth.
    pub fn state(&self) -> ClientState { self.session.state() }
    /// Exact accepted HEVC signaling; missing parameter sets remain missing.
    pub fn media(&self) -> Option<&HevcClientMedia> { self.session.hevc_media() }
    /// All retained TCP bytes, including any complete held challenge/retry frame.
    pub fn buffered_wire_bytes(&self) -> usize {
        self.intake.buffered_bytes()
            + self.challenge.as_ref().map_or(0, |h| h.frame.expose_wire().len())
            + self.retry.as_ref().map_or(0, |h| h.frame.expose_wire().len())
    }
    /// Retained incomplete NAL bytes, not the independent source-custody size.
    pub fn retained_nal_bytes(&self) -> usize {
        self.video.as_ref().map_or(0, H265Receiver::pending_nal_bytes)
    }
    /// Original RTP bytes queued for ordered delivery, not a persistence receipt.
    pub fn queued_rtp_bytes(&self) -> usize {
        self.video.as_ref().map_or(0, H265Receiver::queued_bytes)
    }

    /// Earliest useful owner wake. A held frame never busy-polls queued lookahead.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        if self.draining { return Some(self.last_ns); }
        let held = self.challenge.is_some() || self.retry.is_some();
        let intake = if held { self.intake.deadline_ns() } else { self.intake.next_wake_ns() };
        let mut wake = if self.buffered_wire_bytes() == 0 {
            self.session.next_wake_ns()
        } else {
            // Requests cannot be issued while a prior frame is unresolved.
            // Keepalive is advisory; do not busy-poll it in a blocked state.
            self.session.next_expiry_ns()
        };
        for at in [
            intake,
            self.video.as_ref().and_then(H265Receiver::next_wake_ns),
            self.challenge.as_ref().map(|h| h.deadline_ns),
            self.retry.as_ref().map(|h| h.deadline_ns),
        ] { wake = earlier(wake, at); }
        if self.input_ended && !held { wake = earlier(wake, Some(self.last_ns)); }
        wake.map(|at| at.max(self.last_ns))
    }

    /// Prepare a plain request. A Digest-enabled client cannot bypass its secret owner.
    /// Write the prepared request once or close; preparation is not a send receipt.
    pub fn request(&mut self, command: ClientCommand, now: u64)
        -> Result<ClientRequest, HevcClientFailure>
    {
        self.admit_request(now)?;
        match self.session.request(command, now) {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(request)
            }
            Err(error) => Err(self.request_failure(HevcClientError::Session(error))),
        }
    }

    /// Borrow credentials for one scoped request. The first request is unsigned;
    /// accepted challenges are reused only under the shared monotone nonce policy.
    pub fn request_digest(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<ClientRequest, HevcClientFailure> {
        self.admit_request(now)?;
        match self.session.request_digest(command, credentials, cnonce, now) {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(request)
            }
            Err(error) => Err(self.request_failure(HevcClientError::Authentication(error))),
        }
    }

    /// Consume the internally retained exact 401. Return both the prepared retry
    /// and original challenge; no reserialization, lost raw challenge, or clock reset.
    /// A refused challenge closes this attempt and transfers every retained source.
    pub fn respond_digest(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
    ) -> Result<HevcChallengeResponse, HevcClientFailure> {
        self.admit_operation(now)?;
        let held = self.challenge.take().ok_or_else(|| safe(HevcClientError::NoChallenge))?;
        match self.session.retry_digest_response(held.frame.expose_wire(), credentials, cnonce, now) {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(HevcChallengeResponse { request, source: held.frame })
            }
            Err(error) => {
                self.challenge = Some(held);
                Err(self.fatal(HevcClientError::Authentication(error)))
            }
        }
    }

    /// Admit one bounded TCP chunk. Backpressure and input-limit refusals consume
    /// no bytes. On fatal failure the retirement owns previously accepted wire;
    /// the new, refused chunk still belongs to the caller.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<(), HevcClientFailure> {
        self.check_time(now).map_err(safe)?;
        if self.closed || self.input_ended { return Err(safe(HevcClientError::Closed)); }
        if !self.input_ready || self.challenge.is_some() || self.retry.is_some() {
            return Err(safe(HevcClientError::Backpressure));
        }
        if bytes.len() > MAX_WIRE_CHUNK
            || bytes.len() > MAX_WIRE_BUFFER.saturating_sub(self.intake.buffered_bytes())
        { return Err(safe(HevcClientError::InputLimit)); }
        self.admit_operation(now)?;
        match self.intake.ingest(bytes, now) {
            Ok(()) => { self.input_ready = false; Ok(()) }
            Err(error @ (WireIntakeError::Backpressure | WireIntakeError::Limit | WireIntakeError::Allocation)) => {
                Err(safe(HevcClientError::Wire(error)))
            }
            Err(error) => Err(self.fatal(HevcClientError::Wire(error))),
        }
    }

    /// One bounded progress step. Deadlines run before queued output, and codec
    /// expiry cannot consume the next original datagram. Poll even without traffic.
    pub fn poll(&mut self, now: u64) -> Result<HevcClientPoll, HevcClientError> {
        self.check_time(now)?;
        self.last_ns = now;
        if self.closed {
            return Ok(HevcClientPoll::Ended { media: None, retirement: None });
        }
        if !self.draining && let Some(error) = self.deadline_error(now) {
            return Ok(self.fault(error, None));
        }
        if let Some(video) = &mut self.video {
            match video.poll(now) {
                Ok(H265ReceivePoll::Pending { .. }) => {},
                Ok(event @ H265ReceivePoll::Ended { .. }) => {
                    let retirement = Some(Box::new(self.cancel()));
                    return Ok(HevcClientPoll::Ended { media: Some(event), retirement });
                }
                Ok(event) => return Ok(HevcClientPoll::Media(event)),
                Err(error) => return Ok(self.fault(HevcClientError::Video(error), None)),
            }
        }
        if self.draining {
            let retirement = Some(Box::new(self.cancel()));
            return Ok(HevcClientPoll::Ended { media: None, retirement });
        }
        if self.challenge.is_some() {
            if self.input_ended { return Ok(self.fault(HevcClientError::AuthenticationAtEof, None)); }
            let Some(cseq) = self.pending_cseq else {
                return Ok(self.fault(HevcClientError::NoChallenge, None));
            };
            return Ok(HevcClientPoll::AuthenticationRequired { cseq, wake_at_ns: self.next_wake_ns() });
        }
        if let Some(held) = self.retry.take() { return Ok(self.frame(held, now)); }
        // Capture the ORIGINAL oldest-byte deadline before intake transfers the
        // frame. Holding a challenge or a full-queue retry never resets its age.
        let deadline = self.intake.deadline_ns();
        match self.intake.poll(now) {
            Ok(Some(frame)) => {
                let Some(deadline_ns) = deadline else {
                    return Ok(self.fault(HevcClientError::Wire(WireIntakeError::Framing), Some(frame)));
                };
                return Ok(self.frame(HeldFrame { frame, deadline_ns }, now));
            }
            Ok(None) => self.input_ready = true,
            Err(error) => return Ok(self.fault(HevcClientError::Wire(error), None)),
        }
        if self.intake.is_ended() {
            self.draining = true;
            if let Some(video) = &mut self.video {
                video.finish();
                return Ok(HevcClientPoll::Pending { wake_at_ns: Some(now) });
            }
            let retirement = Some(Box::new(self.cancel()));
            return Ok(HevcClientPoll::Ended { media: None, retirement });
        }
        if self.buffered_wire_bytes() == 0
            && self.session.tick(now).map_err(HevcClientError::Session)? == ClientProgress::KeepAliveDue
        {
            return Ok(HevcClientPoll::KeepAliveDue);
        }
        Ok(HevcClientPoll::Pending { wake_at_ns: self.next_wake_ns() })
    }

    fn frame(&mut self, held: HeldFrame, now: u64) -> HevcClientPoll {
        match held.frame.event() {
            RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. } => {
                if matches!(response.status_code, 401 | 407) && self.digest_enabled {
                    let matching = self.pending_cseq.is_some()
                        && response.headers.cseq().is_some_and(|c| c.ok() == self.pending_cseq);
                    let supported = response.status_code == 401 && response.auth_challenge == Some(AuthScheme::Digest);
                    self.challenge = Some(held);
                    if !matching {
                        return self.fault(HevcClientError::Session(ClientError::CseqMismatch), None);
                    }
                    if !supported {
                        return self.fault(HevcClientError::Authentication(
                            DigestClientError::Authentication(AuthenticationError::Unsupported)), None);
                    }
                    if self.input_ended { return self.fault(HevcClientError::AuthenticationAtEof, None); }
                    let Some(cseq) = self.pending_cseq else {
                        return self.fault(HevcClientError::NoChallenge, None);
                    };
                    return HevcClientPoll::AuthenticationRequired { cseq, wake_at_ns: self.next_wake_ns() };
                }
                match self.session.accept(response, now) {
                    Ok(progress) => {
                        if progress != ClientProgress::Interim { self.pending_cseq = None; }
                        if self.session.state() == ClientState::Ready && self.video.is_none()
                            && let Err(error) = self.configure_video()
                        { return self.fault(error, Some(held.frame)); }
                        if self.session.state() == ClientState::Closed {
                            // Input after a confirmed TEARDOWN is not admitted.
                            // Return its exact lookahead as part of terminal retirement.
                            self.input_ended = true;
                            self.draining = true;
                            self.intake.finish();
                            if let Some(video) = &mut self.video { video.finish(); }
                        }
                        HevcClientPoll::Control { progress, source: held.frame }
                    }
                    Err(error) => self.fault(HevcClientError::Session(error), Some(held.frame)),
                }
            }
            RtspEvent::Interleaved { channel, span } => {
                let channel = match self.session.admit_channel(*channel, now) {
                    Ok(channel) => channel,
                    Err(error) => return self.fault(HevcClientError::Session(error), Some(held.frame)),
                };
                if channel == ClientChannel::Rtcp {
                    let reduced = self.session.hevc_media().is_some_and(|m| m.reduced_rtcp());
                    let mode = if reduced { RtcpMode::ReducedSize } else { RtcpMode::Compound };
                    let validation = RtcpCompound::parse(span, self.reorder_limits.packet, mode)
                        .map(|compound| compound.packet_count());
                    return HevcClientPoll::Rtcp { source: held.frame, validation };
                }
                let result = match &mut self.video {
                    Some(video) => video.ingest(self.key, span, now),
                    None => return self.fault(HevcClientError::StreamBinding, Some(held.frame)),
                };
                match result {
                    Ok(admission) => {
                        let restart = admission.transport.disposition == ReorderDisposition::RestartRequired;
                        let retirement = if restart { Some(Box::new(self.cancel())) } else { None };
                        HevcClientPoll::Rtp { source: held.frame, admission, retirement }
                    }
                    Err(H265ReceiveError::Transport(ReorderError::PacketCapacity | ReorderError::ByteCapacity)) => {
                        if span.len() > self.reorder_limits.max_bytes {
                            return self.fault(HevcClientError::InputLimit, Some(held.frame));
                        }
                        self.retry = Some(held);
                        HevcClientPoll::Backpressure { wake_at_ns: self.next_wake_ns() }
                    }
                    Err(error) => self.fault(HevcClientError::Video(error), Some(held.frame)),
                }
            }
            RtspEvent::Request(_) => self.fault(HevcClientError::ServerRequest, Some(held.frame)),
        }
    }

    fn configure_video(&mut self) -> Result<(), HevcClientError> {
        if self.session.server_ssrc().is_some_and(|ssrc| ssrc != self.key.ssrc) {
            return Err(HevcClientError::StreamBinding);
        }
        let media = self.session.hevc_media().ok_or(HevcClientError::StreamBinding)?;
        self.video = Some(H265Receiver::new(
            self.key, media.payload_type(), media.sprop_max_don_diff(),
            self.reorder_limits, self.h265_limits,
        ).map_err(HevcClientError::Video)?);
        Ok(())
    }

    /// Mark EOF. Complete frames drain before codec EOF; truncated wire becomes
    /// a fault with original retained bytes, never successful media finalization.
    pub fn finish(&mut self) { self.input_ended = true; self.intake.finish(); }

    /// Stop every local layer and transfer exact unprocessed wire ownership.
    /// No automatic TEARDOWN is sent and no source-custody data is deleted.
    pub fn cancel(&mut self) -> HevcClientRetirement {
        self.closed = true;
        self.input_ready = false;
        self.pending_cseq = None;
        HevcClientRetirement {
            session: self.session.cancel(),
            video: self.video.take().map(|mut video| video.cancel()),
            wire: self.intake.cancel(),
            challenge: self.challenge.take().map(|h| h.frame),
            retry: self.retry.take().map(|h| h.frame),
        }
    }

    fn check_time(&self, now: u64) -> Result<(), HevcClientError> {
        if now < self.last_ns { Err(HevcClientError::Session(ClientError::ClockReversed)) }
        else { Ok(()) }
    }
    fn deadline_error(&mut self, now: u64) -> Option<HevcClientError> {
        if let Err(error) = self.session.tick(now) { return Some(HevcClientError::Session(error)); }
        let expired = [
            self.intake.deadline_ns(),
            self.challenge.as_ref().map(|h| h.deadline_ns),
            self.retry.as_ref().map(|h| h.deadline_ns),
        ].into_iter().flatten().any(|at| now >= at);
        expired.then_some(HevcClientError::Wire(WireIntakeError::Deadline))
    }
    fn admit_operation(&mut self, now: u64) -> Result<(), HevcClientFailure> {
        self.check_time(now).map_err(safe)?;
        if self.closed || self.input_ended { return Err(safe(HevcClientError::Closed)); }
        self.last_ns = now;
        if let Some(error) = self.deadline_error(now) { return Err(self.fatal(error)); }
        Ok(())
    }
    fn admit_request(&mut self, now: u64) -> Result<(), HevcClientFailure> {
        self.admit_operation(now)?;
        if self.buffered_wire_bytes() != 0 {
            return Err(safe(HevcClientError::Backpressure));
        }
        Ok(())
    }
    fn request_failure(&mut self, reason: HevcClientError) -> HevcClientFailure {
        if self.session.state() == ClientState::Failed { self.fatal(reason) } else { safe(reason) }
    }
    fn fatal(&mut self, reason: HevcClientError) -> HevcClientFailure {
        HevcClientFailure { reason, retirement: Some(Box::new(self.cancel())) }
    }
    fn fault(&mut self, reason: HevcClientError, source: Option<RtspWireFrame>) -> HevcClientPoll {
        HevcClientPoll::Fault { reason, retirement: Box::new(self.cancel()), source }
    }
}

fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) }
}
fn safe(reason: HevcClientError) -> HevcClientFailure {
    HevcClientFailure { reason, retirement: None }
}

/// Loss-aware picture assembly on the same plain or authenticated HEVC client.
pub mod pictures;
