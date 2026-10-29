#![forbid(unsafe_code)]
//! Owner-driven RTSP TCP -> negotiated ONVIF metadata document reception, with exact wire ownership.
//!
//! One shared RTSP session owns scope, CSeq, authentication and lifetime. The
//! existing exact-frame intake and OnvifMetadataReceiver own wire and media semantics.
//! This module performs no I/O and does not turn PLAY or a document into
//! source-custody, capture-time, XML validity, vendor trust or physical-coverage certification.

use std::fmt;

use fss_packet::{
    OnvifMetadataLimits, OnvifMetadataReceiveAdmission, OnvifMetadataReceiveCancellation,
    OnvifMetadataReceiveError, OnvifMetadataReceivePoll, OnvifMetadataReceiver, PacketError,
    ReorderDisposition, ReorderError, ReorderLimits, RtcpCompound, RtcpMode, StreamKey,
};

use super::RtspEvent;
use super::authentication::{AuthenticationError, DigestCredentials, DigestPolicy};
use super::client::authenticated::DigestClientError;
use super::client::metadata::MetadataClientMedia;
use super::client::{
    ClientChannel, ClientCloseReceipt, ClientCodec, ClientCommand, ClientConfig, ClientError,
    ClientProgress, ClientRequest, ClientState, RtspClientSession,
};
use super::framed::{
    MAX_WIRE_BUFFER, MAX_WIRE_CHUNK, RetainedRtspWire, RtspWireFrame, RtspWireIntake,
    WireIntakeError,
};

/// Payload-free refusal categories. No URL, token, challenge or media is printed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataClientError {
    /// Shared RTSP scope, correlation, state or lifetime refusal.
    Session(ClientError),
    /// Existing Digest owner refused credentials, challenge or retry policy.
    Authentication(DigestClientError),
    /// Exact-frame intake rejected framing, expiry, EOF or a bounded allocation.
    Wire(WireIntakeError),
    /// Shared RTP admission or ONVIF metadata reconstruction configuration failed.
    Metadata(OnvifMetadataReceiveError),
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

impl fmt::Display for MetadataClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP ONVIF metadata refusal: {self:?}")
    }
}
impl std::error::Error for MetadataClientError {}

/// Terminal accounting for every locally retained layer, not remote TEARDOWN proof.
#[derive(Debug)]
pub struct MetadataClientRetirement {
    /// Shared session uncertainty and any outstanding request correlation.
    pub session: ClientCloseReceipt,
    /// Separate retirement of queued RTP datagrams and incomplete ONVIF metadata fragments.
    pub metadata: Option<OnvifMetadataReceiveCancellation>,
    /// All unprocessed TCP bytes, including a malformed or incomplete suffix.
    pub wire: RetainedRtspWire,
    /// A complete challenge that was not successfully consumed by authentication.
    pub challenge: Option<RtspWireFrame>,
    /// A complete RTP frame awaiting queue capacity, never admitted twice.
    pub retry: Option<RtspWireFrame>,
}

/// Failed request/feed. Without a retirement this is a safe, unconsumed refusal.
#[derive(Debug)]
pub struct MetadataClientFailure {
    /// Stable category with no source contents or credentials.
    pub reason: MetadataClientError,
    /// Present only when this operation closed and retired every local layer.
    pub retirement: Option<Box<MetadataClientRetirement>>,
}
impl fmt::Display for MetadataClientFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for MetadataClientFailure {}

/// A prepared retry and the exact challenge it consumed. Neither implies a send.
#[derive(Debug)]
pub struct MetadataChallengeResponse {
    /// Scoped request with a fresh CSeq and the original absolute deadline.
    pub request: ClientRequest,
    /// Original challenge transferred to the explicit authentication/custody owner.
    /// Its wire may contain sensitive material; Debug excludes all contents.
    pub source: RtspWireFrame,
}

/// Exactly one bounded progress step. All source-bearing values hide bytes in Debug.
#[derive(Debug)]
pub enum MetadataClientPoll {
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
        /// Shared sequence/restart accounting; reconstruction comes from Metadata steps.
        admission: OnvifMetadataReceiveAdmission,
        /// Present on confirmed source restart, which permanently closes this epoch.
        retirement: Option<Box<MetadataClientRetirement>>,
    },
    /// Whole-compound RTCP validation, without inventing wall time or a coverage claim.
    Rtcp {
        /// Exact source bytes survive malformed RTCP too.
        source: RtspWireFrame,
        /// Validated packet count or typed failure; RTCP failure is not a metadata gap.
        validation: Result<usize, PacketError>,
    },
    /// Existing ordered RTP/ONVIF metadata output, including original datagrams on reconstruction failures.
    Metadata(OnvifMetadataReceivePoll),
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
        reason: MetadataClientError,
        /// Local quiescence, unprocessed source bytes and remote-session uncertainty.
        retirement: Box<MetadataClientRetirement>,
        /// A parsed frame returned intact when its control/media admission failed.
        source: Option<RtspWireFrame>,
    },
    /// Local EOF/TEARDOWN draining ended. This never asserts successful remote closure.
    Ended {
        /// Final media EOF event, including any incomplete-fragment retirement.
        media: Option<OnvifMetadataReceivePoll>,
        /// Present only on the first terminal poll, never repeated.
        retirement: Option<Box<MetadataClientRetirement>>,
    },
}

struct HeldFrame {
    frame: RtspWireFrame,
    deadline_ns: u64,
}

/// Bounded, optionally authenticated, owner-driven TCP-to-ONVIF metadata reference connection.
///
/// Feed at most MAX_WIRE_CHUNK bytes, then poll until Pending/Backpressure or a
/// held authentication challenge. Honor next_wake_ns even without network input.
/// An explicit stream key binds the expected SSRC and generation, and a dynamic
/// payload type pins the exact uncompressed application mapping. SDP cannot
/// select gzip/EXI, change the expected source or grant network authority. Original
/// TCP source remains separately subject to the owner's custody/privacy policy.
///
/// Outer frame and ordered RTP received_ns preserve the same final-byte intake
/// time, even when backpressure delays queue admission. This is not camera capture
/// time. Queue deadlines and document work use the actual monotonic processing time.
pub struct RtspMetadataClient {
    session: RtspClientSession,
    intake: RtspWireIntake,
    key: StreamKey,
    reorder_limits: ReorderLimits,
    metadata_limits: OnvifMetadataLimits,
    metadata: Option<OnvifMetadataReceiver>,
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

impl fmt::Debug for RtspMetadataClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspMetadataClient")
            .field("key", &self.key)
            .field("state", &self.state())
            .field("wire_bytes", &self.buffered_wire_bytes())
            .field("pending_document_bytes", &self.retained_document_bytes())
            .field("challenge_pending", &self.challenge.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl RtspMetadataClient {
    /// Validate scope, expected source and both independent budgets before any request.
    pub fn new(
        config: ClientConfig,
        key: StreamKey,
        payload_type: u8,
        reorder_limits: ReorderLimits,
        metadata_limits: OnvifMetadataLimits,
    ) -> Result<Self, MetadataClientError> {
        if key.ingress == 0 || key.generation == 0 {
            return Err(MetadataClientError::StreamBinding);
        }
        let session = RtspClientSession::with_codec_and_payload_type(
            config,
            ClientCodec::OnvifMetadata,
            payload_type,
        )
        .map_err(MetadataClientError::Session)?;
        // Validate through the semantic owners. This temporary receiver admits
        // no packet; DESCRIBE must agree with this exact owner-selected payload.
        let _ = OnvifMetadataReceiver::new(key, payload_type, reorder_limits, metadata_limits)
            .map_err(MetadataClientError::Metadata)?;
        Ok(Self {
            session,
            intake: RtspWireIntake::new(),
            key,
            reorder_limits,
            metadata_limits,
            metadata: None,
            challenge: None,
            retry: None,
            pending_cseq: None,
            last_ns: 0,
            digest_enabled: false,
            input_ready: true,
            input_ended: false,
            draining: false,
            closed: false,
        })
    }

    /// Pin a credential realm/policy before the first request. Passwords and HA1
    /// values are never stored. SHA-256 remains the default; no legacy fallback.
    pub fn with_digest(
        config: ClientConfig,
        key: StreamKey,
        payload_type: u8,
        reorder_limits: ReorderLimits,
        metadata_limits: OnvifMetadataLimits,
        realm: &str,
        policy: DigestPolicy,
    ) -> Result<Self, MetadataClientError> {
        let mut client = Self::new(config, key, payload_type, reorder_limits, metadata_limits)?;
        client
            .session
            .enable_digest(realm, policy)
            .map_err(MetadataClientError::Authentication)?;
        client.digest_enabled = true;
        Ok(client)
    }

    /// Shared protocol state only, not frame, source-custody or camera health truth.
    pub fn state(&self) -> ClientState {
        self.session.state()
    }
    /// Exact accepted uncompressed ONVIF signaling; XML interpretation remains separate.
    pub fn media(&self) -> Option<&MetadataClientMedia> {
        self.session.metadata_media()
    }
    /// All retained TCP bytes, including any complete held challenge/retry frame.
    pub fn buffered_wire_bytes(&self) -> usize {
        self.intake.buffered_bytes()
            + self
                .challenge
                .as_ref()
                .map_or(0, |h| h.frame.expose_wire().len())
            + self
                .retry
                .as_ref()
                .map_or(0, |h| h.frame.expose_wire().len())
    }
    /// Retained incomplete document bytes, not the independent source-custody size.
    pub fn retained_document_bytes(&self) -> usize {
        self.metadata
            .as_ref()
            .map_or(0, OnvifMetadataReceiver::pending_document_bytes)
    }
    /// Original RTP bytes queued for ordered delivery, not a persistence receipt.
    pub fn queued_rtp_bytes(&self) -> usize {
        self.metadata
            .as_ref()
            .map_or(0, OnvifMetadataReceiver::queued_bytes)
    }

    /// Earliest useful owner wake. A held frame never busy-polls queued lookahead.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        if self.draining {
            return Some(self.last_ns);
        }
        let held = self.challenge.is_some() || self.retry.is_some();
        let intake = if held {
            self.intake.deadline_ns()
        } else {
            self.intake.next_wake_ns()
        };
        let mut wake = if self.buffered_wire_bytes() == 0 {
            self.session.next_wake_ns()
        } else {
            // Requests cannot be issued while a prior frame is unresolved.
            // Keepalive is advisory; do not busy-poll it in a blocked state.
            self.session.next_expiry_ns()
        };
        for at in [
            intake,
            self.metadata
                .as_ref()
                .and_then(OnvifMetadataReceiver::next_wake_ns),
            self.challenge.as_ref().map(|h| h.deadline_ns),
            self.retry.as_ref().map(|h| h.deadline_ns),
        ] {
            wake = earlier(wake, at);
        }
        if self.input_ended && !held {
            wake = earlier(wake, Some(self.last_ns));
        }
        wake.map(|at| at.max(self.last_ns))
    }

    /// Prepare a plain request. A Digest-enabled client cannot bypass its secret owner.
    /// Write the prepared request once or close; preparation is not a send receipt.
    pub fn request(
        &mut self,
        command: ClientCommand,
        now: u64,
    ) -> Result<ClientRequest, MetadataClientFailure> {
        self.admit_request(now)?;
        match self.session.request(command, now) {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(request)
            }
            Err(error) => Err(self.request_failure(MetadataClientError::Session(error))),
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
    ) -> Result<ClientRequest, MetadataClientFailure> {
        self.admit_request(now)?;
        match self
            .session
            .request_digest(command, credentials, cnonce, now)
        {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(request)
            }
            Err(error) => Err(self.request_failure(MetadataClientError::Authentication(error))),
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
    ) -> Result<MetadataChallengeResponse, MetadataClientFailure> {
        self.admit_operation(now)?;
        let held = self
            .challenge
            .take()
            .ok_or_else(|| safe(MetadataClientError::NoChallenge))?;
        match self
            .session
            .retry_digest_response(held.frame.expose_wire(), credentials, cnonce, now)
        {
            Ok(request) => {
                self.pending_cseq = Some(request.cseq());
                Ok(MetadataChallengeResponse {
                    request,
                    source: held.frame,
                })
            }
            Err(error) => {
                self.challenge = Some(held);
                Err(self.fatal(MetadataClientError::Authentication(error)))
            }
        }
    }

    /// Admit one bounded TCP chunk. Backpressure and input-limit refusals consume
    /// no bytes. On fatal failure the retirement owns previously accepted wire;
    /// the new, refused chunk still belongs to the caller.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<(), MetadataClientFailure> {
        self.check_time(now).map_err(safe)?;
        if self.closed || self.input_ended {
            return Err(safe(MetadataClientError::Closed));
        }
        if !self.input_ready || self.challenge.is_some() || self.retry.is_some() {
            return Err(safe(MetadataClientError::Backpressure));
        }
        if bytes.len() > MAX_WIRE_CHUNK
            || bytes.len() > MAX_WIRE_BUFFER.saturating_sub(self.intake.buffered_bytes())
        {
            return Err(safe(MetadataClientError::InputLimit));
        }
        self.admit_operation(now)?;
        match self.intake.ingest(bytes, now) {
            Ok(()) => {
                self.input_ready = false;
                Ok(())
            }
            Err(
                error @ (WireIntakeError::Backpressure
                | WireIntakeError::Limit
                | WireIntakeError::Allocation),
            ) => Err(safe(MetadataClientError::Wire(error))),
            Err(error) => Err(self.fatal(MetadataClientError::Wire(error))),
        }
    }

    /// One bounded progress step. Deadlines run before queued output, and document
    /// expiry cannot consume the next original datagram. Poll even without traffic.
    pub fn poll(&mut self, now: u64) -> Result<MetadataClientPoll, MetadataClientError> {
        self.check_time(now)?;
        self.last_ns = now;
        if self.closed {
            return Ok(MetadataClientPoll::Ended {
                media: None,
                retirement: None,
            });
        }
        if !self.draining
            && let Some(error) = self.deadline_error(now)
        {
            return Ok(self.fault(error, None));
        }
        if let Some(metadata) = &mut self.metadata {
            match metadata.poll(now) {
                Ok(OnvifMetadataReceivePoll::Pending { .. }) => {}
                Ok(event @ OnvifMetadataReceivePoll::Ended { .. }) => {
                    let retirement = Some(Box::new(self.cancel()));
                    return Ok(MetadataClientPoll::Ended {
                        media: Some(event),
                        retirement,
                    });
                }
                Ok(event) => return Ok(MetadataClientPoll::Metadata(event)),
                Err(error) => return Ok(self.fault(MetadataClientError::Metadata(error), None)),
            }
        }
        if self.draining {
            let retirement = Some(Box::new(self.cancel()));
            return Ok(MetadataClientPoll::Ended {
                media: None,
                retirement,
            });
        }
        if self.challenge.is_some() {
            if self.input_ended {
                return Ok(self.fault(MetadataClientError::AuthenticationAtEof, None));
            }
            let Some(cseq) = self.pending_cseq else {
                return Ok(self.fault(MetadataClientError::NoChallenge, None));
            };
            return Ok(MetadataClientPoll::AuthenticationRequired {
                cseq,
                wake_at_ns: self.next_wake_ns(),
            });
        }
        if let Some(held) = self.retry.take() {
            return Ok(self.frame(held, now));
        }
        // Capture the ORIGINAL oldest-byte deadline before intake transfers the
        // frame. Holding a challenge or a full-queue retry never resets its age.
        let deadline = self.intake.deadline_ns();
        match self.intake.poll(now) {
            Ok(Some(frame)) => {
                let Some(deadline_ns) = deadline else {
                    return Ok(self.fault(
                        MetadataClientError::Wire(WireIntakeError::Framing),
                        Some(frame),
                    ));
                };
                return Ok(self.frame(HeldFrame { frame, deadline_ns }, now));
            }
            Ok(None) => self.input_ready = true,
            Err(error) => return Ok(self.fault(MetadataClientError::Wire(error), None)),
        }
        if self.intake.is_ended() {
            self.draining = true;
            if let Some(metadata) = &mut self.metadata {
                metadata.finish();
                return Ok(MetadataClientPoll::Pending {
                    wake_at_ns: Some(now),
                });
            }
            let retirement = Some(Box::new(self.cancel()));
            return Ok(MetadataClientPoll::Ended {
                media: None,
                retirement,
            });
        }
        if self.buffered_wire_bytes() == 0
            && self
                .session
                .tick(now)
                .map_err(MetadataClientError::Session)?
                == ClientProgress::KeepAliveDue
        {
            return Ok(MetadataClientPoll::KeepAliveDue);
        }
        Ok(MetadataClientPoll::Pending {
            wake_at_ns: self.next_wake_ns(),
        })
    }

    fn frame(&mut self, held: HeldFrame, now: u64) -> MetadataClientPoll {
        match held.frame.event() {
            RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. } => {
                if matches!(response.status_code, 401 | 407) && self.digest_enabled {
                    let matching = self.pending_cseq.is_some()
                        && response
                            .headers
                            .cseq()
                            .is_some_and(|c| c.ok() == self.pending_cseq);
                    let supported = response.status_code == 401
                        && super::client::authenticated::offers_digest(held.frame.expose_wire());
                    self.challenge = Some(held);
                    if !matching {
                        return self.fault(
                            MetadataClientError::Session(ClientError::CseqMismatch),
                            None,
                        );
                    }
                    if !supported {
                        return self.fault(
                            MetadataClientError::Authentication(DigestClientError::Authentication(
                                AuthenticationError::Unsupported,
                            )),
                            None,
                        );
                    }
                    if self.input_ended {
                        return self.fault(MetadataClientError::AuthenticationAtEof, None);
                    }
                    let Some(cseq) = self.pending_cseq else {
                        return self.fault(MetadataClientError::NoChallenge, None);
                    };
                    return MetadataClientPoll::AuthenticationRequired {
                        cseq,
                        wake_at_ns: self.next_wake_ns(),
                    };
                }
                match self.session.accept(response, now) {
                    Ok(progress) => {
                        if progress != ClientProgress::Interim {
                            self.pending_cseq = None;
                        }
                        if self.session.state() == ClientState::Ready
                            && self.metadata.is_none()
                            && let Err(error) = self.configure_metadata()
                        {
                            return self.fault(error, Some(held.frame));
                        }
                        if self.session.state() == ClientState::Closed {
                            // Input after a confirmed TEARDOWN is not admitted.
                            // Return its exact lookahead as part of terminal retirement.
                            self.input_ended = true;
                            self.draining = true;
                            self.intake.finish();
                            if let Some(metadata) = &mut self.metadata {
                                metadata.finish();
                            }
                        }
                        MetadataClientPoll::Control {
                            progress,
                            source: held.frame,
                        }
                    }
                    Err(error) => self.fault(MetadataClientError::Session(error), Some(held.frame)),
                }
            }
            RtspEvent::Interleaved { channel, span } => {
                let channel = match self.session.admit_channel(*channel, now) {
                    Ok(channel) => channel,
                    Err(error) => {
                        return self.fault(MetadataClientError::Session(error), Some(held.frame));
                    }
                };
                if channel == ClientChannel::Rtcp {
                    let reduced = self
                        .session
                        .metadata_media()
                        .is_some_and(|m| m.reduced_rtcp());
                    let mode = if reduced {
                        RtcpMode::ReducedSize
                    } else {
                        RtcpMode::Compound
                    };
                    let validation = RtcpCompound::parse(span, self.reorder_limits.packet, mode)
                        .map(|compound| compound.packet_count());
                    return MetadataClientPoll::Rtcp {
                        source: held.frame,
                        validation,
                    };
                }
                let result = match &mut self.metadata {
                    Some(metadata) => {
                        metadata.ingest_received(self.key, span, held.frame.received_ns(), now)
                    }
                    None => {
                        return self.fault(MetadataClientError::StreamBinding, Some(held.frame));
                    }
                };
                match result {
                    Ok(admission) => {
                        let restart =
                            admission.transport.disposition == ReorderDisposition::RestartRequired;
                        let retirement = if restart {
                            Some(Box::new(self.cancel()))
                        } else {
                            None
                        };
                        MetadataClientPoll::Rtp {
                            source: held.frame,
                            admission,
                            retirement,
                        }
                    }
                    Err(OnvifMetadataReceiveError::Transport(
                        ReorderError::PacketCapacity | ReorderError::ByteCapacity,
                    )) => {
                        if span.len() > self.reorder_limits.max_bytes {
                            return self.fault(MetadataClientError::InputLimit, Some(held.frame));
                        }
                        self.retry = Some(held);
                        MetadataClientPoll::Backpressure {
                            wake_at_ns: self.next_wake_ns(),
                        }
                    }
                    Err(error) => {
                        self.fault(MetadataClientError::Metadata(error), Some(held.frame))
                    }
                }
            }
            RtspEvent::Request(_) => {
                self.fault(MetadataClientError::ServerRequest, Some(held.frame))
            }
        }
    }

    fn configure_metadata(&mut self) -> Result<(), MetadataClientError> {
        if self
            .session
            .server_ssrc()
            .is_some_and(|ssrc| ssrc != self.key.ssrc)
        {
            return Err(MetadataClientError::StreamBinding);
        }
        let media = self
            .session
            .metadata_media()
            .ok_or(MetadataClientError::StreamBinding)?;
        self.metadata = Some(
            OnvifMetadataReceiver::new(
                self.key,
                media.payload_type(),
                self.reorder_limits,
                self.metadata_limits,
            )
            .map_err(MetadataClientError::Metadata)?,
        );
        Ok(())
    }

    /// Mark EOF. Complete frames drain before document EOF; truncated wire becomes
    /// a fault with original retained bytes, never successful media finalization.
    pub fn finish(&mut self) {
        self.input_ended = true;
        self.intake.finish();
    }

    /// Stop every local layer and transfer exact unprocessed wire ownership.
    /// No automatic TEARDOWN is sent and no source-custody data is deleted.
    pub fn cancel(&mut self) -> MetadataClientRetirement {
        self.closed = true;
        self.input_ready = false;
        self.pending_cseq = None;
        MetadataClientRetirement {
            session: self.session.cancel(),
            metadata: self.metadata.take().map(|mut metadata| metadata.cancel()),
            wire: self.intake.cancel(),
            challenge: self.challenge.take().map(|h| h.frame),
            retry: self.retry.take().map(|h| h.frame),
        }
    }

    fn check_time(&self, now: u64) -> Result<(), MetadataClientError> {
        if now < self.last_ns {
            Err(MetadataClientError::Session(ClientError::ClockReversed))
        } else {
            Ok(())
        }
    }
    fn deadline_error(&mut self, now: u64) -> Option<MetadataClientError> {
        if let Err(error) = self.session.tick(now) {
            return Some(MetadataClientError::Session(error));
        }
        let expired = [
            self.intake.deadline_ns(),
            self.challenge.as_ref().map(|h| h.deadline_ns),
            self.retry.as_ref().map(|h| h.deadline_ns),
        ]
        .into_iter()
        .flatten()
        .any(|at| now >= at);
        expired.then_some(MetadataClientError::Wire(WireIntakeError::Deadline))
    }
    fn admit_operation(&mut self, now: u64) -> Result<(), MetadataClientFailure> {
        self.check_time(now).map_err(safe)?;
        if self.closed || self.input_ended {
            return Err(safe(MetadataClientError::Closed));
        }
        self.last_ns = now;
        if let Some(error) = self.deadline_error(now) {
            return Err(self.fatal(error));
        }
        Ok(())
    }
    fn admit_request(&mut self, now: u64) -> Result<(), MetadataClientFailure> {
        self.admit_operation(now)?;
        if self.buffered_wire_bytes() != 0 {
            return Err(safe(MetadataClientError::Backpressure));
        }
        Ok(())
    }
    fn request_failure(&mut self, reason: MetadataClientError) -> MetadataClientFailure {
        if self.session.state() == ClientState::Failed {
            self.fatal(reason)
        } else {
            safe(reason)
        }
    }
    fn fatal(&mut self, reason: MetadataClientError) -> MetadataClientFailure {
        MetadataClientFailure {
            reason,
            retirement: Some(Box::new(self.cancel())),
        }
    }
    fn fault(
        &mut self,
        reason: MetadataClientError,
        source: Option<RtspWireFrame>,
    ) -> MetadataClientPoll {
        MetadataClientPoll::Fault {
            reason,
            retirement: Box::new(self.cancel()),
            source,
        }
    }
}

fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn safe(reason: MetadataClientError) -> MetadataClientFailure {
    MetadataClientFailure {
        reason,
        retirement: None,
    }
}
