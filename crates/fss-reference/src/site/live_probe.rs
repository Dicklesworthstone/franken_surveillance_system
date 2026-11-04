#![forbid(unsafe_code)]
//! One approved native RTSP connection producing a bounded site observation receipt.
//!
//! This owner composes the existing scoped client, exact-message intake, native TCP link and
//! RTP observer. It owns no clock, sleep, entropy, credential store, retry, recording or decoder.
//! The caller supplies current authority and monotonic time on every step. Source/control bytes
//! are deliberately omitted and accounted for, including on failure; no raw wire leaves this
//! module. A completed sample is released only after the matching TEARDOWN acknowledgement.
//! Neither that acknowledgement nor a Digest exchange authenticates scene liveness or grants
//! recording authority. RTCP is explicitly excluded from observations and timing claims.

use std::fmt;

use fss_core::ContentDigest;
use fss_packet::{PacketLimits, RtpPacket};

use super::probe_observation::{
    MAX_PROBE_PICTURES, NegotiatedProbe, ObservationError, RtspProbeObserver,
};
use super::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};
use crate::rtsp::authentication::{DigestCredentials, DigestPolicy};
use crate::rtsp::client::authenticated::DigestClientError;
use crate::rtsp::client::{
    ClientChannel, ClientCloseReceipt, ClientCodec, ClientCommand, ClientConfig, ClientError,
    ClientProgress, ClientRequest, ClientState, RtspClientSession,
};
use crate::rtsp::framed::{RtspWireFrame, RtspWireIntake, WireIntakeError};
use crate::rtsp::tcp::{
    RtspTcpLink, SocketReadiness, SsrcPolicy, TcpAuthority, TcpBinding, TcpError, TcpLimits,
    TcpReadStep, TcpTotals, TcpWriteStep,
};
use crate::rtsp::{RtspEvent, RtspResponse};

/// Maximum connection-wide driver admissions, including calls without socket readiness.
pub const MAX_PROBE_STEPS: u64 = 65_536;
/// Maximum approved lifetime of a single probe connection, including negotiation and close.
pub const MAX_PROBE_DURATION_NS: u64 = 60_000_000_000;
/// Hard ceiling over all received bytes, including authentication, SDP and excluded RTCP.
pub const MAX_PROBE_WIRE_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling over all sent requests, including bounded authentication retries.
pub const MAX_PROBE_SENT_BYTES: u64 = 256 * 1024;

/// Optional exact Digest policy; raw credentials are borrowed only when a request needs them.
pub struct ProbeDigestConfig {
    /// Expected realm, equal to the manifest credential reference's realm.
    pub realm: String,
    /// Exact algorithm/downgrade policy, equal to the manifest declaration.
    pub policy: DigestPolicy,
}

impl fmt::Debug for ProbeDigestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeDigestConfig")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Immutable scope and independent limits for one native observation. No field grants authority.
pub struct LiveSiteProbeConfig {
    /// Source ordinal in the complete pinned manifest.
    pub source_index: usize,
    /// Exact manifest route and explicitly selected media/channel pair.
    pub protocol: ClientConfig,
    /// Caller-approved literal peer, ingress/generation and optional pinned SSRC.
    pub binding: TcpBinding,
    /// Bounded byte, syscall and connect allowances; never replenished by protocol progress.
    pub transport: TcpLimits,
    /// AVC, HEVC or RFC 2435 JPEG through the existing native media owners.
    pub codec: ProbeCodec,
    /// Optional exact payload selection (26 for JPEG or 96..=127); ambiguity is refused.
    pub payload_type: Option<u8>,
    /// Absolute owner-clock deadline, at most sixty seconds beyond construction.
    pub deadline_ns: u64,
    /// Driver-step ceiling, at most [`MAX_PROBE_STEPS`].
    pub max_steps: u64,
    /// Minimum native syntax-grouped pictures to observe, from three through sixty-four.
    /// Each RTP datagram is processed atomically and can confirm more than one group.
    pub stop_after_pictures: u32,
    /// Optional existing manifest-bound credential policy.
    pub digest: Option<ProbeDigestConfig>,
}

impl fmt::Debug for LiveSiteProbeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveSiteProbeConfig")
            .field("source_index", &self.source_index)
            .field("codec", &self.codec)
            .field("payload_type", &self.payload_type)
            .field("deadline_ns", &self.deadline_ns)
            .field("max_steps", &self.max_steps)
            .field("stop_after_pictures", &self.stop_after_pictures)
            .finish_non_exhaustive()
    }
}

/// Explicit non-retention and exclusion accounting, never a source-custody certificate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProbeAccounting {
    /// Selected RTP packets accepted by the strict observation owner.
    pub rtp_packets: u64,
    /// Whole accepted RTP datagram bytes, including headers.
    pub rtp_bytes: u64,
    /// Complete reconstructed NAL bytes excluded at the explicit sample cut.
    /// These derivative bytes are not additional original-wire omissions or frame counts.
    pub unverified_nal_bytes_excluded: u64,
    /// Unfinished reconstructed fragment bytes excluded at the explicit sample cut.
    pub unfinished_fragment_bytes_excluded: u64,
    /// Interleaved RTCP-channel frames deliberately excluded, without claiming packet validity.
    pub rtcp_frames_excluded: u64,
    /// Omitted RTCP-channel bytes; no sender-report time is inferred from them.
    pub rtcp_bytes_excluded: u64,
    /// Negotiated-channel frames excluded after the sample while awaiting remote close.
    pub closing_frames_excluded: u64,
    /// Omitted payload bytes of those in-flight closing frames.
    pub closing_bytes_excluded: u64,
    /// Fully parsed control responses, including interim and authentication responses.
    pub control_responses: u64,
    /// All actually received wire bytes deliberately not retained, including unread suffixes.
    pub discarded_wire_bytes: u64,
}

/// Payload-free refusal states. Nested error types contain classifications and bounded counts only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// Scope, selected codec, manifest authentication policy or limits are inconsistent.
    Configuration,
    /// Native network authority, route, deadline or transport resource allowance refused.
    Transport(TcpError),
    /// Existing client lifecycle, negotiation, correlation or deadline refused.
    Session(ClientError),
    /// Existing bounded Digest owner refused the exact original challenge or request.
    Authentication(DigestClientError),
    /// Exact-message framing or parser refused the incoming bytes.
    Wire(WireIntakeError),
    /// The strict source/cadence observer refused the sample.
    Observation(ObservationError),
    /// Caller must provide an ephemeral credential borrow before the pending request can progress.
    CredentialsRequired,
    /// A response arrived without a completely sent matching request.
    UnexpectedResponse,
    /// A request, unknown channel or pre-PLAY media arrived where no such input is admitted.
    UnexpectedInput,
    /// The peer closed before both a complete sample and acknowledged TEARDOWN.
    Incomplete,
    /// Owner time moved backwards; no new network effect was attempted.
    ClockReversed,
    /// The independent driver-step allowance was exhausted.
    WorkBudget,
    /// The connection is already retired. It cannot issue another receipt or reconnect in place.
    Closed,
}

impl ProbeError {
    /// Stable payload-free diagnostic identity.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "ERR-SITE-PROBE-CONFIGURATION-001",
            Self::Transport(_) => "ERR-SITE-PROBE-TRANSPORT-001",
            Self::Session(_) => "ERR-SITE-PROBE-SESSION-001",
            Self::Authentication(_) | Self::CredentialsRequired => "ERR-SITE-PROBE-AUTH-001",
            Self::Wire(_) => "ERR-SITE-PROBE-WIRE-001",
            Self::Observation(error) => error.code(),
            Self::UnexpectedResponse => "ERR-SITE-PROBE-RESPONSE-001",
            Self::UnexpectedInput => "ERR-SITE-PROBE-INPUT-001",
            Self::Incomplete => "ERR-SITE-PROBE-INCOMPLETE-001",
            Self::ClockReversed => "ERR-SITE-PROBE-CLOCK-001",
            Self::WorkBudget => "ERR-SITE-PROBE-LIMIT-001",
            Self::Closed => "ERR-SITE-PROBE-CLOSED-001",
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ProbeError {}

/// Construction refusal distinguishes pure preflight from a real connection attempt.
#[derive(Debug)]
pub struct ProbeConnectFailure {
    /// Payload-free refusal.
    pub reason: ProbeError,
    /// A native connect was attempted; no RTSP requests were sent by construction.
    pub connection_attempted: bool,
}

impl fmt::Display for ProbeConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for ProbeConnectFailure {}

/// Terminal local resource ownership and explicit remote uncertainty, with no private raw data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ProbeRetirement {
    /// Actual native transport byte/call counts.
    pub totals: TcpTotals,
    /// Existing RTSP remote-session uncertainty and unsettled correlation.
    pub close: ClientCloseReceipt,
    /// Source omission and channel exclusion account.
    pub accounting: ProbeAccounting,
    /// Prefix already sent from the currently incomplete request, if one exists.
    pub request_sent_bytes: usize,
    /// Remaining unsent bytes, including a prepared request refused before queue admission.
    pub unsent_request_bytes: usize,
    /// True only after accepting the matching successful TEARDOWN response.
    pub teardown_acknowledged: bool,
}

/// Fatal errors retire the sole socket once; recoverable missing credentials return no retirement.
#[derive(Debug)]
pub struct ProbeFailure {
    /// Payload-free refusal.
    pub reason: ProbeError,
    /// Present exactly once when this call retired the live connection.
    pub retirement: Option<Box<ProbeRetirement>>,
}

impl fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for ProbeFailure {}

/// One bounded owner step. No variant contains raw SDP, credentials, session tokens or media.
#[derive(Debug)]
#[must_use]
pub enum ProbeStep {
    /// Local work or one bounded native read/write progressed; re-check credential needs.
    Progress,
    /// Wait for readiness or the exact earliest protocol/transport deadline.
    Pending {
        /// One read may be attempted when the caller observes readiness.
        readable: bool,
        /// An already prepared request has an unsent suffix.
        writable: bool,
        /// Earliest absolute owner-clock wake.
        wake_at_ns: Option<u64>,
    },
    /// One frozen, witnessed-picture prefix released after acknowledged TEARDOWN and local closure.
    Complete {
        /// Existing manifest-bound observation schema, with no liveness/freshness grant.
        receipt: SiteProbeReceipt,
        /// Native transport work for this exact connection.
        totals: TcpTotals,
        /// Matching remote close acknowledgement; both fields are terminal and settled.
        close: ClientCloseReceipt,
        /// Explicit source non-retention and excluded input.
        accounting: ProbeAccounting,
    },
}

#[derive(Clone, Copy)]
struct Outstanding {
    command: ClientCommand,
    cseq: u32,
    sent_ns: Option<u64>,
}

/// Sole owner of one native probe. Dropping/cancelling closes local resources without hidden I/O.
#[must_use]
pub struct LiveSiteProbe<'a> {
    manifest: &'a SiteManifest,
    source_index: usize,
    media_index: usize,
    codec: ProbeCodec,
    digest_enabled: bool,
    protocol: RtspClientSession,
    transport: Option<RtspTcpLink>,
    intake: RtspWireIntake,
    observer: Option<RtspProbeObserver<'a>>,
    challenge: Option<RtspWireFrame>,
    next_request: Option<ClientCommand>,
    outstanding: Option<Outstanding>,
    pinned_ssrc: Option<u32>,
    deadline_ns: u64,
    max_steps: u64,
    steps: u64,
    last_ns: u64,
    target_pictures: u32,
    observed_pictures: u32,
    sample_complete: bool,
    teardown_acknowledged: bool,
    unqueued_request_bytes: usize,
    accounting: ProbeAccounting,
}

impl fmt::Debug for LiveSiteProbe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveSiteProbe")
            .field("source_index", &self.source_index)
            .field("state", &self.protocol.state())
            .field("steps", &self.steps)
            .field("observed_pictures", &self.observed_pictures)
            .field("sample_complete", &self.sample_complete)
            .field("retired", &self.transport.is_none())
            .finish()
    }
}

impl<'a> LiveSiteProbe<'a> {
    /// Validate the complete immutable scope, then attempt exactly one authorized connection.
    /// This sends no RTSP bytes and borrows no credentials. Invalid configuration performs no I/O.
    pub fn connect(
        manifest: &'a SiteManifest,
        config: LiveSiteProbeConfig,
        now_ns: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, ProbeConnectFailure> {
        let fail = |reason| ProbeConnectFailure {
            reason,
            connection_attempted: false,
        };
        validate_config(manifest, &config, now_ns).map_err(fail)?;
        let codec = match config.codec {
            ProbeCodec::Avc => ClientCodec::H264,
            ProbeCodec::Hevc => ClientCodec::H265,
            ProbeCodec::Jpeg => ClientCodec::Jpeg,
        };
        let media_index = config.protocol.media_index;
        let mut protocol = match config.payload_type {
            Some(payload) => {
                RtspClientSession::with_codec_and_payload_type(config.protocol, codec, payload)
            }
            None => RtspClientSession::with_codec(config.protocol, codec),
        }
        .map_err(|error| fail(ProbeError::Session(error)))?;
        let digest_enabled = config.digest.is_some();
        if let Some(digest) = config.digest {
            protocol
                .enable_digest(&digest.realm, digest.policy)
                .map_err(|error| fail(ProbeError::Authentication(error)))?;
        }
        let pinned_ssrc = (config.binding.ssrc_policy() == SsrcPolicy::Pinned)
            .then_some(config.binding.key().ssrc);
        let transport = RtspTcpLink::connect(
            config.binding,
            config.transport,
            now_ns,
            config.deadline_ns,
            authority,
        )
        .map_err(|error| ProbeConnectFailure {
            reason: ProbeError::Transport(error.reason),
            connection_attempted: error.connection_attempted,
        })?;
        Ok(Self {
            manifest,
            source_index: config.source_index,
            media_index,
            codec: config.codec,
            digest_enabled,
            protocol,
            transport: Some(transport),
            intake: RtspWireIntake::new(),
            observer: None,
            challenge: None,
            next_request: Some(ClientCommand::Options),
            outstanding: None,
            pinned_ssrc,
            deadline_ns: config.deadline_ns,
            max_steps: config.max_steps,
            steps: 0,
            last_ns: now_ns,
            target_pictures: config.stop_after_pictures,
            observed_pictures: 0,
            sample_complete: false,
            teardown_acknowledged: false,
            unqueued_request_bytes: 0,
            accounting: ProbeAccounting::default(),
        })
    }

    /// Whether the next step needs a newly authorized credential borrow and fresh cnonce entropy.
    /// Ordinary socket polling, RTP observations and waiting never require either resource.
    pub fn needs_credentials(&self) -> bool {
        self.transport.is_some()
            && self.digest_enabled
            && (self.next_request.is_some() || self.challenge.is_some())
    }

    /// Advance one bounded local operation or native read/write. The caller owns all waits/time.
    /// Credentials are borrowed solely for a pending request/challenge and never stored here.
    pub fn step(
        &mut self,
        readiness: SocketReadiness,
        now_ns: u64,
        credentials: Option<&DigestCredentials<'_>>,
        cnonce: [u8; 16],
        authority: &dyn TcpAuthority,
    ) -> Result<ProbeStep, ProbeFailure> {
        if self.transport.is_none() {
            return Err(ProbeFailure {
                reason: ProbeError::Closed,
                retirement: None,
            });
        }
        if now_ns < self.last_ns {
            return Err(self.fail(ProbeError::ClockReversed));
        }
        if self.steps == self.max_steps {
            return Err(self.fail(ProbeError::WorkBudget));
        }
        self.last_ns = now_ns;
        self.steps += 1;
        let result = self.advance(readiness, now_ns, credentials, cnonce, authority);
        match result {
            Err(ProbeError::CredentialsRequired) => Err(ProbeFailure {
                reason: ProbeError::CredentialsRequired,
                retirement: None,
            }),
            Err(error) => Err(self.fail(error)),
            Ok(step) => Ok(step),
        }
    }

    fn advance(
        &mut self,
        readiness: SocketReadiness,
        now: u64,
        credentials: Option<&DigestCredentials<'_>>,
        cnonce: [u8; 16],
        authority: &dyn TcpAuthority,
    ) -> Result<ProbeStep, ProbeError> {
        self.transport_mut()?
            .check(now, authority)
            .map_err(ProbeError::Transport)?;
        let clock_progress = self.protocol.tick(now).map_err(ProbeError::Session)?;

        if let Some(frame) = self.challenge.as_ref() {
            let credentials = credentials.ok_or(ProbeError::CredentialsRequired)?;
            let request = self
                .protocol
                .retry_digest_response(frame.expose_wire(), credentials, cnonce, now)
                .map_err(ProbeError::Authentication)?;
            self.challenge = None;
            self.queue(request, now, authority)?;
            return Ok(ProbeStep::Progress);
        }
        if let Some(command) = self.next_request {
            let request = if self.digest_enabled {
                self.protocol
                    .request_digest(
                        command,
                        credentials.ok_or(ProbeError::CredentialsRequired)?,
                        cnonce,
                        now,
                    )
                    .map_err(ProbeError::Authentication)?
            } else {
                self.protocol
                    .request(command, now)
                    .map_err(ProbeError::Session)?
            };
            self.next_request = None;
            self.queue(request, now, authority)?;
            return Ok(ProbeStep::Progress);
        }

        if self.transport_mut()?.has_pending_request() {
            if readiness.writable {
                let progress = self
                    .transport_mut()?
                    .write_step(now, authority)
                    .map_err(ProbeError::Transport)?;
                match progress {
                    TcpWriteStep::Sent { cseq, .. } => {
                        let pending = self
                            .outstanding
                            .as_mut()
                            .filter(|pending| pending.cseq == cseq)
                            .ok_or(ProbeError::UnexpectedResponse)?;
                        pending.sent_ns = Some(now);
                        return Ok(ProbeStep::Progress);
                    }
                    TcpWriteStep::Advanced { .. } => return Ok(ProbeStep::Progress),
                    TcpWriteStep::Idle | TcpWriteStep::Pending => {}
                }
            }
            return Ok(self.pending(false, true));
        }

        if let Some(frame) = self.intake.poll(now).map_err(ProbeError::Wire)? {
            return self.frame(frame, now);
        }
        if clock_progress == ClientProgress::KeepAliveDue && self.outstanding.is_none() {
            self.next_request = Some(if self.sample_complete {
                ClientCommand::Teardown
            } else {
                ClientCommand::KeepAlive
            });
            return Ok(ProbeStep::Progress);
        }
        if readiness.readable {
            match self
                .transport_mut()?
                .read_step(now, authority)
                .map_err(ProbeError::Transport)?
            {
                TcpReadStep::Buffered => {
                    let link = self.transport.as_ref().ok_or(ProbeError::Closed)?;
                    let chunk = link.pending_read().ok_or(ProbeError::Incomplete)?;
                    self.intake
                        .ingest(chunk.expose(), chunk.admitted_ns())
                        .map_err(ProbeError::Wire)?;
                    // The probe explicitly omits these originals after the intake accepts them.
                    // Retirement accounts for all received bytes, including fatal read suffixes.
                    drop(self.transport_mut()?.acknowledge_read());
                    return Ok(ProbeStep::Progress);
                }
                TcpReadStep::Eof => {
                    self.intake.finish();
                    // The intake was drained immediately before this zero-byte read. A partial
                    // frame must retain its framing refusal; clean EOF is still not TEARDOWN.
                    self.intake.poll(now).map_err(ProbeError::Wire)?;
                    return Err(ProbeError::Incomplete);
                }
                TcpReadStep::Pending => {}
            }
        }
        Ok(self.pending(true, false))
    }

    fn queue(
        &mut self,
        request: ClientRequest,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), ProbeError> {
        let outstanding = Outstanding {
            command: request.command(),
            cseq: request.cseq(),
            sent_ns: None,
        };
        match self.transport_mut()?.queue_request(request, now, authority) {
            Ok(()) => {
                self.outstanding = Some(outstanding);
                Ok(())
            }
            Err(refusal) => {
                self.unqueued_request_bytes = refusal.request.bytes().len();
                Err(ProbeError::Transport(refusal.reason))
            }
        }
    }

    fn frame(&mut self, frame: RtspWireFrame, now: u64) -> Result<ProbeStep, ProbeError> {
        match frame.event() {
            RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. } => {
                self.accounting.control_responses += 1;
                let pending = self.outstanding.ok_or(ProbeError::UnexpectedResponse)?;
                if pending
                    .sent_ns
                    .is_none_or(|sent| frame.received_ns() < sent)
                {
                    return Err(ProbeError::UnexpectedResponse);
                }
                if response.status_code == 401 && self.digest_enabled {
                    // The challenge remains private, bounded and subject to the original
                    // pending request deadline. Credential access occurs on the next step.
                    self.challenge = Some(frame);
                    return Ok(ProbeStep::Progress);
                }
                match self
                    .protocol
                    .accept(response, now)
                    .map_err(ProbeError::Session)?
                {
                    ClientProgress::Interim => return Ok(ProbeStep::Progress),
                    ClientProgress::Accepted(_) => {}
                    _ => return Err(ProbeError::UnexpectedResponse),
                }
                self.outstanding = None;
                match pending.command {
                    ClientCommand::Options => self.next_request = Some(ClientCommand::Describe),
                    ClientCommand::Describe => {
                        self.observer = Some(self.begin_observation(response)?);
                        self.next_request = Some(ClientCommand::Setup);
                    }
                    ClientCommand::Setup => {
                        if self.pinned_ssrc.is_some()
                            && self.protocol.server_ssrc().is_some()
                            && self.pinned_ssrc != self.protocol.server_ssrc()
                        {
                            return Err(ProbeError::Observation(ObservationError::Continuity));
                        }
                        self.next_request = Some(ClientCommand::Play);
                    }
                    ClientCommand::Play => {}
                    ClientCommand::KeepAlive | ClientCommand::KeepAliveGetParameter => {
                        if self.sample_complete {
                            self.next_request = Some(ClientCommand::Teardown);
                        }
                    }
                    ClientCommand::Teardown => return self.complete(),
                }
            }
            RtspEvent::Interleaved { channel, span } => self.media(*channel, span, now)?,
            RtspEvent::Request(_) => return Err(ProbeError::UnexpectedInput),
        }
        Ok(ProbeStep::Progress)
    }

    fn begin_observation(
        &self,
        response: &RtspResponse,
    ) -> Result<RtspProbeObserver<'a>, ProbeError> {
        let server_headers: Vec<_> = response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("Server"))
            .collect();
        let server_identity = match server_headers.as_slice() {
            [] => "rtsp-server:unreported".to_owned(),
            [header] => format!(
                "server-header:{}",
                ContentDigest::sha256(header.value.as_bytes()).to_text()
            ),
            _ => return Err(ProbeError::Session(ClientError::Response)),
        };
        let (payload_type, parameter_sets) = match self.codec {
            ProbeCodec::Avc => {
                let media = self.protocol.media().ok_or(ProbeError::Configuration)?;
                let (sps, pps) = media.parameter_sets();
                (media.payload_type(), vec![sps, pps])
            }
            ProbeCodec::Hevc => {
                let media = self
                    .protocol
                    .hevc_media()
                    .ok_or(ProbeError::Configuration)?;
                let ([vps], [sps], [pps]) = (media.vps(), media.sps(), media.pps()) else {
                    return Err(ProbeError::Observation(ObservationError::Negotiation));
                };
                (
                    media.payload_type(),
                    vec![vps.as_slice(), sps.as_slice(), pps.as_slice()],
                )
            }
            ProbeCodec::Jpeg => {
                let media = self
                    .protocol
                    .jpeg_media()
                    .ok_or(ProbeError::Configuration)?;
                (media.payload_type(), Vec::new())
            }
        };
        RtspProbeObserver::new(
            self.manifest,
            self.source_index,
            NegotiatedProbe {
                sdp: &response.body,
                media_index: self.media_index,
                rtp_channel: self.protocol.channels().0,
                codec: self.codec,
                payload_type,
                parameter_sets: &parameter_sets,
                server_identity: &server_identity,
            },
        )
        .map_err(ProbeError::Observation)
    }

    fn media(&mut self, channel: u8, span: &[u8], now: u64) -> Result<(), ProbeError> {
        let channels = self.protocol.channels();
        if self.sample_complete {
            // Cameras can have in-flight media after accepting our TEARDOWN request. It is
            // excluded, never appended to the already complete sample or mistaken for an ACK.
            if channel != channels.0 && channel != channels.1 {
                return Err(ProbeError::UnexpectedInput);
            }
            self.accounting.closing_frames_excluded += 1;
            self.accounting.closing_bytes_excluded += span.len() as u64;
            return Ok(());
        }
        match self
            .protocol
            .admit_channel(channel, now)
            .map_err(ProbeError::Session)?
        {
            ClientChannel::Rtcp => {
                // Deliberately do not assert that these bytes are a valid RTCP compound,
                // authenticate the sender, or use them to narrow capture-time uncertainty.
                self.accounting.rtcp_frames_excluded += 1;
                self.accounting.rtcp_bytes_excluded += span.len() as u64;
            }
            ClientChannel::Rtp => {
                let packet = RtpPacket::parse(span, PacketLimits::default())
                    .map_err(|_| ProbeError::Observation(ObservationError::Packet))?;
                if self.pinned_ssrc.is_some_and(|ssrc| ssrc != packet.ssrc())
                    || self
                        .protocol
                        .server_ssrc()
                        .is_some_and(|ssrc| ssrc != packet.ssrc())
                {
                    return Err(ProbeError::Observation(ObservationError::Continuity));
                }
                let observer = self.observer.as_mut().ok_or(ProbeError::Incomplete)?;
                observer
                    .observe_rtp_at(channel, span, now)
                    .map_err(ProbeError::Observation)?;
                self.accounting.rtp_packets += 1;
                self.accounting.rtp_bytes += span.len() as u64;
                self.observed_pictures = observer.confirmed_pictures();
                if self.observed_pictures >= self.target_pictures {
                    // A native boundary can retain the start of the next group.
                    // Explicitly omit that unverified tail; never invent EOS or
                    // count the RTP marker as independent picture evidence.
                    let tail = observer.freeze_prefix().map_err(ProbeError::Observation)?;
                    self.accounting.unverified_nal_bytes_excluded =
                        tail.unverified_nal_bytes_excluded;
                    self.accounting.unfinished_fragment_bytes_excluded =
                        tail.unfinished_fragment_bytes_excluded;
                    self.sample_complete = true;
                    if self.outstanding.is_none() {
                        self.next_request = Some(ClientCommand::Teardown);
                    }
                }
            }
        }
        Ok(())
    }

    fn complete(&mut self) -> Result<ProbeStep, ProbeError> {
        if !self.sample_complete || self.protocol.state() != ClientState::Closed {
            return Err(ProbeError::Incomplete);
        }
        self.teardown_acknowledged = true;
        let receipt = self
            .observer
            .take()
            .ok_or(ProbeError::Incomplete)?
            .finish_prefix()
            .map_err(ProbeError::Observation)?;
        let retirement = self.cancel().ok_or(ProbeError::Closed)?;
        if retirement.close.remote_session_may_exist || retirement.close.pending_cseq.is_some() {
            return Err(ProbeError::Incomplete);
        }
        Ok(ProbeStep::Complete {
            receipt,
            totals: retirement.totals,
            close: retirement.close,
            accounting: retirement.accounting,
        })
    }

    fn pending(&self, readable: bool, writable: bool) -> ProbeStep {
        let wake_at_ns = [
            Some(self.deadline_ns),
            self.protocol.next_wake_ns(),
            self.intake.next_wake_ns(),
            self.transport
                .as_ref()
                .and_then(RtspTcpLink::next_deadline_ns),
        ]
        .into_iter()
        .flatten()
        .min();
        ProbeStep::Pending {
            readable,
            writable,
            wake_at_ns,
        }
    }

    fn transport_mut(&mut self) -> Result<&mut RtspTcpLink, ProbeError> {
        self.transport.as_mut().ok_or(ProbeError::Closed)
    }

    fn fail(&mut self, reason: ProbeError) -> ProbeFailure {
        ProbeFailure {
            reason,
            retirement: self.cancel().map(Box::new),
        }
    }

    /// Request immediate local closure and finalize byte omission/remote uncertainty once.
    /// No TEARDOWN is sent after cancellation or authority revocation. Remote uncertainty remains
    /// explicit, and calling this again cannot duplicate a terminal receipt or any network effect.
    pub fn cancel(&mut self) -> Option<ProbeRetirement> {
        let transport = self.transport.take()?.retire();
        let close = self.protocol.cancel();
        self.accounting.discarded_wire_bytes = transport.totals.received_bytes;
        let unsent_request_bytes = self.unqueued_request_bytes
            + transport.request.as_ref().map_or(0, |request| {
                request.bytes().len() - transport.request_sent_bytes
            });
        let result = ProbeRetirement {
            totals: transport.totals,
            close,
            accounting: self.accounting,
            request_sent_bytes: transport.request_sent_bytes,
            unsent_request_bytes,
            teardown_acknowledged: self.teardown_acknowledged,
        };
        self.next_request = None;
        self.outstanding = None;
        self.challenge = None;
        self.observer = None;
        // All unprocessed original control/media bytes follow the probe's explicit omission
        // policy. TcpRetirement itself must never leave this owner: it can carry credentials.
        drop(self.intake.cancel());
        drop(transport);
        Some(result)
    }
}

fn validate_config(
    manifest: &SiteManifest,
    config: &LiveSiteProbeConfig,
    now: u64,
) -> Result<(), ProbeError> {
    manifest.validate().map_err(|_| ProbeError::Configuration)?;
    let source = manifest
        .sources
        .get(config.source_index)
        .ok_or(ProbeError::Configuration)?;
    if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel)
        || !source.owner_authorized
        || !source.plaintext
        || config.binding.peer() != source.peer
        || config.binding.authority() != source.authority
        || config.binding.key().generation != source.generation
        || config.protocol.presentation_uri
            != format!(
                "rtsp://{}{}",
                source.authority,
                source
                    .presentation
                    .as_deref()
                    .ok_or(ProbeError::Configuration)?
            )
        || config.protocol.control_root_uri
            != format!(
                "rtsp://{}{}",
                source.authority,
                source
                    .control_root
                    .as_deref()
                    .ok_or(ProbeError::Configuration)?
            )
        || config.protocol.channels.0 % 2 != 0
        || config.payload_type.is_some_and(|value| {
            !(96..=127).contains(&value) && !(config.codec == ProbeCodec::Jpeg && value == 26)
        })
        || !(1..=MAX_PROBE_DURATION_NS).contains(&config.deadline_ns.saturating_sub(now))
        || !(1..=MAX_PROBE_STEPS).contains(&config.max_steps)
        || !(3..=MAX_PROBE_PICTURES).contains(&config.stop_after_pictures)
        || config.transport.max_received_bytes > MAX_PROBE_WIRE_BYTES
        || config.transport.max_sent_bytes > MAX_PROBE_SENT_BYTES
        || config.transport.max_io_calls > MAX_PROBE_STEPS
    {
        return Err(ProbeError::Configuration);
    }
    config.transport.validate().map_err(ProbeError::Transport)?;
    match (&source.authentication, &config.digest) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if expected.realm == actual.realm
                && expected.legacy_md5 == actual.policy.allow_legacy_md5
                && expected.legacy_no_qop == actual.policy.allow_legacy_no_qop => {}
        _ => return Err(ProbeError::Configuration),
    }
    Ok(())
}
