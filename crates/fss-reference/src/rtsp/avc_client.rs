#![forbid(unsafe_code)]
//! Bounded RTSP wire -> negotiated RTP/RTCP -> loss-aware AVC picture integration.

use std::fmt;
use fss_packet::{H264Mode, H264ReceiveError, PacketError, ReorderDisposition,
    ReorderError, RtcpCompound, RtcpMode, StreamKey};
use fss_packet::avc::{AvcError, AvcReceiveAdmission, AvcReceiveCancellation,
    AvcReceiveError, AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps, parse_sps};
use super::{RtspError, RtspEvent, RtspLimits, RtspParser};
use super::client::{ClientChannel, ClientCloseReceipt, ClientCommand, ClientConfig,
    ClientError, ClientProgress, ClientRequest, ClientState, RtspClientSession};

const MAX_CHUNK: usize = 4_096;
const MAX_BUFFER: usize = 135_168;
const PARTIAL_TIMEOUT: u64 = 5_000_000_000;

/// Payload-free connection/pump refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvcClientError {
    /// Session negotiation, authority, time, or expiry failed.
    Session(ClientError),
    /// Existing RTSP wire parser rejected a message or lost framing.
    Wire(RtspError),
    /// SDP parameter bytes failed the real AVC syntax owner.
    Syntax(AvcError),
    /// Ordered media admission or reconstruction failed.
    Video(AvcReceiveError),
    /// Drain pending events before providing more input; this chunk was not consumed.
    Backpressure,
    /// Chunk or total partial-frame byte ceiling exceeded before input consumption.
    InputLimit,
    /// Partial RTSP message or interleaved frame exceeded its fixed lifetime.
    PartialTimeout,
    /// EOF occurred inside an RTSP message or interleaved frame.
    Truncated,
    /// Owner binding is invalid or disagrees with the SETUP SSRC assertion.
    StreamBinding,
    /// Server-initiated requests have no admitted handling contract.
    ServerRequest,
    /// Admission is closed; reconnect needs a new connection and stream epoch.
    Closed,
}
impl fmt::Display for AvcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "RTSP AVC refusal: {self:?}") }
}
impl std::error::Error for AvcClientError {}

/// Exact interleaved payload and its channel. Debug never includes media bytes.
/// The owner separately retains the complete original TCP stream, including `$` framing.
pub struct InterleavedSource {
    channel: u8,
    received_ns: u64,
    payload: Vec<u8>,
}
impl InterleavedSource {
    /// Exact original RTP/RTCP datagram (without the RTSP four-byte envelope).
    pub fn payload(&self) -> &[u8] { &self.payload }
    /// Channel from the RTSP framing, not inferred from payload bytes.
    pub fn channel(&self) -> u8 { self.channel }
    /// Owner time when the parser completed this frame, not capture time.
    pub fn received_ns(&self) -> u64 { self.received_ns }
}
impl fmt::Debug for InterleavedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterleavedSource").field("channel", &self.channel)
            .field("received_ns", &self.received_ns).field("bytes", &self.payload.len()).finish()
    }
}

/// Local teardown accounting; remote session existence remains a separate question.
#[derive(Debug)]
pub struct AvcClientRetirement {
    /// Remote-session uncertainty and the outstanding CSeq, if any.
    pub session: ClientCloseReceipt,
    /// Every retained RTP/NAL/picture derivative retired, if the codec was configured.
    pub video: Option<AvcReceiveCancellation>,
    /// Parsed events retired before admission, including a backpressured RTP frame.
    pub pending_events: usize,
    /// Parsed media payload bytes retired before admission (control bodies not included).
    pub pending_media_bytes: usize,
    /// Remaining unparsed RTSP framing/body bytes retired.
    pub partial_wire_bytes: usize,
}

/// Failed input/request operation. A retirement distinguishes fatal closure from safe refusal.
#[derive(Debug)]
pub struct AvcClientFailure {
    /// No input contents occur in this typed category.
    pub reason: AvcClientError,
    /// Present only when this operation closed the connection and retired its state.
    pub retirement: Option<AvcClientRetirement>,
}
impl fmt::Display for AvcClientFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for AvcClientFailure {}

/// One bounded owner-visible step; all exact source media survives success and refusal.
#[derive(Debug)]
pub enum AvcClientPoll {
    /// Negotiation/keepalive progress; no frame or continuity claim.
    Control(ClientProgress),
    /// Original datagram and sequence/restart admission receipt.
    Rtp {
        /// Complete original RTP bytes, including its own headers and padding.
        source: InterleavedSource,
        /// Admission result; codec reconstruction is delivered by later Media steps.
        admission: AvcReceiveAdmission,
        /// Confirmed stream restart closes this connection; no old epoch is reused.
        retirement: Option<AvcClientRetirement>,
    },
    /// Complete RTCP validation; raw reports remain available without inventing wall time.
    Rtcp {
        /// Exact original compound bytes, even when malformed.
        source: InterleavedSource,
        /// Full-compound packet count or typed failure. Invalid RTCP does not assert a video gap.
        validation: Result<usize, PacketError>,
    },
    /// Existing loss-aware AVC receiver output, preserving packet spans and picture boundaries.
    Media(AvcReceivePoll),
    /// RTP queue pressure retains the unconsumed frame; no duplicate admission or source drop.
    Backpressure {
        /// Drive the earlier media/session wake before retrying this retained frame.
        wake_at_ns: Option<u64>,
    },
    /// No immediate work; arrange this wake even if the socket stays silent.
    Pending {
        /// Earliest response, keepalive, partial-frame, reorder, fragment, or picture timer.
        wake_at_ns: Option<u64>,
    },
    /// Fatal input/session failure with complete retirement and any rejected source datagram.
    Fault {
        /// Typed refusal, never wire text.
        reason: AvcClientError,
        /// Local quiescence and remote uncertainty accounting.
        retirement: AvcClientRetirement,
        /// A parsed datagram returned intact when admission failed.
        source: Option<InterleavedSource>,
    },
    /// EOF drained accepted input. Tail boundaries remain explicitly unverified.
    Ended {
        /// Final AVC EOF event, including an unverified tail or explicit retirement.
        media: Option<AvcReceivePoll>,
        /// Closing receipt, absent on repeated terminal polls.
        retirement: Option<AvcClientRetirement>,
    },
}

/// Sans-I/O client pump using the existing RTSP parser, client session, and AVC receiver.
/// Ingest chunks no larger than 4 KiB and poll to Pending between feeds. This bounds
/// parser output batches (including zero-length `$` frames) and the partial wire buffer.
/// A backpressured RTP frame is retained until timer-driven queue progress is possible.
/// Original TCP custody, actual I/O, credentials, and network capabilities stay with the owner.
pub struct RtspAvcClient {
    session: RtspClientSession,
    parser: RtspParser,
    key: StreamKey,
    limits: AvcReceiveLimits,
    video: Option<AvcReceiver>,
    events: std::vec::IntoIter<RtspEvent>,
    event_time_ns: u64,
    retry: Option<InterleavedSource>,
    last_ns: u64,
    partial_deadline_ns: Option<u64>,
    input_ended: bool,
    draining: bool,
    closed: bool,
}
impl fmt::Debug for RtspAvcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspAvcClient").field("key", &self.key)
            .field("state", &self.session.state()).field("queued_events", &self.events.len())
            .field("partial_wire_bytes", &self.parser.buffered_bytes())
            .field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl RtspAvcClient {
    /// Bind an explicit owner epoch/expected SSRC and independent media budgets.
    pub fn new(config: ClientConfig, key: StreamKey, limits: AvcReceiveLimits) -> Result<Self, AvcClientError> {
        if key.ingress == 0 || key.generation == 0 { return Err(AvcClientError::StreamBinding); }
        limits.syntax.validate().map_err(AvcClientError::Syntax)?;
        Ok(Self {
            session: RtspClientSession::new(config).map_err(AvcClientError::Session)?,
            parser: RtspParser::with_limits(RtspLimits { max_line_bytes: 2_048, max_headers: 32,
                max_body_bytes: 65_536, max_interleaved_bytes: 65_535 }),
            key, limits, video: None, events: Vec::new().into_iter(), event_time_ns: 0,
            retry: None, last_ns: 0, partial_deadline_ns: None, input_ended: false, draining: false, closed: false,
        })
    }
    /// Protocol state; not camera health or decodability.
    pub fn state(&self) -> ClientState { self.session.state() }
    /// Number of currently unparsed TCP bytes.
    pub fn buffered_wire_bytes(&self) -> usize { self.parser.buffered_bytes() }
    /// Retained codec derivative bytes; original source custody is separately owned.
    pub fn retained_nal_bytes(&self) -> usize { self.video.as_ref().map_or(0, AvcReceiver::retained_nal_bytes) }
    /// Prepare a request; no actual socket write occurs here.
    pub fn request(&mut self, command: ClientCommand, now: u64) -> Result<ClientRequest, AvcClientFailure> {
        self.check_time(now).map_err(refusal)?;
        if self.closed || self.input_ended { return Err(refusal(AvcClientError::Closed)); }
        self.last_ns = now;
        if self.partial_deadline_ns.is_some_and(|at| now >= at) {
            return Err(AvcClientFailure { reason: AvcClientError::PartialTimeout, retirement: Some(self.cancel()) });
        }
        match self.session.request(command, now) {
            Ok(request) => Ok(request),
            Err(error) => {
                let retirement = if self.session.state() == ClientState::Failed { Some(self.cancel()) } else { None };
                Err(AvcClientFailure { reason: AvcClientError::Session(error), retirement })
            }
        }
    }
    /// Consume one bounded TCP chunk. Backpressure/byte refusals consume nothing.
    /// Fatal parse errors retire the connection; never automatically retry those bytes.
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<(), AvcClientFailure> {
        self.check_time(now).map_err(refusal)?;
        if self.closed || self.input_ended { return Err(refusal(AvcClientError::Closed)); }
        if self.events.len() != 0 || self.retry.is_some() { return Err(refusal(AvcClientError::Backpressure)); }
        if bytes.len() > MAX_CHUNK || self.parser.buffered_bytes().saturating_add(bytes.len()) > MAX_BUFFER {
            return Err(refusal(AvcClientError::InputLimit));
        }
        let deadline = now.checked_add(PARTIAL_TIMEOUT).ok_or_else(|| refusal(AvcClientError::Session(ClientError::Exhausted)))?;
        self.last_ns = now;
        // Check before feeding: otherwise a late final byte could empty the
        // parser buffer and erase the expired partial-frame deadline.
        if self.partial_deadline_ns.is_some_and(|at| now >= at) {
            return Err(AvcClientFailure { reason: AvcClientError::PartialTimeout, retirement: Some(self.cancel()) });
        }
        if let Err(error) = self.session.tick(now) {
            return Err(AvcClientFailure { reason: AvcClientError::Session(error), retirement: Some(self.cancel()) });
        }
        match self.parser.feed(bytes) {
            Ok(events) => {
                self.events = events.into_iter(); self.event_time_ns = now;
                self.partial_deadline_ns = if self.parser.buffered_bytes() == 0 { None }
                    // A complete event proves the prior frame ended; a residual
                    // partial frame belongs to the next message, with its own age.
                    else if self.events.len() != 0 { Some(deadline) }
                    else { self.partial_deadline_ns.or(Some(deadline)) };
                Ok(())
            }
            Err(error) => Err(AvcClientFailure { reason: AvcClientError::Wire(error), retirement: Some(self.cancel()) }),
        }
    }
    /// Earliest session/media/framing wake; queued parsed input requests immediate polling.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        if self.events.len() != 0 && self.retry.is_none() || self.input_ended && self.retry.is_none() { return Some(self.last_ns); }
        let mut wake = self.session.next_wake_ns();
        for at in [self.partial_deadline_ns, self.video.as_ref().and_then(AvcReceiver::next_wake_ns)] {
            wake = earlier(wake, at);
        }
        wake.map(|at| at.max(self.last_ns))
    }
    /// One bounded progress step. Drive until Pending/Backpressure/Ended and honor timer wakes.
    pub fn poll(&mut self, now: u64) -> Result<AvcClientPoll, AvcClientError> {
        self.check_time(now)?;
        self.last_ns = now;
        if self.closed { return Ok(AvcClientPoll::Ended { media: None, retirement: None }); }
        if !self.draining {
            if let Err(error) = self.session.tick(now) { return Ok(self.fault(AvcClientError::Session(error), None)); }
            if self.partial_deadline_ns.is_some_and(|at| now >= at) { return Ok(self.fault(AvcClientError::PartialTimeout, None)); }
        }
        if let Some(video) = &mut self.video {
            match video.poll(now) {
                Ok(AvcReceivePoll::Pending { .. }) => {},
                Ok(event @ AvcReceivePoll::Ended { .. }) => {
                    let retirement = self.cancel();
                    return Ok(AvcClientPoll::Ended { media: Some(event), retirement: Some(retirement) });
                }
                Ok(event) => return Ok(AvcClientPoll::Media(event)),
                Err(error) => return Ok(self.fault(AvcClientError::Video(error), None)),
            }
        }
        if let Some(source) = self.retry.take() { return Ok(self.frame(source, now)); }
        if let Some(event) = self.events.next() {
            return Ok(match event {
                RtspEvent::Response(response) | RtspEvent::AuthRequired { response, .. } => {
                    match self.session.accept(&response, now) {
                        Ok(progress) => {
                            if self.session.state() == ClientState::Ready && self.video.is_none() {
                                if let Err(error) = self.configure_video() { return Ok(self.fault(error, None)); }
                            }
                            if self.session.state() == ClientState::Closed { self.input_ended = true; self.draining = true; if let Some(v) = &mut self.video { v.finish(); } }
                            AvcClientPoll::Control(progress)
                        }
                        Err(error) => self.fault(AvcClientError::Session(error), None),
                    }
                }
                RtspEvent::Interleaved { channel, span } => self.frame(InterleavedSource {
                    channel, payload: span, received_ns: self.event_time_ns,
                }, now),
                RtspEvent::Request(_) => self.fault(AvcClientError::ServerRequest, None),
            });
        }
        // Surface the existing parser's deferred error before any new wire can be admitted.
        match self.parser.feed(&[]) {
            Err(error) => return Ok(self.fault(AvcClientError::Wire(error), None)),
            Ok(events) if !events.is_empty() => {
                if self.parser.buffered_bytes() == 0 { self.partial_deadline_ns = None; }
                self.events = events.into_iter();
                return Ok(AvcClientPoll::Pending { wake_at_ns: Some(now) });
            }
            Ok(_) => {},
        }
        if self.parser.buffered_bytes() == 0 { self.partial_deadline_ns = None; }
        if self.input_ended {
            if self.parser.buffered_bytes() != 0 { return Ok(self.fault(AvcClientError::Truncated, None)); }
            self.draining = true;
            if let Some(video) = &mut self.video { video.finish(); return Ok(AvcClientPoll::Pending { wake_at_ns: Some(now) }); }
            let retirement = self.cancel();
            return Ok(AvcClientPoll::Ended { media: None, retirement: Some(retirement) });
        }
        if self.session.tick(now).map_err(AvcClientError::Session)? == ClientProgress::KeepAliveDue {
            return Ok(AvcClientPoll::Control(ClientProgress::KeepAliveDue));
        }
        Ok(AvcClientPoll::Pending { wake_at_ns: self.next_wake_ns() })
    }
    fn configure_video(&mut self) -> Result<(), AvcClientError> {
        if self.session.server_ssrc().is_some_and(|ssrc| ssrc != self.key.ssrc) { return Err(AvcClientError::StreamBinding); }
        let media = self.session.media().ok_or(AvcClientError::StreamBinding)?;
        let (sps, pps) = media.parameter_sets();
        let sps = parse_sps(sps, self.limits.syntax).map_err(AvcClientError::Syntax)?;
        let pps = parse_pps(pps, &sps, self.limits.syntax).map_err(AvcClientError::Syntax)?;
        let mode = if media.packetization_mode() == 0 { H264Mode::SingleNal } else { H264Mode::NonInterleaved };
        self.video = Some(AvcReceiver::new(self.key, media.payload_type(), mode, self.limits, (sps, pps)).map_err(AvcClientError::Video)?);
        Ok(())
    }
    fn frame(&mut self, source: InterleavedSource, now: u64) -> AvcClientPoll {
        let channel = match self.session.admit_channel(source.channel, now) {
            Ok(channel) => channel,
            Err(error) => return self.fault(AvcClientError::Session(error), Some(source)),
        };
        if channel == ClientChannel::Rtcp {
            let reduced = self.session.media().is_some_and(|m| m.reduced_rtcp());
            let mode = if reduced { RtcpMode::ReducedSize } else { RtcpMode::Compound };
            let validation = RtcpCompound::parse(&source.payload, self.limits.reorder.packet, mode).map(|c| c.packet_count());
            return AvcClientPoll::Rtcp { source, validation };
        }
        let result = match &mut self.video {
            Some(video) => video.ingest(self.key, &source.payload, now),
            None => return self.fault(AvcClientError::StreamBinding, Some(source)),
        };
        match result {
            Ok(admission) => {
                let restart = admission.transport.transport.disposition == ReorderDisposition::RestartRequired;
                let retirement = if restart { Some(self.cancel()) } else { None };
                AvcClientPoll::Rtp { source, admission, retirement }
            }
            Err(AvcReceiveError::Transport(H264ReceiveError::Transport(ReorderError::PacketCapacity | ReorderError::ByteCapacity))) => {
                if source.payload.len() > self.limits.reorder.max_bytes {
                    return self.fault(AvcClientError::InputLimit, Some(source));
                }
                self.retry = Some(source);
                AvcClientPoll::Backpressure { wake_at_ns: self.next_wake_ns() }
            }
            Err(error) => self.fault(AvcClientError::Video(error), Some(source)),
        }
    }
    /// Mark TCP EOF. Already accepted complete events drain before codec EOF;
    /// truncated framing instead fences the entire derivative path.
    pub fn finish(&mut self) { self.input_ended = true; }
    /// Stop every layer and return bounded receipts. Original custody is never implicitly deleted.
    pub fn cancel(&mut self) -> AvcClientRetirement {
        let pending_events = self.events.len() + usize::from(self.retry.is_some());
        let pending_media_bytes = self.events.as_slice().iter().map(|e| match e {
            RtspEvent::Interleaved { span, .. } => span.len(), _ => 0,
        }).sum::<usize>() + self.retry.as_ref().map_or(0, |s| s.payload.len());
        let partial_wire_bytes = self.parser.buffered_bytes();
        self.events = Vec::new().into_iter(); self.retry = None; self.parser.reset();
        self.partial_deadline_ns = None; self.closed = true;
        AvcClientRetirement { session: self.session.cancel(), video: self.video.as_mut().map(AvcReceiver::cancel),
            pending_events, pending_media_bytes, partial_wire_bytes }
    }
    fn fault(&mut self, reason: AvcClientError, source: Option<InterleavedSource>) -> AvcClientPoll {
        AvcClientPoll::Fault { reason, retirement: self.cancel(), source }
    }
    fn check_time(&self, now: u64) -> Result<(), AvcClientError> {
        if now < self.last_ns { Err(AvcClientError::Session(ClientError::ClockReversed)) } else { Ok(()) }
    }
}
fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) }
}
fn refusal(reason: AvcClientError) -> AvcClientFailure { AvcClientFailure { reason, retirement: None } }
