#![forbid(unsafe_code)]
//! Owner-driven RTSP client negotiation. No sockets or ambient time.
//! Opt-in Digest helpers borrow credentials from an explicit owner.

/// Bounded credential-owner integration preserving this session's request lifecycle.
pub mod authenticated;
/// Bounded RFC 7798 negotiation without a decoder or codec fallback.
pub mod hevc;

use std::fmt;
use super::{AuthScheme, RtspHeaders, RtspResponse, parse_sdp_bytes};

const SECOND: u64 = 1_000_000_000;
const MAX_URI: usize = 2_048;

/// Explicit owner policy for one connection. URLs never grant network authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientConfig {
    /// Presentation to DESCRIBE, without embedded credentials.
    pub presentation_uri: String,
    /// Allowed control subtree on the same exact authority; no server-directed redirects.
    pub control_root_uri: String,
    /// Exact SDP media index; audio is never implicitly selected.
    pub media_index: usize,
    /// Offered consecutive RTP/RTCP TCP channels.
    pub channels: (u8, u8),
    /// Request response deadline, 1 ns through 60 seconds.
    pub response_timeout_ns: u64,
    /// Session timeout when SETUP omits it, 1 through 3,600 seconds.
    pub default_session_timeout_seconds: u32,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig").field("media_index", &self.media_index)
            .field("channels", &self.channels).finish_non_exhaustive()
    }
}

/// Local negotiation state; Playing means PLAY acknowledged, not frames or continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientState {
    /// No media negotiation yet.
    Idle,
    /// A bounded description for the explicitly selected codec has been accepted.
    Described,
    /// SETUP accepted; PLAY has not yet succeeded.
    Ready,
    /// PLAY acknowledged; the negotiated channels can be consumed.
    Playing,
    /// TEARDOWN is outstanding; media admission is stopped.
    Closing,
    /// Locally closed; consult the close receipt for remote uncertainty.
    Closed,
    /// Failed; reconnect requires a new owner connection and stream generation.
    Failed,
}

/// The only outgoing commands implemented by this reference client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCommand {
    /// Discover supported methods; optional before DESCRIBE.
    Options,
    /// Fetch one description.
    Describe,
    /// Negotiate the selected TCP-interleaved video track.
    Setup,
    /// Start the negotiated session.
    Play,
    /// Refresh a session using OPTIONS (universally defined), without a method fallback.
    KeepAlive,
    /// Stop the session; completion requires its matching response.
    Teardown,
}

/// Payload-free refusal categories; no server text, session token, or URL is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    /// Invalid bounded owner configuration.
    Configuration,
    /// URL is malformed, credential-bearing, or outside the owner subtree.
    UriScope,
    /// The command/event is not valid at this state, or another request is pending.
    State,
    /// Monotonic owner time reversed.
    ClockReversed,
    /// CSeq, time, or bounded allocation cannot be represented.
    Exhausted,
    /// A response does not match the sole outstanding request.
    CseqMismatch,
    /// Malformed or duplicate decision-bearing fields.
    Response,
    /// Only the explicitly selected codec and its supported SDP subset are admitted.
    Description,
    /// SETUP changed the offered transport, channels, or supported parameters.
    Transport,
    /// Missing, invalid, or changed session identity/timeout.
    Session,
    /// The request deadline expired; no automatic resend is safe.
    ResponseTimeout,
    /// The conservative remote session lifetime elapsed.
    SessionExpired,
    /// Authentication must be handled by a separately authorized secret owner.
    Authentication(Option<AuthScheme>),
    /// A non-success response; redirects are never followed.
    Rejected(u16),
    /// A frame arrived outside Playing or on an unnegotiated channel.
    MediaNotAdmitted,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "RTSP client refusal: {self:?}") }
}
impl std::error::Error for ClientError {}

/// Prepared wire bytes. The owner must write once or close; this is not a send receipt.
pub struct ClientRequest {
    command: ClientCommand,
    cseq: u32,
    bytes: String,
}
impl ClientRequest {
    /// Validated complete RTSP request bytes, available only to the transport owner.
    pub fn bytes(&self) -> &[u8] { self.bytes.as_bytes() }
    /// Exact correlation sequence; never reused by this instance.
    pub fn cseq(&self) -> u32 { self.cseq }
    /// Typed intent, independent of its wire method.
    pub fn command(&self) -> ClientCommand { self.command }
}
impl fmt::Debug for ClientRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRequest").field("command", &self.command)
            .field("cseq", &self.cseq).field("byte_len", &self.bytes.len()).finish()
    }
}

/// Immutable owner codec selection. A server cannot switch codecs or choose a fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCodec {
    /// Existing RFC 6184 single-NAL/noninterleaved AVC contract.
    H264,
    /// RFC 7798 HEVC in single-stream transmission order with no DON fields.
    H265,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NegotiatedMedia {
    H264(ClientMedia),
    H265(hevc::HevcClientMedia),
}

/// Negotiated compressed-video parameters. Syntax/decodability remain the codec owner's job.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientMedia {
    payload_type: u8,
    packetization_mode: u8,
    sps: Vec<u8>,
    pps: Vec<u8>,
    reduced_rtcp: bool,
}
impl ClientMedia {
    /// Selected payload mapping.
    pub fn payload_type(&self) -> u8 { self.payload_type }
    /// RFC 6184 mode zero or one.
    pub fn packetization_mode(&self) -> u8 { self.packetization_mode }
    /// Exact decoded SDP parameter-set bytes, including the NAL header.
    pub fn parameter_sets(&self) -> (&[u8], &[u8]) { (&self.sps, &self.pps) }
    /// Explicit reduced-size RTCP negotiation; never inferred from malformed compounds.
    pub fn reduced_rtcp(&self) -> bool { self.reduced_rtcp }
}
impl fmt::Debug for ClientMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientMedia").field("payload_type", &self.payload_type)
            .field("packetization_mode", &self.packetization_mode)
            .field("reduced_rtcp", &self.reduced_rtcp).finish_non_exhaustive()
    }
}

/// Progress from a response or an owner timer wake, never a network effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientProgress {
    /// Informational response; does not renew any deadline.
    Interim,
    /// An exact final response advanced local state.
    Accepted(ClientState),
    /// Owner should issue KeepAlive or close; no request was automatically sent.
    KeepAliveDue,
    /// No action due yet.
    Pending,
}

/// Classification of one authorized interleaved channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientChannel { /// RTP bytes, still untrusted codec input.
    Rtp, /// RTCP bytes, still requiring complete packet validation.
    Rtcp }

/// Cancellation/connection-loss accounting; local closure is not remote TEARDOWN proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCloseReceipt {
    /// SETUP may have crossed the transport and no matching TEARDOWN was accepted.
    pub remote_session_may_exist: bool,
    /// Unsettled request correlation, when present.
    pub pending_cseq: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
struct Pending { command: ClientCommand, cseq: u32, sent_ns: u64, deadline_ns: u64 }

/// Deterministic, one-request-at-a-time session around the existing wire/SDP parsers.
/// Retain raw input independently. All time comes from one owner monotonic clock.
/// On a matching malformed response, timeout, or connection loss, reconnect rather
/// than replaying a request whose server-side outcome may be unknown.
pub struct RtspClientSession {
    config: ClientConfig,
    state: ClientState,
    last_ns: u64,
    next_cseq: u32,
    pending: Option<Pending>,
    codec: ClientCodec,
    media: Option<NegotiatedMedia>,
    track_uri: String,
    aggregate_uri: String,
    session_id: Option<String>,
    timeout_ns: u64,
    expires_ns: Option<u64>,
    keepalive_ns: Option<u64>,
    remote_may_exist: bool,
    ssrc: Option<u32>,
    digest: Option<authenticated::DigestState>,
}
impl fmt::Debug for RtspClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspClientSession").field("state", &self.state)
            .field("pending", &self.pending).field("media", &self.media)
            .field("remote_may_exist", &self.remote_may_exist).finish_non_exhaustive()
    }
}
impl RtspClientSession {
    /// Open one locally scoped client; this neither authenticates nor opens a connection.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        Self::with_codec(config, ClientCodec::H264)
    }
    /// Pin a codec before any request. The original constructor remains H.264-only.
    /// HEVC uses the same scope, CSeq, Digest, session, expiry, and teardown rules.
    pub fn with_codec(config: ClientConfig, codec: ClientCodec) -> Result<Self, ClientError> {
        if config.channels.0.checked_add(1) != Some(config.channels.1)
            || config.media_index >= 64 || config.response_timeout_ns == 0
            || config.response_timeout_ns > 60 * SECOND
            || !(1..=3_600).contains(&config.default_session_timeout_seconds)
        { return Err(ClientError::Configuration); }
        let (root_authority, root_path) = uri_parts(&config.control_root_uri)?;
        if root_path.contains('?') { return Err(ClientError::UriScope); }
        let (authority, _) = uri_parts(&config.presentation_uri)?;
        if authority != root_authority { return Err(ClientError::UriScope); }
        scoped(&config, &config.presentation_uri)?;
        Ok(Self {
            timeout_ns: u64::from(config.default_session_timeout_seconds) * SECOND,
            config, state: ClientState::Idle, last_ns: 0, next_cseq: 1,
            pending: None, codec, media: None, track_uri: String::new(), aggregate_uri: String::new(),
            session_id: None, expires_ns: None, keepalive_ns: None,
            remote_may_exist: false, ssrc: None, digest: None,
        })
    }
    /// Local protocol state only, not a camera health certificate.
    pub fn state(&self) -> ClientState { self.state }
    /// Immutable H.264 parameters after DESCRIBE; always None for an HEVC session.
    /// Existing AVC callers cannot accidentally consume HEVC parameter-set bytes.
    pub fn media(&self) -> Option<&ClientMedia> {
        match self.media.as_ref() { Some(NegotiatedMedia::H264(media)) => Some(media), _ => None }
    }
    /// Immutable HEVC transport parameters after DESCRIBE, not a decode-readiness claim.
    pub fn hevc_media(&self) -> Option<&hevc::HevcClientMedia> {
        match self.media.as_ref() { Some(NegotiatedMedia::H265(media)) => Some(media), _ => None }
    }
    /// Exact owner choice, including before DESCRIBE; never inferred from network data.
    pub fn codec(&self) -> ClientCodec { self.codec }
    /// Negotiated channel pair from the owner offer.
    pub fn channels(&self) -> (u8, u8) { self.config.channels }
    /// Optional server-asserted SSRC; never sender authentication.
    pub fn server_ssrc(&self) -> Option<u32> { self.ssrc }
    /// Earliest useful owner wake. Keepalives do not compete with an outstanding request.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if matches!(self.state, ClientState::Closed | ClientState::Failed) { return None; }
        match (self.pending.map(|p| p.deadline_ns).or(self.keepalive_ns), self.expires_ns) {
            (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b),
        }
    }
    /// Advance timers even without input. Expiry stops media admission immediately.
    pub fn tick(&mut self, now_ns: u64) -> Result<ClientProgress, ClientError> {
        if now_ns < self.last_ns { return Err(ClientError::ClockReversed); }
        self.last_ns = now_ns;
        if matches!(self.state, ClientState::Closed | ClientState::Failed) { return Err(ClientError::State); }
        let error = if self.expires_ns.is_some_and(|at| now_ns >= at) {
            Some(ClientError::SessionExpired)
        } else if self.pending.is_some_and(|p| now_ns >= p.deadline_ns) {
            Some(ClientError::ResponseTimeout)
        } else { None };
        if let Some(error) = error { self.state = ClientState::Failed; return Err(error); }
        Ok(if self.pending.is_none() && self.keepalive_ns.is_some_and(|at| now_ns >= at) {
            ClientProgress::KeepAliveDue
        } else { ClientProgress::Pending })
    }
    /// Prepare a single request and reserve its CSeq/deadline. No unchanged retry is automatic.
    /// An explicitly Digest-enabled session requires request_digest, even for its first request.
    pub fn request(&mut self, command: ClientCommand, now_ns: u64) -> Result<ClientRequest, ClientError> {
        if self.digest.is_some() { return Err(ClientError::Authentication(Some(AuthScheme::Digest))); }
        self.unsigned_request(command, now_ns)
    }
    fn unsigned_request(&mut self, command: ClientCommand, now_ns: u64) -> Result<ClientRequest, ClientError> {
        self.tick(now_ns)?;
        if self.pending.is_some() { return Err(ClientError::State); }
        let valid = match command {
            ClientCommand::Options | ClientCommand::Describe => self.state == ClientState::Idle,
            ClientCommand::Setup => self.state == ClientState::Described,
            ClientCommand::Play => self.state == ClientState::Ready,
            ClientCommand::KeepAlive | ClientCommand::Teardown => matches!(self.state, ClientState::Ready | ClientState::Playing),
        };
        if !valid { return Err(ClientError::State); }
        let cseq = self.next_cseq;
        let next = cseq.checked_add(1).ok_or(ClientError::Exhausted)?;
        let deadline = now_ns.checked_add(self.config.response_timeout_ns).ok_or(ClientError::Exhausted)?;
        let (method, uri) = match command {
            ClientCommand::Options => ("OPTIONS", self.config.presentation_uri.as_str()),
            ClientCommand::Describe => ("DESCRIBE", self.config.presentation_uri.as_str()),
            ClientCommand::Setup => ("SETUP", self.track_uri.as_str()),
            ClientCommand::Play => ("PLAY", self.aggregate_uri.as_str()),
            ClientCommand::KeepAlive => ("OPTIONS", self.aggregate_uri.as_str()),
            ClientCommand::Teardown => ("TEARDOWN", self.aggregate_uri.as_str()),
        };
        // Upper bounds include URI, session token, and every fixed header and number.
        let mut bytes = String::new();
        bytes.try_reserve(MAX_URI + 512).map_err(|_| ClientError::Exhausted)?;
        use fmt::Write as _;
        write!(&mut bytes, "{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n").map_err(|_| ClientError::Exhausted)?;
        if let Some(id) = &self.session_id { write!(&mut bytes, "Session: {id}\r\n").map_err(|_| ClientError::Exhausted)?; }
        if command == ClientCommand::Describe { bytes.push_str("Accept: application/sdp\r\n"); }
        if command == ClientCommand::Setup {
            write!(&mut bytes, "Transport: RTP/AVP/TCP;unicast;interleaved={}-{}\r\n", self.config.channels.0, self.config.channels.1).map_err(|_| ClientError::Exhausted)?;
        }
        bytes.push_str("\r\n");
        self.pending = Some(Pending { command, cseq, sent_ns: now_ns, deadline_ns: deadline });
        self.next_cseq = next;
        if command == ClientCommand::Setup { self.remote_may_exist = true; }
        if command == ClientCommand::Teardown { self.state = ClientState::Closing; }
        Ok(ClientRequest { command, cseq, bytes })
    }
    /// Accept a parsed response while retaining caller ownership of the original input.
    /// Unmatched CSeq is refused without consuming the pending request or renewing time.
    pub fn accept(&mut self, response: &RtspResponse, now_ns: u64) -> Result<ClientProgress, ClientError> {
        if now_ns < self.last_ns { return Err(ClientError::ClockReversed); }
        let pending = self.pending.ok_or(ClientError::State)?;
        bounded_response(response)?;
        let cseq = decimal(singleton(&response.headers, "CSeq")?.ok_or(ClientError::Response)?)?;
        if cseq != u64::from(pending.cseq) { return Err(ClientError::CseqMismatch); }
        self.tick(now_ns)?;
        let result = self.accept_matching(response, pending, now_ns);
        match result {
            Ok(ClientProgress::Interim) => {},
            Ok(_) => {
                self.pending = None;
                if let Some(auth) = &mut self.digest { auth.settled(); }
                if self.state == ClientState::Closed { self.digest = None; }
            },
            Err(_) => self.state = ClientState::Failed,
        }
        result
    }
    fn accept_matching(&mut self, response: &RtspResponse, p: Pending, now: u64) -> Result<ClientProgress, ClientError> {
        if response.version != "RTSP/1.0" { return Err(ClientError::Response); }
        if (100..200).contains(&response.status_code) { return Ok(ClientProgress::Interim); }
        if matches!(response.status_code, 401 | 407) { return Err(ClientError::Authentication(response.auth_challenge)); }
        if response.status_code != 200 { return Err(ClientError::Rejected(response.status_code)); }
        if p.command == ClientCommand::Describe {
            let (media, track, aggregate) = description(&self.config, response, self.codec)?;
            self.media = Some(media); self.track_uri = track; self.aggregate_uri = aggregate;
            self.state = ClientState::Described;
        } else if p.command == ClientCommand::Setup {
            let value = singleton(&response.headers, "Session")?.ok_or(ClientError::Session)?;
            let (id, timeout) = session(value, self.timeout_ns)?;
            let transport = singleton(&response.headers, "Transport")?.ok_or(ClientError::Transport)?;
            let ssrc = transport_binding(transport, self.config.channels)?;
            self.renew(p.sent_ns, now, timeout)?;
            self.session_id = Some(id.to_string()); self.ssrc = ssrc;
            self.state = ClientState::Ready;
        } else if matches!(p.command, ClientCommand::Play | ClientCommand::KeepAlive | ClientCommand::Teardown) {
            let value = singleton(&response.headers, "Session")?;
            if value.is_none() && p.command != ClientCommand::KeepAlive { return Err(ClientError::Session); }
            let timeout = if let Some(value) = value {
                let (id, timeout) = session(value, self.timeout_ns)?;
                if self.session_id.as_deref() != Some(id) { return Err(ClientError::Session); }
                timeout
            } else { self.timeout_ns };
            if p.command == ClientCommand::Teardown {
                self.remote_may_exist = false; self.state = ClientState::Closed;
                self.expires_ns = None; self.keepalive_ns = None; self.session_id = None;
            } else {
                self.renew(p.sent_ns, now, timeout)?;
                if p.command == ClientCommand::Play { self.state = ClientState::Playing; }
            }
        }
        Ok(ClientProgress::Accepted(self.state))
    }
    fn renew(&mut self, sent: u64, now: u64, timeout: u64) -> Result<(), ClientError> {
        // Start at request issue, not ACK receipt: delayed responses cannot manufacture lifetime.
        let expires = sent.checked_add(timeout).ok_or(ClientError::Exhausted)?;
        let keepalive = sent.checked_add(timeout / 2).ok_or(ClientError::Exhausted)?;
        if now >= expires { return Err(ClientError::SessionExpired); }
        self.timeout_ns = timeout; self.expires_ns = Some(expires); self.keepalive_ns = Some(keepalive);
        Ok(())
    }
    /// Classify a frame only after time/lifecycle checks; packet parsing is separate.
    pub fn admit_channel(&mut self, channel: u8, now_ns: u64) -> Result<ClientChannel, ClientError> {
        self.tick(now_ns)?;
        if self.state != ClientState::Playing { return Err(ClientError::MediaNotAdmitted); }
        if channel == self.config.channels.0 { Ok(ClientChannel::Rtp) }
        else if channel == self.config.channels.1 { Ok(ClientChannel::Rtcp) }
        else { Err(ClientError::MediaNotAdmitted) }
    }
    /// Stop admission immediately. Owner closes/drains I/O separately and retains this receipt.
    pub fn cancel(&mut self) -> ClientCloseReceipt {
        let receipt = ClientCloseReceipt { remote_session_may_exist: self.remote_may_exist, pending_cseq: self.pending.map(|p| p.cseq) };
        self.state = ClientState::Closed; self.pending = None; self.session_id = None;
        self.expires_ns = None; self.keepalive_ns = None; self.digest = None;
        receipt
    }
}

fn singleton<'a>(headers: &'a RtspHeaders, name: &str) -> Result<Option<&'a str>, ClientError> {
    let mut values = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|h| h.value.as_str());
    if values.next().is_some() { return Err(ClientError::Response); }
    Ok(value)
}
fn bounded_response(response: &RtspResponse) -> Result<(), ClientError> {
    if response.body.len() > 65_536 || response.headers.len() > 128 || response.reason.len() > 4_096
        || response.headers.iter().any(|h| h.name.len() > 128 || h.value.len() > 4_096
            || h.value.bytes().any(|b| b < 32 && b != b'\t' || b == 127))
    { return Err(ClientError::Response); }
    let length = singleton(&response.headers, "Content-Length")?.map(decimal).transpose()?.unwrap_or(0);
    if length != response.body.len() as u64 { return Err(ClientError::Response); }
    Ok(())
}
fn decimal(value: &str) -> Result<u64, ClientError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) { return Err(ClientError::Response); }
    value.parse().map_err(|_| ClientError::Response)
}
fn session(value: &str, default: u64) -> Result<(&str, u64), ClientError> {
    let mut parts = value.split(';');
    let id = parts.next().ok_or(ClientError::Session)?.trim();
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)) {
        return Err(ClientError::Session);
    }
    let mut timeout = None;
    for part in parts {
        let (name, val) = part.trim().split_once('=').ok_or(ClientError::Session)?;
        if !name.eq_ignore_ascii_case("timeout") || timeout.is_some() { return Err(ClientError::Session); }
        let seconds = decimal(val).map_err(|_| ClientError::Session)?;
        if !(1..=3_600).contains(&seconds) { return Err(ClientError::Session); }
        timeout = Some(seconds * SECOND);
    }
    Ok((id, timeout.unwrap_or(default)))
}
fn transport_binding(value: &str, offered: (u8, u8)) -> Result<Option<u32>, ClientError> {
    let mut parts = value.split(';');
    if parts.next() != Some("RTP/AVP/TCP") || value.contains(',') { return Err(ClientError::Transport); }
    let (mut unicast, mut channels, mut mode, mut ssrc) = (false, false, false, None);
    for part in parts {
        let part = part.trim();
        if part == "unicast" && !unicast { unicast = true; continue; }
        let (name, val) = part.split_once('=').ok_or(ClientError::Transport)?;
        match name {
            "interleaved" if !channels => {
                let (a, b) = val.split_once('-').ok_or(ClientError::Transport)?;
                if decimal(a).ok() != Some(u64::from(offered.0)) || decimal(b).ok() != Some(u64::from(offered.1)) {
                    return Err(ClientError::Transport);
                }
                channels = true;
            }
            "mode" if !mode && matches!(val, "PLAY" | "\"PLAY\"") => mode = true,
            "ssrc" if ssrc.is_none() && !val.is_empty() && val.len() <= 8 && val.bytes().all(|b| b.is_ascii_hexdigit()) => {
                ssrc = Some(u32::from_str_radix(val, 16).map_err(|_| ClientError::Transport)?);
            }
            _ => return Err(ClientError::Transport),
        }
    }
    if !unicast || !channels { return Err(ClientError::Transport); }
    Ok(ssrc)
}

fn description(config: &ClientConfig, r: &RtspResponse, codec: ClientCodec)
    -> Result<(NegotiatedMedia, String, String), ClientError>
{
    let content_type = singleton(&r.headers, "Content-Type")?.ok_or(ClientError::Description)?;
    if !content_type.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/sdp") {
        return Err(ClientError::Description);
    }
    let text = std::str::from_utf8(&r.body).map_err(|_| ClientError::Description)?;
    // Existing SDP parser intentionally keeps a broad observational subset. At a client
    // decision boundary, reject ambiguous last-wins attributes and multi-format m-lines.
    let (mut section, mut controls, mut maps, mut formats) = (None, 0, 0, 0);
    for line in text.lines().map(str::trim) {
        if line.starts_with("m=") {
            section = Some(section.map_or(0, |n: usize| n + 1)); controls = 0; maps = 0; formats = 0;
            if section == Some(config.media_index) && line.split_whitespace().count() != 4 { return Err(ClientError::Description); }
        } else if line.starts_with("a=control:") {
            controls += 1; if controls > 1 { return Err(ClientError::Description); }
        } else if section == Some(config.media_index) && line.starts_with("a=rtpmap:") {
            maps += 1; if maps > 1 { return Err(ClientError::Description); }
        } else if section == Some(config.media_index) && line.starts_with("a=fmtp:") {
            formats += 1; if formats > 1 { return Err(ClientError::Description); }
            let mut seen = std::collections::BTreeSet::new();
            let attrs = line.split_once(' ').ok_or(ClientError::Description)?.1;
            for attr in attrs.split(';') {
                let key = attr.trim().split('=').next().ok_or(ClientError::Description)?
                    .trim().to_ascii_lowercase();
                if key.is_empty() || !seen.insert(key) { return Err(ClientError::Description); }
            }
        }
    }
    let sdp = parse_sdp_bytes(&r.body).map_err(|_| ClientError::Description)?;
    let m = sdp.media.get(config.media_index).ok_or(ClientError::Description)?;
    let media = match codec {
        ClientCodec::H264 => NegotiatedMedia::H264(h264_media(m)?),
        ClientCodec::H265 => NegotiatedMedia::H265(hevc::negotiate(text, config.media_index, m)?),
    };
    let content_base = singleton(&r.headers, "Content-Base")?;
    let location = singleton(&r.headers, "Content-Location")?;
    let base = if let Some(base) = content_base { scoped(config, base)?; base.to_string() }
        else if let Some(location) = location { resolve(config, &config.presentation_uri, location)? }
        else { config.presentation_uri.clone() };
    let track = resolve(config, &base, m.control.as_deref().ok_or(ClientError::Description)?)?;
    let aggregate = match sdp.session_control.as_deref() {
        Some("*") => base,
        Some(control) => resolve(config, &base, control)?,
        None => track.clone(),
    };
    Ok((media, track, aggregate))
}

fn h264_media(m: &super::SdpMedia) -> Result<ClientMedia, ClientError> {
    if m.media_type != "video" || !matches!(m.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
        || m.encoding_name.as_deref() != Some("H264") || m.clock_rate != Some(90_000)
        || m.packetization_mode.unwrap_or(0) > 1 || m.sprop_parameter_sets.len() != 2
    { return Err(ClientError::Description); }
    let sps = m.sps.as_ref().ok_or(ClientError::Description)?;
    let pps = m.pps.as_ref().ok_or(ClientError::Description)?;
    if sps.len() < 4 || pps.len() < 2 || sps.len() > 16_384 || pps.len() > 16_384
        || sps[0] & 0x9f != 7 || pps[0] & 0x9f != 8
    { return Err(ClientError::Description); }
    // The advertised profile/constraints/level must agree with the selected SPS.
    // Missing signaling stays missing; it is never replaced with an invented profile.
    if let Some(profile) = &m.profile_level_id {
        if profile.len() != 6 || !profile.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ClientError::Description);
        }
        for index in 0..3 {
            let value = u8::from_str_radix(&profile[index * 2..index * 2 + 2], 16)
                .map_err(|_| ClientError::Description)?;
            if value != sps[index + 1] { return Err(ClientError::Description); }
        }
    }
    Ok(ClientMedia { payload_type: m.payload_type, packetization_mode: m.packetization_mode.unwrap_or(0),
        sps: sps.clone(), pps: pps.clone(), reduced_rtcp: m.rtcp_reduced_size })
}

fn uri_parts(uri: &str) -> Result<(&str, &str), ClientError> {
    if uri.len() > MAX_URI || !uri.is_ascii() || uri.bytes().any(|b| b <= 32 || b >= 127 || b"\\#@".contains(&b)) {
        return Err(ClientError::UriScope);
    }
    let rest = uri.strip_prefix("rtsp://").ok_or(ClientError::UriScope)?;
    let split = rest.find('/').ok_or(ClientError::UriScope)?;
    let (authority, path) = rest.split_at(split);
    if authority.is_empty() || (authority.contains('%') || authority.contains('?')) { return Err(ClientError::UriScope); }
    // Authority is matched exactly, not resolved. No DNS alias or alternate port broadening.
    if !authority.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)) { return Err(ClientError::UriScope); }
    for segment in path.split('?').next().unwrap_or("").split('/') {
        if matches!(segment, "." | "..") { return Err(ClientError::UriScope); }
    }
    let mut at = 0;
    let raw = path.as_bytes();
    while at < raw.len() {
        if raw[at] == b'%' {
            let hex = path.get(at + 1..at + 3).ok_or(ClientError::UriScope)?;
            let decoded = u8::from_str_radix(hex, 16).map_err(|_| ClientError::UriScope)?;
            if decoded <= 32 || b"./\\@#%".contains(&decoded) || decoded == 127 { return Err(ClientError::UriScope); }
            at += 3;
        } else { at += 1; }
    }
    Ok((authority, path))
}
fn scoped(config: &ClientConfig, uri: &str) -> Result<(), ClientError> {
    let (root_authority, root_path) = uri_parts(&config.control_root_uri)?;
    let (authority, path) = uri_parts(uri)?;
    let root = root_path.trim_end_matches('/');
    let path = path.split('?').next().unwrap_or("");
    if authority != root_authority || !(path == root || path.strip_prefix(root).is_some_and(|tail| tail.starts_with('/'))) {
        return Err(ClientError::UriScope);
    }
    Ok(())
}
fn resolve(config: &ClientConfig, base: &str, control: &str) -> Result<String, ClientError> {
    if control.is_empty() || control == "*" || control.len() > MAX_URI { return Err(ClientError::UriScope); }
    let result = if control.starts_with("rtsp://") { control.to_string() } else {
        if control.contains("://") || control.starts_with("//") { return Err(ClientError::UriScope); }
        let (authority, path) = uri_parts(base)?;
        if control.starts_with('/') { format!("rtsp://{authority}{control}") }
        else {
            let path = path.split('?').next().unwrap_or("");
            let end = path.rfind('/').ok_or(ClientError::UriScope)? + 1;
            format!("rtsp://{authority}{}{control}", &path[..end])
        }
    };
    scoped(config, &result)?;
    Ok(result)
}
