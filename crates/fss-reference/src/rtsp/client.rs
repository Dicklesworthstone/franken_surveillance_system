#![forbid(unsafe_code)]
//! Owner-driven RTSP client negotiation. No sockets or ambient time.
//! Opt-in Digest helpers borrow credentials from an explicit owner.

/// Bounded credential-owner integration preserving this session's request lifecycle.
#[path = "client/authenticated.rs"]
pub mod authenticated;
/// Bounded RFC 7798 negotiation without a decoder or codec fallback.
#[path = "client/hevc.rs"]
pub mod hevc;
/// Bounded in-band H.264/H.265 parameter-set acquisition for SDP-minimal RTSP sources.
#[path = "client/inband.rs"]
pub mod inband;
/// RFC 2435 JPEG transport on the shared session and exact payload selection.
#[path = "client/jpeg.rs"]
pub mod jpeg;
/// Owner-selected uncompressed ONVIF application transport metadata.
#[path = "client/metadata.rs"]
pub mod metadata;
/// Pure validation of supplied video DESCRIBE evidence without a live transaction.
#[path = "client/observed.rs"]
pub mod observed;
/// Closed forward recorder playback with explicit request and acknowledgement bounds.
#[path = "client/replay.rs"]
pub mod replay;

use super::selection::{
    select_h264_description, select_h265_description, select_jpeg_description,
    select_onvif_metadata_description,
};
use super::{AuthScheme, RtspHeaders, RtspResponse};
use replay::{ReplayAcceptance, ReplayError, ReplayRejection, ReplayWindow};
use std::fmt;

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
        f.debug_struct("ClientConfig")
            .field("media_index", &self.media_index)
            .field("channels", &self.channels)
            .finish_non_exhaustive()
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
    /// Negotiate the selected TCP-interleaved media track.
    Setup,
    /// Negotiate AVC or HEVC recorder playback with the required ONVIF replay option.
    SetupReplay,
    /// Start the negotiated session.
    Play,
    /// Request one bounded forward recorder interval after an accepted replay SETUP.
    PlayReplay(ReplayWindow),
    /// Refresh a session using OPTIONS, preserving the original default wire contract.
    KeepAlive,
    /// Explicit empty-body GET_PARAMETER liveness request (RFC 2326 section 10.8).
    /// This does not read or change camera parameters and never enables method fallback.
    KeepAliveGetParameter,
    /// Stop the session; completion requires its matching response.
    Teardown,
}
impl ClientCommand {
    /// Exact method used by BOTH wire preparation and Digest A2 computation.
    /// This contains no target, credential, session identity or source payload.
    pub const fn wire_method(self) -> &'static str {
        match self {
            Self::Options | Self::KeepAlive => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Setup | Self::SetupReplay => "SETUP",
            Self::Play | Self::PlayReplay(_) => "PLAY",
            Self::KeepAliveGetParameter => "GET_PARAMETER",
            Self::Teardown => "TEARDOWN",
        }
    }
    /// Whether this command only requests session liveness, not a media transition.
    pub const fn is_keepalive(self) -> bool {
        matches!(self, Self::KeepAlive | Self::KeepAliveGetParameter)
    }
    const fn is_setup(self) -> bool {
        matches!(self, Self::Setup | Self::SetupReplay)
    }
    const fn is_play(self) -> bool {
        matches!(self, Self::Play | Self::PlayReplay(_))
    }
    const fn is_replay(self) -> bool {
        matches!(self, Self::SetupReplay | Self::PlayReplay(_))
    }
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
    /// Malformed, missing, ambiguous or widened replay acknowledgement.
    Replay(ReplayError),
    /// Specific recorder replay rejection; none proves upstream retention expiry.
    ReplayRejected(ReplayRejection),
    /// A frame arrived outside Playing or on an unnegotiated channel.
    MediaNotAdmitted,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP client refusal: {self:?}")
    }
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
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
    /// Exact correlation sequence; never reused by this instance.
    pub fn cseq(&self) -> u32 {
        self.cseq
    }
    /// Typed intent, independent of its wire method.
    pub fn command(&self) -> ClientCommand {
        self.command
    }
    /// Bind the immutable request target to the transport's exact owner-approved authority.
    /// Only the first wire line is relevant; Digest headers cannot supply the target.
    pub(super) fn matches_authority(&self, authority: &str) -> bool {
        self.bytes
            .split_once("\r\n")
            .and_then(|(line, _)| line.strip_prefix(self.command.wire_method()))
            .and_then(|target| target.strip_prefix(' '))
            .and_then(|target| target.strip_suffix(" RTSP/1.0"))
            .and_then(|target| uri_parts(target).ok())
            .is_some_and(|(target_authority, _)| target_authority == authority)
    }
}
impl fmt::Debug for ClientRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRequest")
            .field("command", &self.command)
            .field("cseq", &self.cseq)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Immutable owner codec selection. A server cannot switch codecs or choose a fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCodec {
    /// Existing RFC 6184 single-NAL/noninterleaved AVC contract.
    H264,
    /// RFC 7798 HEVC in single-stream transmission order with no DON fields.
    H265,
    /// RFC 2435 baseline JPEG images on static payload 26 or a pinned dynamic payload.
    Jpeg,
    /// Uncompressed ONVIF metadata with an explicitly pinned dynamic payload type.
    OnvifMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NegotiatedMedia {
    H264(ClientMedia),
    H265(hevc::HevcClientMedia),
    Jpeg(jpeg::JpegClientMedia),
    OnvifMetadata(metadata::MetadataClientMedia),
}

/// Negotiated compressed-video parameters. Syntax/decodability remain the codec owner's job.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientMedia {
    payload_type: u8,
    packetization_mode: u8,
    sps: Vec<u8>,
    pps: Vec<u8>,
    reduced_rtcp: bool,
    parameter_set_origin: Option<inband::ParameterSetOrigin>,
}
impl ClientMedia {
    /// Selected payload mapping.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }
    /// RFC 6184 mode zero or one.
    pub fn packetization_mode(&self) -> u8 {
        self.packetization_mode
    }
    /// Exact decoded SDP parameter-set bytes, including the NAL header.
    /// Empty only when opt-in in-band RTP parameter-set acquisition was explicitly enabled.
    pub fn parameter_sets(&self) -> (&[u8], &[u8]) {
        (&self.sps, &self.pps)
    }
    /// Whether SDP supplied complete out-of-band SPS and PPS parameter sets.
    pub fn has_parameter_sets(&self) -> bool {
        !self.sps.is_empty() && !self.pps.is_empty()
    }
    /// Provenance of SDP parameter sets, or `None` when awaiting in-band RTP acquisition.
    pub fn parameter_set_origin(&self) -> Option<inband::ParameterSetOrigin> {
        self.parameter_set_origin
    }
    /// Explicit reduced-size RTCP negotiation; never inferred from malformed compounds.
    pub fn reduced_rtcp(&self) -> bool {
        self.reduced_rtcp
    }
}
impl fmt::Debug for ClientMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientMedia")
            .field("payload_type", &self.payload_type)
            .field("packetization_mode", &self.packetization_mode)
            .field("reduced_rtcp", &self.reduced_rtcp)
            .finish_non_exhaustive()
    }
}

/// Progress from a response or an owner timer wake, never a network effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientProgress {
    /// Informational response; does not renew any deadline.
    Interim,
    /// An exact final response advanced local state.
    Accepted(ClientState),
    /// A matching replay PLAY was accepted within its requested interval. The local
    /// state is Playing; this does not certify received media or historical coverage.
    ReplayAccepted(ReplayAcceptance),
    /// Owner should issue an explicitly selected keepalive or close; nothing was sent.
    KeepAliveDue,
    /// No action due yet.
    Pending,
}

/// Classification of one authorized interleaved channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientChannel {
    /// RTP bytes, still untrusted codec input.
    Rtp,
    /// RTCP bytes, still requiring complete packet validation.
    Rtcp,
}

/// Cancellation/connection-loss accounting; local closure is not remote TEARDOWN proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCloseReceipt {
    /// SETUP may have crossed the transport and no matching TEARDOWN was accepted.
    pub remote_session_may_exist: bool,
    /// Unsettled request correlation, when present.
    pub pending_cseq: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    command: ClientCommand,
    cseq: u32,
    sent_ns: u64,
    deadline_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompanionTrack {
    track_uri: String,
    channels: (u8, u8),
}

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
    selected_payload_type: Option<u8>,
    allow_inband_parameter_sets: bool,
    setup_companion_tracks: bool,
    video_setup_done: bool,
    companion_tracks: Vec<CompanionTrack>,
    companion_setup_index: usize,
    track_uri: String,
    aggregate_uri: String,
    session_id: Option<String>,
    timeout_ns: u64,
    expires_ns: Option<u64>,
    keepalive_ns: Option<u64>,
    remote_may_exist: bool,
    replay_setup: bool,
    ssrc: Option<u32>,
    digest: Option<authenticated::DigestState>,
}
impl fmt::Debug for RtspClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspClientSession")
            .field("state", &self.state)
            .field("pending", &self.pending)
            .field("media", &self.media)
            .field("remote_may_exist", &self.remote_may_exist)
            .finish_non_exhaustive()
    }
}
impl RtspClientSession {
    /// Open one locally scoped client; this neither authenticates nor opens a connection.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        Self::with_codec(config, ClientCodec::H264)
    }
    /// Pin a codec before any request. The original constructor remains H.264-only.
    /// HEVC uses the same scope, CSeq, Digest, session, expiry, and teardown rules.
    /// ONVIF metadata requires `with_codec_and_payload_type` with a dynamic payload.
    pub fn with_codec(config: ClientConfig, codec: ClientCodec) -> Result<Self, ClientError> {
        if codec == ClientCodec::OnvifMetadata {
            // Metadata has no implicit first/only-payload selection contract.
            return Err(ClientError::Configuration);
        }
        Self::new_for_codec(config, codec)
    }

    fn new_for_codec(config: ClientConfig, codec: ClientCodec) -> Result<Self, ClientError> {
        if config.channels.0.checked_add(1) != Some(config.channels.1)
            || config.media_index >= 64
            || config.response_timeout_ns == 0
            || config.response_timeout_ns > 60 * SECOND
            || !(1..=3_600).contains(&config.default_session_timeout_seconds)
        {
            return Err(ClientError::Configuration);
        }
        let (root_authority, root_path) = uri_parts(&config.control_root_uri)?;
        if root_path.contains('?') {
            return Err(ClientError::UriScope);
        }
        let (authority, _) = uri_parts(&config.presentation_uri)?;
        if authority != root_authority {
            return Err(ClientError::UriScope);
        }
        scoped(&config, &config.presentation_uri)?;
        Ok(Self {
            timeout_ns: u64::from(config.default_session_timeout_seconds) * SECOND,
            config,
            state: ClientState::Idle,
            last_ns: 0,
            next_cseq: 1,
            pending: None,
            codec,
            media: None,
            selected_payload_type: None,
            allow_inband_parameter_sets: false,
            setup_companion_tracks: false,
            video_setup_done: false,
            companion_tracks: Vec::new(),
            companion_setup_index: 0,
            track_uri: String::new(),
            aggregate_uri: String::new(),
            session_id: None,
            expires_ns: None,
            keepalive_ns: None,
            remote_may_exist: false,
            replay_setup: false,
            ssrc: None,
            digest: None,
        })
    }
    /// Open a session pinned to one offered H.264 payload type.
    ///
    /// This owner choice is immutable for this connection. An absent, unsupported,
    /// or malformed chosen mapping is refused; no fallback to another offer occurs.
    /// The configured media index, URI scope, and transport constraints still apply.
    pub fn new_with_payload_type(
        config: ClientConfig,
        payload_type: u8,
    ) -> Result<Self, ClientError> {
        if payload_type > 127 {
            return Err(ClientError::Configuration);
        }
        let mut session = Self::new(config)?;
        session.selected_payload_type = Some(payload_type);
        Ok(session)
    }
    /// Pin both codec and payload before any request or authentication challenge.
    /// No other offered payload can substitute for an absent or invalid selection.
    /// This also permits explicit selection between multiple HEVC mappings while
    /// retaining the existing HEVC format, URI, session and transport validators.
    /// ONVIF metadata requires an exact dynamic payload (96 through 127).
    pub fn with_codec_and_payload_type(
        config: ClientConfig,
        codec: ClientCodec,
        payload_type: u8,
    ) -> Result<Self, ClientError> {
        if payload_type > 127
            || (codec == ClientCodec::OnvifMetadata && payload_type < 96)
            || (codec == ClientCodec::Jpeg && !matches!(payload_type, 26 | 96..=127))
        {
            return Err(ClientError::Configuration);
        }
        let mut session = Self::new_for_codec(config, codec)?;
        session.selected_payload_type = Some(payload_type);
        Ok(session)
    }
    /// Local protocol state only, not a camera health certificate.
    pub fn state(&self) -> ClientState {
        self.state
    }
    /// Immutable H.264 parameters after DESCRIBE; None for other media contracts.
    /// Existing AVC callers cannot consume another codec's parameters or metadata.
    pub fn media(&self) -> Option<&ClientMedia> {
        match self.media.as_ref() {
            Some(NegotiatedMedia::H264(media)) => Some(media),
            _ => None,
        }
    }
    /// Immutable HEVC transport parameters after DESCRIBE, not a decode-readiness claim.
    pub fn hevc_media(&self) -> Option<&hevc::HevcClientMedia> {
        match self.media.as_ref() {
            Some(NegotiatedMedia::H265(media)) => Some(media),
            _ => None,
        }
    }
    /// Exact JPEG transport signaling; per-image format and pixels remain unvalidated.
    pub fn jpeg_media(&self) -> Option<&jpeg::JpegClientMedia> {
        match self.media.as_ref() {
            Some(NegotiatedMedia::Jpeg(media)) => Some(media),
            _ => None,
        }
    }
    /// Exact uncompressed ONVIF transport selection; no XML or vendor claim is implied.
    pub fn metadata_media(&self) -> Option<&metadata::MetadataClientMedia> {
        match self.media.as_ref() {
            Some(NegotiatedMedia::OnvifMetadata(media)) => Some(media),
            _ => None,
        }
    }
    /// Exact owner choice, including before DESCRIBE; never inferred from network data.
    pub fn codec(&self) -> ClientCodec {
        self.codec
    }
    /// Opt in before DESCRIBE to admit an H.264 SDP offer that omits `sprop-parameter-sets`,
    /// deferring parameter-set lock to bounded in-band RTP acquisition. Default is strict (`false`).
    pub fn set_allow_inband_parameter_sets(&mut self, enabled: bool) -> Result<(), ClientError> {
        if self.state != ClientState::Idle || self.pending.is_some() {
            return Err(ClientError::State);
        }
        self.allow_inband_parameter_sets = enabled;
        Ok(())
    }
    /// Whether in-band parameter-set acquisition is enabled for this session.
    pub fn allow_inband_parameter_sets(&self) -> bool {
        self.allow_inband_parameter_sets
    }
    /// Opt in before DESCRIBE to negotiate companion `m=audio` tracks on distinct TCP
    /// interleaved channel pairs alongside the selected video track before `PLAY`.
    /// Audio bytes are never recorded or decoded (GOAL-009); companion channels are drained.
    pub fn set_setup_companion_tracks(&mut self, enabled: bool) -> Result<(), ClientError> {
        if self.state != ClientState::Idle || self.pending.is_some() {
            return Err(ClientError::State);
        }
        self.setup_companion_tracks = enabled;
        Ok(())
    }
    /// Whether companion audio track SETUP is enabled for this session.
    pub fn setup_companion_tracks(&self) -> bool {
        self.setup_companion_tracks
    }
    /// Negotiated companion interleaved channel pairs (empty unless companion tracks were found).
    pub fn companion_channels(&self) -> Vec<(u8, u8)> {
        self.companion_tracks.iter().map(|t| t.channels).collect()
    }
    /// Whether `channel` belongs to a negotiated companion (e.g., audio) track while `Playing`.
    /// Companion packets must be explicitly counted and drained without entering the video path.
    pub fn is_companion_channel(&mut self, channel: u8, now_ns: u64) -> Result<bool, ClientError> {
        self.tick(now_ns)?;
        if self.state != ClientState::Playing {
            return Ok(false);
        }
        Ok(self.companion_tracks[..self.companion_setup_index]
            .iter()
            .any(|track| channel == track.channels.0 || channel == track.channels.1))
    }
    /// Negotiated channel pair from the owner offer.
    pub fn channels(&self) -> (u8, u8) {
        self.config.channels
    }
    /// Optional server-asserted SSRC; never sender authentication.
    pub fn server_ssrc(&self) -> Option<u32> {
        self.ssrc
    }
    /// Earliest useful owner wake. Keepalives do not compete with an outstanding request.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if matches!(self.state, ClientState::Closed | ClientState::Failed) {
            return None;
        }
        match (
            self.pending.map(|p| p.deadline_ns).or(self.keepalive_ns),
            self.expires_ns,
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Earliest hard request/session expiry, excluding advisory keepalive timing.
    /// A transport owner that cannot issue requests while wire is backpressured
    /// must still wake for these fail-closed deadlines rather than busy-polling
    /// a past-due keepalive or silently extending the remote lifetime.
    pub fn next_expiry_ns(&self) -> Option<u64> {
        if matches!(self.state, ClientState::Closed | ClientState::Failed) {
            return None;
        }
        match (self.pending.map(|p| p.deadline_ns), self.expires_ns) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Advance timers even without input. Expiry stops media admission immediately.
    pub fn tick(&mut self, now_ns: u64) -> Result<ClientProgress, ClientError> {
        if now_ns < self.last_ns {
            return Err(ClientError::ClockReversed);
        }
        self.last_ns = now_ns;
        if matches!(self.state, ClientState::Closed | ClientState::Failed) {
            return Err(ClientError::State);
        }
        let error = if self.expires_ns.is_some_and(|at| now_ns >= at) {
            Some(ClientError::SessionExpired)
        } else if self.pending.is_some_and(|p| now_ns >= p.deadline_ns) {
            Some(ClientError::ResponseTimeout)
        } else {
            None
        };
        if let Some(error) = error {
            self.state = ClientState::Failed;
            return Err(error);
        }
        Ok(
            if self.pending.is_none() && self.keepalive_ns.is_some_and(|at| now_ns >= at) {
                ClientProgress::KeepAliveDue
            } else {
                ClientProgress::Pending
            },
        )
    }
    /// Prepare a single request and reserve its CSeq/deadline. No unchanged retry is automatic.
    /// An explicitly Digest-enabled session requires request_digest, even for its first request.
    pub fn request(
        &mut self,
        command: ClientCommand,
        now_ns: u64,
    ) -> Result<ClientRequest, ClientError> {
        if self.digest.is_some() {
            return Err(ClientError::Authentication(Some(AuthScheme::Digest)));
        }
        self.unsigned_request(command, now_ns)
    }
    // One method/URI owner prevents Digest from signing a method different from the wire.
    fn request_target(&self, command: ClientCommand) -> (&'static str, &str) {
        let uri = match command {
            ClientCommand::Options | ClientCommand::Describe => &self.config.presentation_uri,
            ClientCommand::Setup | ClientCommand::SetupReplay => {
                if self.video_setup_done
                    && let Some(companion) = self.companion_tracks.get(self.companion_setup_index)
                {
                    &companion.track_uri
                } else {
                    &self.track_uri
                }
            }
            ClientCommand::Play
            | ClientCommand::PlayReplay(_)
            | ClientCommand::KeepAlive
            | ClientCommand::KeepAliveGetParameter
            | ClientCommand::Teardown => &self.aggregate_uri,
        };
        (command.wire_method(), uri)
    }
    fn active_setup_channels(&self) -> (u8, u8) {
        if self.video_setup_done
            && let Some(companion) = self.companion_tracks.get(self.companion_setup_index)
        {
            companion.channels
        } else {
            self.config.channels
        }
    }
    fn unsigned_request(
        &mut self,
        command: ClientCommand,
        now_ns: u64,
    ) -> Result<ClientRequest, ClientError> {
        self.tick(now_ns)?;
        if self.pending.is_some() {
            return Err(ClientError::State);
        }
        let valid = match command {
            ClientCommand::Options | ClientCommand::Describe => self.state == ClientState::Idle,
            ClientCommand::Setup => self.state == ClientState::Described,
            ClientCommand::SetupReplay => {
                self.state == ClientState::Described
                    && !self.video_setup_done
                    && matches!(self.codec, ClientCodec::H264 | ClientCodec::H265)
            }
            ClientCommand::Play => self.state == ClientState::Ready && !self.replay_setup,
            ClientCommand::PlayReplay(_) => self.state == ClientState::Ready && self.replay_setup,
            ClientCommand::KeepAlive
            | ClientCommand::KeepAliveGetParameter
            | ClientCommand::Teardown => {
                matches!(self.state, ClientState::Ready | ClientState::Playing)
            }
        };
        if !valid {
            return Err(ClientError::State);
        }
        let cseq = self.next_cseq;
        let next = cseq.checked_add(1).ok_or(ClientError::Exhausted)?;
        let deadline = now_ns
            .checked_add(self.config.response_timeout_ns)
            .ok_or(ClientError::Exhausted)?;
        let setup_channels = self.active_setup_channels();
        let (method, uri) = self.request_target(command);
        // Upper bounds include URI, session token, and every fixed header and number.
        let mut bytes = String::new();
        bytes
            .try_reserve(MAX_URI + 512)
            .map_err(|_| ClientError::Exhausted)?;
        use fmt::Write as _;
        write!(&mut bytes, "{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n")
            .map_err(|_| ClientError::Exhausted)?;
        if let Some(id) = &self.session_id {
            write!(&mut bytes, "Session: {id}\r\n").map_err(|_| ClientError::Exhausted)?;
        }
        if command == ClientCommand::Describe {
            bytes.push_str("Accept: application/sdp\r\n");
        }
        if command.is_setup() {
            write!(
                &mut bytes,
                "Transport: RTP/AVP/TCP;unicast;interleaved={}-{}\r\n",
                setup_channels.0, setup_channels.1
            )
            .map_err(|_| ClientError::Exhausted)?;
        }
        if command.is_replay() {
            bytes.push_str("Require: onvif-replay\r\n");
        }
        if let ClientCommand::PlayReplay(window) = command {
            write!(&mut bytes, "Range: {window}\r\nRate-Control: no\r\n")
                .map_err(|_| ClientError::Exhausted)?;
        }
        if command == ClientCommand::KeepAliveGetParameter {
            // No parameter names or arbitrary body can cross this liveness-only API.
            // Leave every legacy OPTIONS byte unchanged.
            bytes.push_str("Content-Length: 0\r\n");
        }
        bytes.push_str("\r\n");
        self.pending = Some(Pending {
            command,
            cseq,
            sent_ns: now_ns,
            deadline_ns: deadline,
        });
        self.next_cseq = next;
        if command.is_setup() {
            self.remote_may_exist = true;
        }
        if command == ClientCommand::Teardown {
            self.state = ClientState::Closing;
        }
        Ok(ClientRequest {
            command,
            cseq,
            bytes,
        })
    }
    /// Accept a parsed response while retaining caller ownership of the original input.
    /// Unmatched CSeq is refused without consuming the pending request or renewing time.
    pub fn accept(
        &mut self,
        response: &RtspResponse,
        now_ns: u64,
    ) -> Result<ClientProgress, ClientError> {
        if now_ns < self.last_ns {
            return Err(ClientError::ClockReversed);
        }
        let pending = self.pending.ok_or(ClientError::State)?;
        bounded_response(response)?;
        let cseq = decimal(singleton(&response.headers, "CSeq")?.ok_or(ClientError::Response)?)?;
        if cseq != u64::from(pending.cseq) {
            return Err(ClientError::CseqMismatch);
        }
        self.tick(now_ns)?;
        let result = self.accept_matching(response, pending, now_ns);
        match result {
            Ok(ClientProgress::Interim) => {}
            Ok(_) => {
                self.pending = None;
                if let Some(auth) = &mut self.digest {
                    auth.settled();
                }
                if self.state == ClientState::Closed {
                    self.digest = None;
                }
            }
            Err(_) => self.state = ClientState::Failed,
        }
        result
    }
    fn accept_matching(
        &mut self,
        response: &RtspResponse,
        p: Pending,
        now: u64,
    ) -> Result<ClientProgress, ClientError> {
        if response.version != "RTSP/1.0" {
            return Err(ClientError::Response);
        }
        if (100..200).contains(&response.status_code) {
            return Ok(ClientProgress::Interim);
        }
        if matches!(response.status_code, 401 | 407) {
            return Err(ClientError::Authentication(response.auth_challenge));
        }
        if response.status_code != 200 {
            if p.command.is_replay()
                && let Some(rejection) = ReplayRejection::from_status(response.status_code)
            {
                return Err(ClientError::ReplayRejected(rejection));
            }
            return Err(ClientError::Rejected(response.status_code));
        }
        // Validate the historical interval before renewing a session or admitting media.
        // Digest retries retain the original command and range while advancing CSeq.
        let replay = if let ClientCommand::PlayReplay(requested) = p.command {
            replay::validate_response_policy(&response.headers).map_err(ClientError::Replay)?;
            let value = singleton(&response.headers, "Range")
                .map_err(|_| ClientError::Replay(ReplayError::DuplicateRange))?
                .ok_or(ClientError::Replay(ReplayError::MissingRange))?;
            let acknowledged = ReplayWindow::parse(value).map_err(ClientError::Replay)?;
            Some(
                ReplayAcceptance::new(p.cseq, requested, acknowledged)
                    .map_err(ClientError::Replay)?,
            )
        } else {
            None
        };
        if p.command == ClientCommand::Describe {
            let (media, track, aggregate, companions) = description(
                &self.config,
                response,
                self.codec,
                self.selected_payload_type,
                self.allow_inband_parameter_sets,
                self.setup_companion_tracks,
            )?;
            self.media = Some(media);
            self.track_uri = track;
            self.aggregate_uri = aggregate;
            self.companion_tracks = companions;
            self.video_setup_done = false;
            self.companion_setup_index = 0;
            self.state = ClientState::Described;
        } else if p.command.is_setup() {
            let value = singleton(&response.headers, "Session")?.ok_or(ClientError::Session)?;
            let (id, timeout) = session(value, self.timeout_ns)?;
            let transport =
                singleton(&response.headers, "Transport")?.ok_or(ClientError::Transport)?;
            if !self.video_setup_done {
                let ssrc = transport_binding(transport, self.config.channels)?;
                self.renew(p.sent_ns, now, timeout)?;
                self.session_id = Some(id.to_string());
                self.ssrc = ssrc;
                self.replay_setup = p.command == ClientCommand::SetupReplay;
                self.video_setup_done = true;
                self.state = if self.companion_setup_index < self.companion_tracks.len() {
                    ClientState::Described
                } else {
                    ClientState::Ready
                };
            } else {
                if self.session_id.as_deref() != Some(id) {
                    return Err(ClientError::Session);
                }
                let expected_channels = self
                    .companion_tracks
                    .get(self.companion_setup_index)
                    .ok_or(ClientError::State)?
                    .channels;
                // Companion audio SSRC never overwrites the video track's SSRC binding.
                let _companion_ssrc = transport_binding(transport, expected_channels)?;
                self.renew(p.sent_ns, now, timeout)?;
                self.companion_setup_index += 1;
                self.state = if self.companion_setup_index < self.companion_tracks.len() {
                    ClientState::Described
                } else {
                    ClientState::Ready
                };
            }
        } else if p.command.is_keepalive()
            || p.command.is_play()
            || p.command == ClientCommand::Teardown
        {
            let value = singleton(&response.headers, "Session")?;
            if value.is_none() && !p.command.is_keepalive() {
                return Err(ClientError::Session);
            }
            let timeout = if let Some(value) = value {
                let (id, timeout) = session(value, self.timeout_ns)?;
                if self.session_id.as_deref() != Some(id) {
                    return Err(ClientError::Session);
                }
                timeout
            } else {
                self.timeout_ns
            };
            if p.command == ClientCommand::Teardown {
                self.remote_may_exist = false;
                self.state = ClientState::Closed;
                self.expires_ns = None;
                self.keepalive_ns = None;
                self.session_id = None;
            } else {
                self.renew(p.sent_ns, now, timeout)?;
                if p.command.is_play() {
                    self.state = ClientState::Playing;
                }
            }
        }
        Ok(match replay {
            Some(acceptance) => ClientProgress::ReplayAccepted(acceptance),
            None => ClientProgress::Accepted(self.state),
        })
    }
    fn renew(&mut self, sent: u64, now: u64, timeout: u64) -> Result<(), ClientError> {
        // Start at request issue, not ACK receipt: delayed responses cannot manufacture lifetime.
        let expires = sent.checked_add(timeout).ok_or(ClientError::Exhausted)?;
        let keepalive = sent
            .checked_add(timeout / 2)
            .ok_or(ClientError::Exhausted)?;
        if now >= expires {
            return Err(ClientError::SessionExpired);
        }
        self.timeout_ns = timeout;
        self.expires_ns = Some(expires);
        self.keepalive_ns = Some(keepalive);
        Ok(())
    }
    /// Classify a frame only after time/lifecycle checks; packet parsing is separate.
    pub fn admit_channel(
        &mut self,
        channel: u8,
        now_ns: u64,
    ) -> Result<ClientChannel, ClientError> {
        self.tick(now_ns)?;
        if self.state != ClientState::Playing {
            return Err(ClientError::MediaNotAdmitted);
        }
        if channel == self.config.channels.0 {
            Ok(ClientChannel::Rtp)
        } else if channel == self.config.channels.1 {
            Ok(ClientChannel::Rtcp)
        } else {
            Err(ClientError::MediaNotAdmitted)
        }
    }
    /// Stop admission immediately. Owner closes/drains I/O separately and retains this receipt.
    pub fn cancel(&mut self) -> ClientCloseReceipt {
        let receipt = ClientCloseReceipt {
            remote_session_may_exist: self.remote_may_exist,
            pending_cseq: self.pending.map(|p| p.cseq),
        };
        self.state = ClientState::Closed;
        self.pending = None;
        self.session_id = None;
        self.expires_ns = None;
        self.keepalive_ns = None;
        self.digest = None;
        receipt
    }
}

fn singleton<'a>(headers: &'a RtspHeaders, name: &str) -> Result<Option<&'a str>, ClientError> {
    let mut values = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|h| h.value.as_str());
    if values.next().is_some() {
        return Err(ClientError::Response);
    }
    Ok(value)
}
fn bounded_response(response: &RtspResponse) -> Result<(), ClientError> {
    if response.body.len() > 65_536
        || response.headers.len() > 128
        || response.reason.len() > 4_096
        || response.headers.iter().any(|h| {
            h.name.len() > 128
                || h.value.len() > 4_096
                || h.value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        })
    {
        return Err(ClientError::Response);
    }
    let length = singleton(&response.headers, "Content-Length")?
        .map(decimal)
        .transpose()?
        .unwrap_or(0);
    if length != response.body.len() as u64 {
        return Err(ClientError::Response);
    }
    Ok(())
}
fn decimal(value: &str) -> Result<u64, ClientError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClientError::Response);
    }
    value.parse().map_err(|_| ClientError::Response)
}
fn session(value: &str, default: u64) -> Result<(&str, u64), ClientError> {
    let mut parts = value.split(';');
    let id = parts.next().ok_or(ClientError::Session)?.trim();
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
    {
        return Err(ClientError::Session);
    }
    let mut timeout = None;
    for part in parts {
        let (name, val) = part.trim().split_once('=').ok_or(ClientError::Session)?;
        if !name.eq_ignore_ascii_case("timeout") || timeout.is_some() {
            return Err(ClientError::Session);
        }
        let seconds = decimal(val).map_err(|_| ClientError::Session)?;
        if !(1..=3_600).contains(&seconds) {
            return Err(ClientError::Session);
        }
        timeout = Some(seconds * SECOND);
    }
    Ok((id, timeout.unwrap_or(default)))
}
fn transport_binding(value: &str, offered: (u8, u8)) -> Result<Option<u32>, ClientError> {
    let mut parts = value.split(';');
    if parts.next() != Some("RTP/AVP/TCP") || value.contains(',') {
        return Err(ClientError::Transport);
    }
    let (mut unicast, mut channels, mut mode, mut ssrc) = (false, false, false, None);
    let (mut source, mut destination) = (false, false);
    for part in parts {
        let part = part.trim();
        if part == "unicast" && !unicast {
            unicast = true;
            continue;
        }
        let (name, val) = part.split_once('=').ok_or(ClientError::Transport)?;
        match name {
            "interleaved" if !channels => {
                let (a, b) = val.split_once('-').ok_or(ClientError::Transport)?;
                if decimal(a).ok() != Some(u64::from(offered.0))
                    || decimal(b).ok() != Some(u64::from(offered.1))
                {
                    return Err(ClientError::Transport);
                }
                channels = true;
            }
            "mode" if !mode && matches!(val, "PLAY" | "\"PLAY\"") => mode = true,
            // RFC 2326 section 12.39 permits address metadata in SETUP. With
            // interleaved TCP it grants no routing authority: media still arrives
            // only on the existing owner-pinned connection and selected channels.
            // Original header custody is unchanged; no address is resolved or used.
            "source" if !source && transport_host(val) => source = true,
            "destination" if !destination && transport_host(val) => destination = true,
            "ssrc"
                if ssrc.is_none()
                    && !val.is_empty()
                    && val.len() <= 8
                    && val.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                ssrc = Some(u32::from_str_radix(val, 16).map_err(|_| ClientError::Transport)?);
            }
            _ => return Err(ClientError::Transport),
        }
    }
    if !unicast || !channels {
        return Err(ClientError::Transport);
    }
    Ok(ssrc)
}

fn transport_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some(ipv6) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return ipv6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    // Reject ambiguous numeric addresses, ports, userinfo and URI syntax. DNS
    // spelling is permitted as metadata only and never invokes a resolver.
    let host = value.strip_suffix('.').unwrap_or(value);
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod transport_metadata_tests {
    use super::*;

    #[test]
    fn tcp_address_metadata_preserves_exact_channels_and_sender() -> Result<(), ClientError> {
        for host in [
            "192.0.2.8",
            "2001:db8::8",
            "[2001:db8::8]",
            "protect.local",
            "console-01.example.test.",
        ] {
            let header = format!(
                "RTP/AVP/TCP;unicast;source={host};destination=192.0.2.9;interleaved=4-5;ssrc=9ABCDEF0;mode=\"PLAY\""
            );
            assert_eq!(transport_binding(&header, (4, 5))?, Some(0x9abc_def0));
            assert_eq!(
                transport_binding(&header, (0, 1)),
                Err(ClientError::Transport)
            );
        }
        assert_eq!(
            transport_binding(
                "RTP/AVP/TCP;unicast;interleaved=0-1;source=protect.local",
                (0, 1)
            )?,
            None
        );
        Ok(())
    }

    #[test]
    fn tcp_address_metadata_rejects_ambiguous_and_routing_directives() {
        let prefix = "RTP/AVP/TCP;unicast;interleaved=0-1";
        for suffix in [
            "source=192.0.2.8;source=192.0.2.8",
            "destination=192.0.2.9;destination=192.0.2.10",
            "source=",
            "destination=",
            "source=010.0.0.1",
            "source=192.0.2.999",
            "source=alice@192.0.2.8",
            "source=rtsp://192.0.2.8/live",
            "source=192.0.2.8:7447",
            "source=[2001:db8::8]:7447",
            "source=[not-an-ip]",
            "source=.local",
            "source=console..local",
            "source=-console.local",
            "source=console_.local",
            "source=console%2elocal",
            "source=console\r\nInjected: value",
            "source=console local",
            "source=console\0local",
            "source=192.0.2.8;client_port=8000-8001",
            "source=192.0.2.8;server_port=8000-8001",
            "source=192.0.2.8;multicast",
            "source=192.0.2.8;mode=RECORD",
            "source=192.0.2.8, RTP/AVP/TCP;unicast;interleaved=0-1",
        ] {
            assert_eq!(
                transport_binding(&format!("{prefix};{suffix}"), (0, 1)),
                Err(ClientError::Transport)
            );
        }
        for host in [format!("{}.local", "x".repeat(64)), "x".repeat(254)] {
            assert_eq!(
                transport_binding(&format!("{prefix};source={host}"), (0, 1)),
                Err(ClientError::Transport)
            );
        }
    }
}

const MAX_COMPANION_TRACKS: usize = 4;

fn description(
    config: &ClientConfig,
    r: &RtspResponse,
    codec: ClientCodec,
    payload_type: Option<u8>,
    allow_inband: bool,
    collect_companions: bool,
) -> Result<(NegotiatedMedia, String, String, Vec<CompanionTrack>), ClientError> {
    let content_type = singleton(&r.headers, "Content-Type")?.ok_or(ClientError::Description)?;
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/sdp")
    {
        return Err(ClientError::Description);
    }
    // Every media owner consumes one bounded exact payload projection. HEVC must
    // receive that projection's matching text because the observational parser
    // does not retain every RFC 7798 field. Original response custody is unchanged.
    let (sdp, hevc_text) = match codec {
        ClientCodec::H264 => (
            select_h264_description(&r.body, config.media_index, payload_type)
                .map_err(|_| ClientError::Description)?,
            None,
        ),
        ClientCodec::H265 => {
            let (sdp, text) = select_h265_description(&r.body, config.media_index, payload_type)
                .map_err(|_| ClientError::Description)?;
            (sdp, Some(text))
        }
        ClientCodec::Jpeg => (
            select_jpeg_description(&r.body, config.media_index, payload_type)
                .map_err(|_| ClientError::Description)?,
            None,
        ),
        ClientCodec::OnvifMetadata => (
            select_onvif_metadata_description(
                &r.body,
                config.media_index,
                payload_type.ok_or(ClientError::Description)?,
            )
            .map_err(|_| ClientError::Description)?,
            None,
        ),
    };
    let m = sdp
        .media
        .get(config.media_index)
        .ok_or(ClientError::Description)?;
    let media = match codec {
        ClientCodec::H264 => NegotiatedMedia::H264(h264_media(m, allow_inband)?),
        ClientCodec::H265 => NegotiatedMedia::H265(hevc::negotiate(
            hevc_text.as_deref().ok_or(ClientError::Description)?,
            config.media_index,
            m,
        )?),
        ClientCodec::Jpeg => NegotiatedMedia::Jpeg(jpeg::negotiate(m)?),
        ClientCodec::OnvifMetadata => NegotiatedMedia::OnvifMetadata(metadata::negotiate(m)?),
    };
    let content_base = singleton(&r.headers, "Content-Base")?;
    let location = singleton(&r.headers, "Content-Location")?;
    let base = if let Some(base) = content_base {
        scoped(config, base)?;
        base.to_string()
    } else if let Some(location) = location {
        resolve(config, &config.presentation_uri, location)?
    } else {
        config.presentation_uri.clone()
    };
    let track = resolve(
        config,
        &base,
        m.control.as_deref().ok_or(ClientError::Description)?,
    )?;
    let mut companions = Vec::new();
    if collect_companions {
        let mut next_channel = config.channels.1.checked_add(1);
        for (index, other) in sdp.media.iter().enumerate() {
            if index == config.media_index
                || other.media_type != "audio"
                || !matches!(other.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
            {
                continue;
            }
            let Some(control) = other.control.as_deref() else {
                continue;
            };
            if companions.len() >= MAX_COMPANION_TRACKS {
                return Err(ClientError::Description);
            }
            let track_uri = resolve(config, &base, control)?;
            // Allocate disjoint consecutive TCP interleaved channels (e.g., 2-3 after 0-1).
            let channels =
                allocate_companion_channels(config.channels, &companions, &mut next_channel)?;
            companions.push(CompanionTrack {
                track_uri,
                channels,
            });
        }
    }
    let aggregate = match sdp.session_control.as_deref() {
        Some("*") => base,
        Some(control) => resolve(config, &base, control)?,
        None => {
            if companions.is_empty() {
                track.clone()
            } else {
                base
            }
        }
    };
    Ok((media, track, aggregate, companions))
}

fn allocate_companion_channels(
    primary: (u8, u8),
    existing: &[CompanionTrack],
    cursor: &mut Option<u8>,
) -> Result<(u8, u8), ClientError> {
    let collides = |pair: (u8, u8)| {
        pair.0 == primary.0
            || pair.0 == primary.1
            || pair.1 == primary.0
            || pair.1 == primary.1
            || existing.iter().any(|track| {
                pair.0 == track.channels.0
                    || pair.0 == track.channels.1
                    || pair.1 == track.channels.0
                    || pair.1 == track.channels.1
            })
    };
    if let Some(start) = *cursor
        && let Some(end) = start.checked_add(1)
        && !collides((start, end))
    {
        *cursor = end.checked_add(1);
        return Ok((start, end));
    }
    for candidate in (0u8..=254u8).step_by(2) {
        let pair = (candidate, candidate + 1);
        if !collides(pair) {
            *cursor = pair.1.checked_add(1);
            return Ok(pair);
        }
    }
    Err(ClientError::Exhausted)
}

fn h264_media(m: &super::SdpMedia, allow_inband: bool) -> Result<ClientMedia, ClientError> {
    if m.media_type != "video"
        || !matches!(m.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
        || m.encoding_name.as_deref() != Some("H264")
        || m.clock_rate != Some(90_000)
        || m.packetization_mode.unwrap_or(0) > 1
    {
        return Err(ClientError::Description);
    }
    if allow_inband && m.sprop_parameter_sets.is_empty() {
        if m.sps.is_some() || m.pps.is_some() {
            return Err(ClientError::Description);
        }
        if let Some(profile) = &m.profile_level_id
            && (profile.len() != 6 || !profile.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ClientError::Description);
        }
        return Ok(ClientMedia {
            payload_type: m.payload_type,
            // When SDP omits a=fmtp in in-band mode, default to non-interleaved (mode 1)
            // so Single NAL, STAP-A, and FU-A payloads are admitted; honor explicit 0 or 1.
            packetization_mode: m.packetization_mode.unwrap_or(1),
            sps: Vec::new(),
            pps: Vec::new(),
            reduced_rtcp: m.rtcp_reduced_size,
            parameter_set_origin: None,
        });
    }
    if m.sprop_parameter_sets.len() != 2 {
        return Err(ClientError::Description);
    }
    let sps = m.sps.as_ref().ok_or(ClientError::Description)?;
    let pps = m.pps.as_ref().ok_or(ClientError::Description)?;
    if sps.len() < 4
        || pps.len() < 2
        || sps.len() > 16_384
        || pps.len() > 16_384
        || sps[0] & 0x9f != 7
        || pps[0] & 0x9f != 8
    {
        return Err(ClientError::Description);
    }
    // The advertised profile/constraints/level must agree with the selected SPS.
    // Missing signaling stays missing; it is never replaced with an invented profile.
    if let Some(profile) = &m.profile_level_id {
        if profile.len() != 6 || !profile.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ClientError::Description);
        }
        for index in 0..3 {
            let value = u8::from_str_radix(&profile[index * 2..index * 2 + 2], 16)
                .map_err(|_| ClientError::Description)?;
            if value != sps[index + 1] {
                return Err(ClientError::Description);
            }
        }
    }
    Ok(ClientMedia {
        payload_type: m.payload_type,
        packetization_mode: m.packetization_mode.unwrap_or(0),
        sps: sps.clone(),
        pps: pps.clone(),
        reduced_rtcp: m.rtcp_reduced_size,
        parameter_set_origin: Some(inband::ParameterSetOrigin::SdpFmtp),
    })
}

/// Validate a bounded credential-free RTSP URI without resolving or rewriting it.
///
/// Returns the exact authority and path plus optional query. This only checks URI syntax;
/// callers must independently authorize the peer, authority, control subtree, and transport.
/// Encoded controls, separators, traversal, and double decoding are refused. The returned
/// strings can contain private stream tokens and must not be included in diagnostics.
pub fn validated_uri_parts(uri: &str) -> Result<(&str, &str), ClientError> {
    super::uri::validated_uri_parts(uri).map_err(|_| ClientError::UriScope)
}
fn uri_parts(uri: &str) -> Result<(&str, &str), ClientError> {
    validated_uri_parts(uri)
}
fn scoped(config: &ClientConfig, uri: &str) -> Result<(), ClientError> {
    let (root_authority, root_path) = uri_parts(&config.control_root_uri)?;
    let (authority, path) = uri_parts(uri)?;
    let root = root_path.trim_end_matches('/');
    let path = path.split('?').next().unwrap_or("");
    if authority != root_authority
        || !(path == root
            || path
                .strip_prefix(root)
                .is_some_and(|tail| tail.starts_with('/')))
    {
        return Err(ClientError::UriScope);
    }
    Ok(())
}
fn resolve(config: &ClientConfig, base: &str, control: &str) -> Result<String, ClientError> {
    if control.is_empty() || control == "*" || control.len() > MAX_URI {
        return Err(ClientError::UriScope);
    }
    let result = if control.starts_with("rtsp://") {
        control.to_string()
    } else {
        if control.contains("://") || control.starts_with("//") {
            return Err(ClientError::UriScope);
        }
        let (authority, path) = uri_parts(base)?;
        if control.starts_with('/') {
            format!("rtsp://{authority}{control}")
        } else {
            let path = path.split('?').next().unwrap_or("");
            let end = path.rfind('/').ok_or(ClientError::UriScope)? + 1;
            format!("rtsp://{authority}{}{control}", &path[..end])
        }
    };
    scoped(config, &result)?;
    Ok(result)
}

#[cfg(test)]
#[path = "client/selection_tests.rs"]
mod selection_tests;

#[cfg(test)]
mod hevc_selection_tests {
    use super::*;
    use crate::rtsp::{RtspEvent, RtspLimits, RtspParser};

    const PREFIX: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n";
    const MIXED: &str = "m=video 0 RTP/AVP 96 98\r\na=control:video\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\na=rtpmap:98 H265/90000\r\na=fmtp:98 sprop-max-don-diff=0;sprop-vps=QAEM;sprop-sps=QgEM;sprop-pps=RAHA\r\na=rtcp-rsize\r\n";

    fn config() -> ClientConfig {
        ClientConfig {
            presentation_uri: "rtsp://camera/live/".into(),
            control_root_uri: "rtsp://camera/live".into(),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: SECOND,
            default_session_timeout_seconds: 60,
        }
    }

    fn describe(
        session: &mut RtspClientSession,
        body: &str,
    ) -> Result<ClientProgress, ClientError> {
        let request = session.request(ClientCommand::Describe, 0)?;
        let wire = format!(
            "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            request.cseq(),
            body.len(),
        );
        let mut parser = RtspParser::with_limits(RtspLimits {
            max_line_bytes: 2_048,
            max_headers: 32,
            max_body_bytes: 65_536,
            max_interleaved_bytes: 65_535,
        });
        for event in parser
            .feed(wire.as_bytes())
            .map_err(|_| ClientError::Response)?
        {
            if let RtspEvent::Response(response) = event {
                return session.accept(&response, 1);
            }
        }
        Err(ClientError::Response)
    }

    #[test]
    fn mixed_offer_selects_hevc_and_reaches_scoped_setup() -> Result<(), ClientError> {
        let mut session = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
        assert_eq!(
            describe(&mut session, &format!("{PREFIX}{MIXED}"))?,
            ClientProgress::Accepted(ClientState::Described)
        );
        assert!(session.media().is_none());
        let media = session.hevc_media().ok_or(ClientError::Description)?;
        assert_eq!(media.payload_type(), 98);
        assert_eq!(media.vps(), &[vec![0x40, 1, 0x0c]]);
        assert_eq!(media.sps(), &[vec![0x42, 1, 0x0c]]);
        assert_eq!(media.pps(), &[vec![0x44, 1, 0xc0]]);
        assert!(media.reduced_rtcp());
        let setup = session.request(ClientCommand::Setup, 2)?;
        assert_eq!(setup.cseq(), 2);
        assert!(
            setup
                .bytes()
                .starts_with(b"SETUP rtsp://camera/live/video RTSP/1.0\r\n")
        );
        Ok(())
    }

    #[test]
    fn ambiguous_hevc_requires_exact_selection_and_never_borrows_sets() -> Result<(), ClientError> {
        let body =
            format!("{PREFIX}{MIXED}").replace("96 98", "96 98 99") + "a=rtpmap:99 H265/90000\r\n";
        let mut ambiguous = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
        assert_eq!(
            describe(&mut ambiguous, &body),
            Err(ClientError::Description)
        );
        assert_eq!(ambiguous.state(), ClientState::Failed);
        assert!(ambiguous.hevc_media().is_none());
        let mut exact =
            RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::H265, 99)?;
        describe(&mut exact, &body)?;
        let media = exact.hevc_media().ok_or(ClientError::Description)?;
        assert_eq!(media.payload_type(), 99);
        assert!(media.vps().is_empty());
        assert!(media.sps().is_empty());
        assert!(media.pps().is_empty());
        Ok(())
    }

    #[test]
    fn exact_hevc_refuses_missing_and_wrong_codec_mapping() -> Result<(), ClientError> {
        for payload in [96, 97] {
            let mut session = RtspClientSession::with_codec_and_payload_type(
                config(),
                ClientCodec::H265,
                payload,
            )?;
            assert_eq!(
                describe(&mut session, &format!("{PREFIX}{MIXED}")),
                Err(ClientError::Description)
            );
            assert!(session.hevc_media().is_none());
            assert!(session.request(ClientCommand::Setup, 2).is_err());
        }
        assert!(matches!(
            RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::H265, 128),
            Err(ClientError::Configuration)
        ));
        Ok(())
    }

    #[test]
    fn selected_hevc_preserves_don_multilayer_and_unknown_format_clamps() -> Result<(), ClientError>
    {
        let body = format!("{PREFIX}{MIXED}");
        for malformed in [
            body.replace("sprop-max-don-diff=0", "sprop-max-don-diff=1"),
            body.replace("sprop-max-don-diff=0", "tx-mode=MRST"),
            body.replace("sprop-max-don-diff=0", "unsupported-required-field=1"),
            body.replace("sprop-max-don-diff=0", "profile-id=1;PROFILE-ID=2"),
            format!("{body}a=rtcp-mux\r\n"),
            body.replace("m=video", "a=group:LS video\r\nm=video"),
            body.replace("H265/90000", "H265/8000"),
        ] {
            let mut session = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
            assert_eq!(
                describe(&mut session, &malformed),
                Err(ClientError::Description)
            );
            assert!(session.hevc_media().is_none());
        }
        Ok(())
    }

    #[test]
    fn selected_hevc_keeps_media_ordinal_and_control_scope() -> Result<(), ClientError> {
        let body = format!("{PREFIX}m=audio 0 RTP/AVP 0\r\na=control:audio\r\n{MIXED}");
        let mut owner = config();
        owner.media_index = 1;
        let mut session = RtspClientSession::with_codec(owner, ClientCodec::H265)?;
        describe(&mut session, &body)?;
        assert_eq!(
            session
                .hevc_media()
                .ok_or(ClientError::Description)?
                .payload_type(),
            98
        );
        for control in ["rtsp://other/live/video", "rtsp://camera/outside/video"] {
            let mut session = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
            assert_eq!(
                describe(
                    &mut session,
                    &format!("{PREFIX}{MIXED}")
                        .replace("a=control:video", &format!("a=control:{control}"))
                ),
                Err(ClientError::UriScope)
            );
            assert!(session.hevc_media().is_none());
        }
        Ok(())
    }
}

#[cfg(test)]
mod inband_and_companion_tests {
    use super::*;
    use crate::rtsp::{RtspEvent, RtspParser};

    fn config() -> ClientConfig {
        ClientConfig {
            presentation_uri: "rtsp://camera/stream1".into(),
            control_root_uri: "rtsp://camera/".into(),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 5 * SECOND,
            default_session_timeout_seconds: 60,
        }
    }

    fn feed_response(
        session: &mut RtspClientSession,
        wire: &[u8],
        now: u64,
    ) -> Result<ClientProgress, ClientError> {
        let mut parser = RtspParser::new();
        parser.set_lossy_nonframing_headers(true);
        for event in parser.feed(wire).map_err(|_| ClientError::Response)? {
            if let RtspEvent::Response(response) = event {
                return session.accept(&response, now);
            }
        }
        Err(ClientError::Response)
    }

    const WYZE_SDP: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.168.4.39\r\n",
        "s=WyzeCam\r\n",
        "t=0 0\r\n",
        "a=control:*\r\n",
        "m=video 0 RTP/AVP 96\r\n",
        "a=rtpmap:96 H264/90000\r\n",
        "a=control:track1\r\n",
        "m=audio 0 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=control:track2\r\n",
    );

    #[test]
    fn strict_mode_rejects_sdp_without_sprop_and_inband_mode_admits_it() -> Result<(), ClientError>
    {
        let describe_resp = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{WYZE_SDP}",
            WYZE_SDP.len()
        );
        let mut strict = RtspClientSession::new(config())?;
        let _ = strict.request(ClientCommand::Describe, 1)?;
        assert_eq!(
            feed_response(&mut strict, describe_resp.as_bytes(), 2),
            Err(ClientError::Description)
        );

        let mut inband = RtspClientSession::new(config())?;
        inband.set_allow_inband_parameter_sets(true)?;
        let _ = inband.request(ClientCommand::Describe, 1)?;
        assert_eq!(
            feed_response(&mut inband, describe_resp.as_bytes(), 2)?,
            ClientProgress::Accepted(ClientState::Described)
        );
        let media = inband.media().ok_or(ClientError::Description)?;
        assert!(!media.has_parameter_sets());
        assert_eq!(media.parameter_set_origin(), None);
        assert_eq!(media.packetization_mode(), 1);
        Ok(())
    }

    #[test]
    fn companion_audio_setup_uses_distinct_channels_and_enforces_scope() -> Result<(), ClientError>
    {
        let describe_resp = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{WYZE_SDP}",
            WYZE_SDP.len()
        );
        let mut session = RtspClientSession::new(config())?;
        session.set_allow_inband_parameter_sets(true)?;
        session.set_setup_companion_tracks(true)?;
        let _ = session.request(ClientCommand::Describe, 1)?;
        assert_eq!(
            feed_response(&mut session, describe_resp.as_bytes(), 2)?,
            ClientProgress::Accepted(ClientState::Described)
        );
        assert_eq!(session.companion_channels(), vec![(2, 3)]);

        // First SETUP targets video track1 on 0-1; stays Described until companion SETUP finishes.
        let setup_video = session.request(ClientCommand::Setup, 3)?;
        let video_req =
            std::str::from_utf8(setup_video.bytes()).map_err(|_| ClientError::Response)?;
        assert!(video_req.starts_with("SETUP rtsp://camera/track1 RTSP/1.0\r\n"));
        assert!(video_req.contains("interleaved=0-1\r\n"));
        let resp_video = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: wyze42;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007\r\n\r\n";
        assert_eq!(
            feed_response(&mut session, resp_video, 4)?,
            ClientProgress::Accepted(ClientState::Described)
        );
        assert_eq!(session.server_ssrc(), Some(7));

        // Second SETUP targets companion audio track2 on 2-3 with Session header.
        let setup_audio = session.request(ClientCommand::Setup, 5)?;
        let audio_req =
            std::str::from_utf8(setup_audio.bytes()).map_err(|_| ClientError::Response)?;
        assert!(audio_req.starts_with("SETUP rtsp://camera/track2 RTSP/1.0\r\n"));
        assert!(audio_req.contains("Session: wyze42\r\n"));
        assert!(audio_req.contains("interleaved=2-3\r\n"));
        let resp_audio = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: wyze42;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3;ssrc=DEADBEEF\r\n\r\n";
        assert_eq!(
            feed_response(&mut session, resp_audio, 6)?,
            ClientProgress::Accepted(ClientState::Ready)
        );
        // Video SSRC must never be overwritten by companion audio SSRC!
        assert_eq!(session.server_ssrc(), Some(7));

        let _ = session.request(ClientCommand::Play, 7)?;
        let resp_play = b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: wyze42\r\n\r\n";
        assert_eq!(
            feed_response(&mut session, resp_play, 8)?,
            ClientProgress::Accepted(ClientState::Playing)
        );
        assert!(session.is_companion_channel(2, 9)?);
        assert!(session.is_companion_channel(3, 9)?);
        assert!(!session.is_companion_channel(0, 9)?);
        assert!(!session.is_companion_channel(4, 9)?);

        // Out-of-scope companion audio URI is refused.
        let bad_sdp = WYZE_SDP.replace("a=control:track2", "a=control:rtsp://evil/track2");
        let bad_resp = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{bad_sdp}",
            bad_sdp.len()
        );
        let mut scoped_session = RtspClientSession::new(config())?;
        scoped_session.set_allow_inband_parameter_sets(true)?;
        scoped_session.set_setup_companion_tracks(true)?;
        let _ = scoped_session.request(ClientCommand::Describe, 1)?;
        assert_eq!(
            feed_response(&mut scoped_session, bad_resp.as_bytes(), 2),
            Err(ClientError::UriScope)
        );
        Ok(())
    }

    #[test]
    fn lossy_parser_tolerates_latin1_vendor_server_header_and_keeps_framing_strict() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Cam");
        wire.push(0xe9); // Latin-1 'é'
        wire.extend_from_slice(b"ra/1.0\r\nContent-Length: 0\r\n\r\n");

        // Default strict parser still fails and poisons.
        let mut strict = RtspParser::new();
        assert!(strict.feed(&wire).is_err());
        assert!(strict.poisoned().is_some());

        // Lossy non-framing mode decodes Server lossily and succeeds cleanly.
        let mut lossy = RtspParser::new();
        lossy.set_lossy_nonframing_headers(true);
        let events = lossy.feed(&wire).expect("lossy parse should succeed");
        assert_eq!(events.len(), 1);
        match &events[0] {
            RtspEvent::Response(resp) => {
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.headers.get("Server"), Some("Cam\u{FFFD}ra/1.0"));
            }
            _ => panic!("expected response"),
        }

        // Non-UTF-8 in a framing header (CSeq) still fails and poisons even in lossy mode.
        let mut bad_cseq = Vec::new();
        bad_cseq.extend_from_slice(b"RTSP/1.0 200 OK\r\nCSeq: 1");
        bad_cseq.push(0xff);
        bad_cseq.extend_from_slice(b"\r\n\r\n");
        let mut lossy_strict_check = RtspParser::new();
        lossy_strict_check.set_lossy_nonframing_headers(true);
        assert!(lossy_strict_check.feed(&bad_cseq).is_err());
        assert!(lossy_strict_check.poisoned().is_some());
    }
}
