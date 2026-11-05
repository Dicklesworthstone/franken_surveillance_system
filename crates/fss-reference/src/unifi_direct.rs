#![forbid(unsafe_code)]
//! Bounded sans-I/O reference for direct-UniFi controller negotiation.
//!
//! The core state machine accepts already-decoded WebSocket message bytes, a
//! stable controller identity, timestamps and local write outcomes. Its
//! networking submodules perform explicitly task-owned I/O; they do not open a
//! authenticate a peer or grant camera control authority.
//! A correlated agreement reply is a protocol observation, not proof of
//! camera identity, adoption, a live stream, or source continuity.
//!
//! Wire behavior is modeled from `xuio/scrypted-unifi-direct` commit
//! `2920ce8896aadd603e2847d17554905592d155e8`; actual device and transport
//! compatibility remain separate qualification work.

use std::{collections::BTreeMap, fmt, net::SocketAddrV4};

use fss_core::json_input::{self, Value};

/// Authorized ledgered FLV evidence publication.
pub mod archive;
/// Bounded camera-local HTTPS request/response state without transport or trust policy.
pub mod camera_api;
/// Task-scoped, bounded camera-local HTTP over an independently admitted transport.
pub mod camera_http;
/// Task-scoped, policy-admitted controller TCP listener.
pub mod controller_listener;
/// Experimental owned hello, agreement and stream-request conversation.
pub mod conversation;
/// Bounded owner-scoped UniFi LAN discovery.
pub mod discovery;
/// Source-linked FLV segment evidence graph preparation.
pub mod evidence;
/// Inert, exact controller-address handoff planning.
pub mod handoff;
/// Source-preserving TCP-to-extended-FLV ingress boundary.
pub mod ingress;
/// Exact inert stream-setting effect intent.
pub mod intent;
/// Bounded task-scoped media listener with caller-supplied peer admission.
pub mod listener;
/// Exact inert controller-association and clock effect intent.
pub mod management;
/// Task-scoped byte admission for controller transport I/O.
pub mod metered;
/// Bounded task-owned WebSocket upgrade orchestration.
pub mod owner;
/// Bounded task-owned TCP ingress to in-memory recording pipeline.
pub mod pipeline;
/// Bounded WebSocket-to-controller observation owner.
pub mod receive;
/// Bounded source-preserving FLV-to-MP4 segment owner.
pub mod recording;
/// Task-owned discovery-candidate handoff orchestration.
pub mod setup;
pub mod supervisor;
/// Bounded, untrusted camera WebSocket upgrade preparation.
pub mod upgrade;

/// Maximum incoming management message size before JSON parsing.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Exact integer ceiling interoperable with the reference's JavaScript numbers.
pub const MAX_MESSAGE_ID: u64 = 9_007_199_254_740_991;
/// Conservative minimum owner-measured delay after the local hello write.
pub const AGREEMENT_DELAY_NS: u64 = 500_000_000;

/// Static, payload-free failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input exceeds its bound, is not UTF-8, or is not strict bounded JSON.
    InvalidJson,
    /// Required envelope fields or their exact types and bounds are invalid.
    InvalidEnvelope,
    /// The message is incompatible with the current protocol state.
    UnexpectedMessage,
    /// A required response is not pending, or another message is already prepared.
    InvalidState,
    /// A second time-sync request cannot fit in the single bounded pending slot.
    TimeSyncLimit,
    /// Prepared message identity did not match the supplied dispatch receipt.
    WrongPreparedMessage,
    /// The controller identity or output timestamp is not within the allowed syntax.
    InvalidConfiguration,
    /// The owner-reported interval after the hello write is shorter than the required delay.
    AgreementTooEarly,
    /// Message identifiers are exhausted; they never wrap or repeat.
    MessageIdExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "direct UniFi control refusal: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Controller-side protocol observation state; none proves peer authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No camera hello has been observed.
    AwaitHello,
    /// A camera hello was observed and requires a reply.
    HelloObserved,
    /// The hello reply was written locally; agreement may now be prepared.
    AwaitAgreementPreparation,
    /// The agreement was written locally and its correlated reply is outstanding.
    AwaitAgreementReply,
    /// A correlated agreement reply was observed, without an adoption/authentication claim.
    AgreementReplyObserved,
    /// A write may have occurred; the owner must reconcile or retire the session.
    Indeterminate,
    /// The owner retired this state machine.
    Closed,
}

/// Payload-free type of a known management message rejected for its state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedMessage {
    /// Camera hello.
    Hello,
    /// Camera time-sync request.
    TimeSync,
    /// Agreement response.
    Agreement,
    /// Video-settings response.
    VideoSettings,
}

/// Sanitized classification of one incoming management envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// Camera hello request; its ID and protocol version are retained internally.
    Hello,
    /// Camera requested time synchronization; one bounded reply slot is reserved.
    TimeSyncRequested,
    /// A reply matched the outstanding agreement's function and request ID.
    AgreementReply,
    /// A correlated settings reply. The optional status fields are untrusted
    /// observations, not proof that a stream is active or the change succeeded.
    StreamSettingsReply {
        /// Controller-local ID of the stream-start request.
        request_id: u64,
        /// The only requested video track.
        channel: VideoChannel,
        /// Uninterpreted optional camera status code.
        status_code: Option<i64>,
        /// Uninterpreted optional camera success field.
        success: Option<bool>,
    },
    /// A different function was not interpreted or echoed.
    Other,
}

/// Typed management messages this reference can prepare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Correlated hello response.
    HelloReply,
    /// Controller request for parameter agreement.
    AgreementRequest,
    /// Correlated time-sync response.
    TimeSyncReply,
    /// Request to change one track's serializer destination.
    StartStream(VideoChannel),
}

/// The camera video track targeted by a stream-start effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoChannel {
    /// First video track.
    Video1,
    /// Second video track.
    Video2,
    /// Third video track.
    Video3,
}

impl VideoChannel {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Video1 => "video1",
            Self::Video2 => "video2",
            Self::Video3 => "video3",
        }
    }
}

/// Selected video serializer codec, not a claim of camera support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoCodec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
}

/// Selected audio serializer mode, not a claim of camera support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioCodec {
    /// Reference mode with Opus disabled.
    Aac,
    /// Reference mode requesting Opus at 48 kHz.
    Opus,
}

/// Caller-authorized parameters for one remote stream-start effect.
///
/// Construction establishes syntax only. The caller must authorize the camera,
/// destination, track, codec, other consumers, and shared audio settings and
/// retain the exact request for reconciliation. The stream name is caller-owned
/// entropy; this module neither generates it nor claims it authenticates a peer.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamStart {
    channel: VideoChannel,
    destination: SocketAddrV4,
    video: VideoCodec,
    audio: AudioCodec,
    stream_name: String,
}

impl StreamStart {
    /// Validate a literal IPv4 destination and a 16-character lowercase hex name.
    /// This does not check reachability, network policy, or entropy quality.
    pub fn new(
        channel: VideoChannel,
        destination: SocketAddrV4,
        video: VideoCodec,
        audio: AudioCodec,
        stream_name: &str,
    ) -> Result<Self, Error> {
        let ip = destination.ip();
        if destination.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || stream_name.len() != 16
            || !stream_name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            channel,
            destination,
            video,
            audio,
            stream_name: stream_name.to_owned(),
        })
    }
}

impl fmt::Debug for StreamStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamStart")
            .field("channel", &self.channel)
            .field("video", &self.video)
            .field("audio", &self.audio)
            .finish_non_exhaustive()
    }
}

/// Local transport outcome supplied by the owning I/O boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dispatch {
    /// The owner proved that no bytes were written; the exact prepared bytes remain retryable.
    NotWritten,
    /// All message bytes were accepted by the local transport; peer receipt is not proved.
    Written,
    /// Some bytes may have been written; automatic retry is unsafe.
    Indeterminate,
}

/// Payload-free retirement information that the owner must reconcile or retain.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retirement {
    /// The state immediately before retirement, including an uncertain write.
    pub previous_phase: Phase,
    /// Known message type rejected for its state, without its payload.
    pub rejected_message: Option<RejectedMessage>,
    /// Unresolved prepared message ID and kind, if present.
    pub prepared: Option<(u64, MessageKind)>,
    /// Outstanding agreement request ID whose reply was not observed.
    pub agreement_id: Option<u64>,
    /// Observed hello request awaiting a locally written reply, if any.
    pub hello_request_id: Option<u64>,
    /// Observed time-sync request awaiting a locally written reply, if any.
    pub time_sync_request_id: Option<u64>,
    /// Locally written stream request for which no matching reply was observed.
    pub stream_request: Option<(u64, VideoChannel)>,
}

/// Exact owner-supplied controller identity; strings are validated before use.
#[derive(Clone, Eq, PartialEq)]
pub struct Identity {
    name: String,
    uuid: String,
    version: String,
}

impl Identity {
    /// Build a stable identity. UUID is 36 hexadecimal/hyphen characters in UUID layout;
    /// names/versions are bounded safe ASCII and cannot inject JSON syntax.
    pub fn new(name: &str, uuid: &str, version: &str) -> Result<Self, Error> {
        let safe = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.'))
        };
        let valid_uuid = uuid.len() == 36
            && uuid.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        if !safe(name) || !safe(version) || !valid_uuid {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            name: name.to_owned(),
            uuid: uuid.to_owned(),
            version: version.to_owned(),
        })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

/// Prepared JSON bytes, held stable until the owner resolves the dispatch outcome.
#[derive(Eq, PartialEq)]
pub struct PreparedMessage {
    id: u64,
    kind: MessageKind,
    bytes: Vec<u8>,
}

impl PreparedMessage {
    /// Controller-local request/message identifier.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// The only operation represented by these bytes.
    pub fn kind(&self) -> MessageKind {
        self.kind
    }
    /// Borrow the exact JSON message; framing and I/O remain the owner's responsibility.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PreparedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedMessage")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// One owner-driven session. No socket, clock, task, or peer identity is held.
pub struct Controller {
    identity: Identity,
    phase: Phase,
    next_id: Option<u64>,
    hello: Option<(u64, u32)>,
    time_sync: Option<u64>,
    agreement_id: Option<u64>,
    stream_request: Option<(u64, VideoChannel)>,
    prepared: Option<PreparedMessage>,
    rejected_message: Option<RejectedMessage>,
}

impl fmt::Debug for Controller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Controller")
            .field("phase", &self.phase)
            .field("has_time_sync", &self.time_sync.is_some())
            .field("prepared", &self.prepared)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// Start an isolated session with an explicitly supplied first controller ID.
    pub fn new(identity: Identity, first_message_id: u64) -> Result<Self, Error> {
        if !(1..=MAX_MESSAGE_ID).contains(&first_message_id) {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            identity,
            phase: Phase::AwaitHello,
            next_id: Some(first_message_id),
            hello: None,
            time_sync: None,
            agreement_id: None,
            stream_request: None,
            prepared: None,
            rejected_message: None,
        })
    }

    /// Current local protocol state, independent of physical camera health.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Exact outstanding local message, if one was prepared.
    pub fn prepared(&self) -> Option<&PreparedMessage> {
        self.prepared.as_ref()
    }

    /// Parse one complete WebSocket message, never retaining its raw JSON or payload.
    pub fn observe(&mut self, bytes: &[u8]) -> Result<Observation, Error> {
        self.rejected_message = None;
        if matches!(self.phase, Phase::Indeterminate | Phase::Closed) {
            return Err(Error::InvalidState);
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::InvalidJson);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
        let parsed = json_input::parse(text).map_err(|_| Error::InvalidJson)?;
        let fields = parsed.object().ok_or(Error::InvalidEnvelope)?;
        if text_field(fields, "from")? != "ubnt_avclient"
            || text_field(fields, "to")? != "UniFiVideo"
        {
            return Err(Error::InvalidEnvelope);
        }
        let name = text_field(fields, "functionName")?;
        if name.is_empty()
            || name.len() > 96
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::InvalidEnvelope);
        }
        let id = number(fields, "messageId", false)?;
        let response_to = if fields.contains_key("inResponseTo") {
            number(fields, "inResponseTo", true)?
        } else {
            0
        };
        if let Some(value) = fields.get("responseExpected")
            && value.boolean().is_none()
        {
            return Err(Error::InvalidEnvelope);
        }
        match name {
            "ubnt_avclient_hello" => {
                if self.phase != Phase::AwaitHello || response_to != 0 {
                    self.rejected_message = Some(RejectedMessage::Hello);
                    return Err(Error::UnexpectedMessage);
                }
                let version = match fields.get("payload") {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(payload)) => payload.get("protocolVersion"),
                    Some(_) => return Err(Error::InvalidEnvelope),
                };
                let protocol = match version {
                    None | Some(Value::Null) => 67,
                    Some(Value::Number(value)) => match value.parse::<u32>() {
                        Ok(0) => 67,
                        Ok(n) if n <= 65_535 => n,
                        _ => return Err(Error::InvalidEnvelope),
                    },
                    Some(_) => return Err(Error::InvalidEnvelope),
                };
                self.hello = Some((id, protocol));
                self.phase = Phase::HelloObserved;
                Ok(Observation::Hello)
            }
            "ubnt_avclient_timeSync" => {
                // A correlated time-sync is a camera reply, not a fresh
                // request. Never resolve a local operation from it or reply
                // again; doing so can create an endless response loop.
                if response_to != 0 {
                    return Ok(Observation::Other);
                }
                if self.time_sync.is_some() {
                    return Err(Error::TimeSyncLimit);
                }
                self.time_sync = Some(id);
                Ok(Observation::TimeSyncRequested)
            }
            "ubnt_avclient_paramAgreement" => {
                if self.phase != Phase::AwaitAgreementReply
                    || self.agreement_id != Some(response_to)
                {
                    self.rejected_message = Some(RejectedMessage::Agreement);
                    return Err(Error::UnexpectedMessage);
                }
                self.agreement_id = None;
                self.phase = Phase::AgreementReplyObserved;
                Ok(Observation::AgreementReply)
            }
            "ChangeVideoSettings" => {
                let Some((request_id, channel)) = self.stream_request else {
                    self.rejected_message = Some(RejectedMessage::VideoSettings);
                    return Err(Error::UnexpectedMessage);
                };
                if self.phase != Phase::AgreementReplyObserved || response_to != request_id {
                    self.rejected_message = Some(RejectedMessage::VideoSettings);
                    return Err(Error::UnexpectedMessage);
                }
                let payload = match fields.get("payload") {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(payload)) => Some(payload),
                    Some(_) => return Err(Error::InvalidEnvelope),
                };
                let status_code = match payload.and_then(|p| p.get("statusCode")) {
                    None | Some(Value::Null) => None,
                    Some(Value::Number(raw)) => {
                        Some(raw.parse::<i64>().map_err(|_| Error::InvalidEnvelope)?)
                    }
                    Some(_) => return Err(Error::InvalidEnvelope),
                };
                let success = match payload.and_then(|p| p.get("success")) {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(v.boolean().ok_or(Error::InvalidEnvelope)?),
                };
                self.stream_request = None;
                Ok(Observation::StreamSettingsReply {
                    request_id,
                    channel,
                    status_code,
                    success,
                })
            }
            _ => Ok(Observation::Other),
        }
    }

    /// Prepare the exact hello response without writing it.
    pub fn prepare_hello(&mut self, timestamp: &str) -> Result<&PreparedMessage, Error> {
        if self.phase != Phase::HelloObserved {
            return Err(Error::InvalidState);
        }
        let (request_id, protocol) = self.hello.ok_or(Error::InvalidState)?;
        let payload = format!(
            "{{\"protocolVersion\":{protocol},\"controllerName\":\"{}\",\"controllerUuid\":\"{}\",\"controllerVersion\":\"{}\",\"overrideUuid\":true}}",
            self.identity.name, self.identity.uuid, self.identity.version
        );
        self.prepare(
            MessageKind::HelloReply,
            "ubnt_avclient_hello",
            request_id,
            false,
            &payload,
            timestamp,
        )
    }

    /// Prepare the parameter-agreement request without writing it.
    ///
    /// The owner supplies the monotonic elapsed time since the hello reply was
    /// fully written locally. This reference does not read or verify a clock.
    pub fn prepare_agreement(
        &mut self,
        timestamp: &str,
        elapsed_ns: u64,
    ) -> Result<&PreparedMessage, Error> {
        if self.phase != Phase::AwaitAgreementPreparation {
            return Err(Error::InvalidState);
        }
        if elapsed_ns < AGREEMENT_DELAY_NS {
            return Err(Error::AgreementTooEarly);
        }
        self.prepare(
            MessageKind::AgreementRequest,
            "ubnt_avclient_paramAgreement",
            0,
            true,
            "{\"enableStatusCodes\":true,\"useHeartbeats\":false,\"heartbeatsTimeoutMs\":60000}",
            timestamp,
        )
    }

    /// Prepare one time-sync reply using an explicitly supplied wall-clock value.
    pub fn prepare_time_sync(
        &mut self,
        wall_ms: u64,
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        let request_id = self.time_sync.ok_or(Error::InvalidState)?;
        if wall_ms > MAX_MESSAGE_ID {
            return Err(Error::InvalidConfiguration);
        }
        let payload = format!("{{\"t1\":{wall_ms},\"t2\":{wall_ms}}}");
        self.prepare(
            MessageKind::TimeSyncReply,
            "ubnt_avclient_timeSync",
            request_id,
            false,
            &payload,
            timestamp,
        )
    }

    /// Prepare a one-track serializer change without writing it.
    ///
    /// This can interrupt the targeted track or affect the camera's shared audio
    /// encoder. It does not quiesce other tracks, authorize the effect, confirm
    /// device support, bind a listener, or prove that any video was delivered.
    /// Only one stream-setting reply may be outstanding. The owner must retain
    /// `request` and the prepared ID across dispatch and reconciliation.
    pub fn prepare_stream_start(
        &mut self,
        request: &StreamStart,
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        if self.phase != Phase::AgreementReplyObserved || self.stream_request.is_some() {
            return Err(Error::InvalidState);
        }
        let video = match request.video {
            VideoCodec::H264 => "h264",
            VideoCodec::H265 => "h265",
        };
        let audio = match request.audio {
            AudioCodec::Aac => "\"withOpus\":false",
            AudioCodec::Opus => "\"withOpus\":true,\"opusSampleRate\":48000",
        };
        let payload = format!(
            "{{\"video\":{{\"{}\":{{\"avSerializer\":{{\"type\":\"extendedFlv\",\"parameters\":{{\"streamName\":\"{}\",{audio}}},\"destinations\":[\"tcp://{}?retryInterval=1&connectTimeout=5\"]}},\"type\":\"{video}\"}}}}}}",
            request.channel.wire_name(),
            request.stream_name,
            request.destination
        );
        self.prepare(
            MessageKind::StartStream(request.channel),
            "ChangeVideoSettings",
            0,
            true,
            &payload,
            timestamp,
        )
    }

    fn prepare(
        &mut self,
        kind: MessageKind,
        function: &str,
        response_to: u64,
        expected: bool,
        payload: &str,
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        if matches!(self.phase, Phase::Indeterminate | Phase::Closed) || self.prepared.is_some() {
            return Err(Error::InvalidState);
        }
        if !valid_timestamp(timestamp) {
            return Err(Error::InvalidConfiguration);
        }
        let id = self.next_id.ok_or(Error::MessageIdExhausted)?;
        let bytes = format!("{{\"from\":\"UniFiVideo\",\"to\":\"ubnt_avclient\",\"functionName\":\"{function}\",\"inResponseTo\":{response_to},\"messageId\":{id},\"payload\":{payload},\"responseExpected\":{expected},\"timeStamp\":\"{timestamp}\"}}").into_bytes();
        self.next_id = if id == MAX_MESSAGE_ID {
            None
        } else {
            Some(id + 1)
        };
        self.prepared = Some(PreparedMessage { id, kind, bytes });
        self.prepared.as_ref().ok_or(Error::InvalidState)
    }

    /// Record the owner's exact local write outcome. A mismatched ID changes nothing.
    pub fn finish_dispatch(&mut self, id: u64, outcome: Dispatch) -> Result<(), Error> {
        if matches!(self.phase, Phase::Closed | Phase::Indeterminate) {
            return Err(Error::InvalidState);
        }
        let prepared = self.prepared.as_ref().ok_or(Error::InvalidState)?;
        if prepared.id != id {
            return Err(Error::WrongPreparedMessage);
        }
        match outcome {
            Dispatch::NotWritten => Ok(()),
            Dispatch::Indeterminate => {
                self.phase = Phase::Indeterminate;
                Ok(())
            }
            Dispatch::Written => {
                match prepared.kind {
                    MessageKind::HelloReply => {
                        self.hello = None;
                        self.phase = Phase::AwaitAgreementPreparation;
                    }
                    MessageKind::AgreementRequest => {
                        self.agreement_id = Some(id);
                        self.phase = Phase::AwaitAgreementReply;
                    }
                    MessageKind::TimeSyncReply => {
                        self.time_sync = None;
                    }
                    MessageKind::StartStream(channel) => {
                        self.stream_request = Some((id, channel));
                    }
                }
                self.prepared = None;
                Ok(())
            }
        }
    }

    /// Retire transient state and return unresolved facts for the owner to retain.
    /// Closing never asserts a remote effect was undone.
    pub fn close(&mut self) -> Retirement {
        let retirement = Retirement {
            previous_phase: self.phase,
            rejected_message: self.rejected_message,
            prepared: self.prepared.as_ref().map(|m| (m.id, m.kind)),
            agreement_id: self.agreement_id,
            hello_request_id: self.hello.map(|hello| hello.0),
            time_sync_request_id: self.time_sync,
            stream_request: self.stream_request,
        };
        self.prepared = None;
        self.hello = None;
        self.time_sync = None;
        self.agreement_id = None;
        self.stream_request = None;
        self.rejected_message = None;
        self.phase = Phase::Closed;
        retirement
    }
}

fn text_field<'a>(fields: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, Error> {
    fields
        .get(key)
        .and_then(Value::text)
        .ok_or(Error::InvalidEnvelope)
}

fn number(fields: &BTreeMap<String, Value>, key: &str, allow_zero: bool) -> Result<u64, Error> {
    let Some(Value::Number(raw)) = fields.get(key) else {
        return Err(Error::InvalidEnvelope);
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidEnvelope);
    }
    let value = raw.parse::<u64>().map_err(|_| Error::InvalidEnvelope)?;
    if value > MAX_MESSAGE_ID || (!allow_zero && value == 0) {
        return Err(Error::InvalidEnvelope);
    }
    Ok(value)
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        4 | 7 => b == b'-',
        10 => b == b'T',
        13 | 16 => b == b':',
        19 => b == b'.',
        23 => b == b'Z',
        _ => b.is_ascii_digit(),
    })
}
