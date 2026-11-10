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
/// Source-preserving collection of the first A/V archive inputs.
pub mod av_bootstrap;
/// Task-owned supervisor-to-bootstrap collection and audio-event pairing.
pub mod av_bootstrap_driver;
/// Source-linked A/V evidence graph preparation.
pub mod av_evidence;
/// Owned A/V archival inputs suitable for a separately supervised worker.
pub mod av_owned_sink;
/// Transactional, source-preserving A/V fragment derivation.
pub mod av_recording;
/// Bounded ownership handoff from the session loop to its caller.
pub mod av_session_inbox;
/// Bounded ownership and backpressure for A/V archive handoff.
pub mod av_sink;
/// Supervisor bridge to the unknown-capture-time archive worker.
pub mod av_unknown_worker_guard;
/// Region-owned asynchronous handoff to the archival persistence worker.
pub mod av_worker;
/// Supervised camera-to-worker handoff with bounded backpressure.
pub mod av_worker_guard;
/// Task-owned, bounded local D-Bus observation for future BlueZ transport.
pub mod bluez_bus;
/// Task-owned BlueZ scan and claim-projection lifecycle.
pub mod bluez_monitor;
/// Bounded reconciliation of scoped BlueZ inventory and device changes.
pub mod bluez_registry;
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
/// Source-preserving camera event observations and bounded interpretation.
pub mod events;
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
/// Inert, digest-bound motion-setting effect intent.
pub mod motion;
/// Bounded task-owned WebSocket upgrade orchestration.
pub mod owner;
/// Bounded task-owned TCP ingress to in-memory recording pipeline.
pub mod pipeline;
/// Bounded WebSocket-to-controller observation owner.
pub mod receive;
/// Bounded source-preserving FLV-to-MP4 segment owner.
pub mod recording;
/// Owns direct-camera bootstrap and recording as one task-scoped session.
pub mod recording_session;
/// Fresh, task-authorized storage for a direct recording session.
pub mod recording_storage;
/// Task-owned discovery-candidate handoff orchestration.
pub mod setup;
/// Source-aware session and archive coordination.
pub mod source_coordinator;
/// Exact standalone source-record evidence for separately returned media.
pub mod source_evidence;
/// Custody-preserving handoff from session events to standalone source storage.
pub mod source_handoff;
/// Task-owned durable publication of separately returned source records.
pub mod source_worker;
pub mod supervisor;
/// Bounded, untrusted camera WebSocket upgrade preparation.
pub mod upgrade;

/// Maximum incoming management message size before JSON parsing.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Exact integer ceiling interoperable with the reference's JavaScript numbers.
pub const MAX_MESSAGE_ID: u64 = 9_007_199_254_740_991;
/// Conservative minimum owner-measured delay after the local hello write.
pub const AGREEMENT_DELAY_NS: u64 = 500_000_000;
const MAX_OPT_IN_TIME_SYNC_REPLIES: usize = 8;
const MAX_EVENT_REPLIES: usize = 64;
/// Maximum replies in the explicitly selected pre-hello clock exchange.
pub const MAX_PRE_HELLO_TIME_SYNC_REPLIES: usize = 32;

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
    /// The single pending time-sync slot or the opt-in reply bound is exhausted.
    TimeSyncLimit,
    /// An event or startup-request reply is pending, repeated, or exceeds the bound.
    EventReplyLimit,
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
    /// Motion-settings response.
    MotionSettings,
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
        /// Controller-local ID of the stream-setting request.
        request_id: u64,
        /// The only requested video track.
        channel: VideoChannel,
        /// The locally requested start or quiesce operation.
        kind: MessageKind,
        /// Uninterpreted optional camera status code.
        status_code: Option<i64>,
        /// Uninterpreted optional camera success field.
        success: Option<bool>,
    },
    /// A correlated motion-settings reply, without asserting the effect succeeded.
    MotionSettingsReply {
        /// Controller-local request ID.
        request_id: u64,
        /// Requested motion enable state.
        enabled: bool,
        /// Untrusted optional status code.
        status_code: Option<i64>,
        /// Untrusted optional success field.
        success: Option<bool>,
    },
    /// A camera-originated event claim. Its payload is retained by the
    /// receiving owner when event capture is enabled, not by this value.
    CameraEvent {
        /// Bounded event category; unknown event names remain in source bytes.
        kind: events::Kind,
        /// Untrusted camera-provided message identity.
        message_id: u64,
        /// The camera requested a reply; this observation does not send one.
        response_expected: bool,
    },
    /// An opt-in, uncorrelated unknown startup request requiring a reply.
    /// Its exact source must be retained by the caller before proceeding.
    StartupRequest {
        /// Untrusted camera message identifier.
        message_id: u64,
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
    /// Correlated reply to a separately observed camera event.
    EventReply,
    /// Correlated reply to an explicitly captured unknown startup request.
    StartupRequestReply,
    /// Request to change one track's serializer destination.
    StartStream(VideoChannel),
    /// Request to route one track's serializer to the discard sink.
    QuiesceStream(VideoChannel),
    /// Request to enable or disable baseline motion detection.
    SetMotion(bool),
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

/// Local identity of a prepared stream request abandoned before any write.
/// This does not settle a separately committed effect or prove remote state.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbandonedStream {
    /// The never-reused local message ID.
    pub id: u64,
    /// The abandoned start or quiesce request.
    pub kind: MessageKind,
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
    /// The kind of that outstanding request, if known.
    pub stream_request_kind: Option<MessageKind>,
    /// Motion request whose reply has not been observed.
    pub motion_request: Option<(u64, bool)>,
    /// Observed event or opt-in startup request awaiting a reply or omission.
    pub event_reply: Option<(u64, fss_core::ContentDigest)>,
    /// Whether that outstanding source was an unknown startup request.
    pub event_reply_is_startup_request: bool,
    /// Payload-free counts of unhandled response-request claims on this session.
    pub unhandled_requests: UnhandledRequestCounts,
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
    source: Option<fss_core::ContentDigest>,
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
    /// Exact observed event source, if this is an event reply.
    pub fn source_digest(&self) -> Option<fss_core::ContentDigest> {
        self.source
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

/// Payload-free counts of valid camera time-sync messages on one session.
/// Correlation and response expectation are untrusted protocol claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimeSyncCounts {
    /// Messages with a zero or absent `inResponseTo` field.
    pub uncorrelated: u32,
    /// Messages with a nonzero `inResponseTo` field.
    pub correlated: u32,
    /// Correlated messages explicitly asserting `responseExpected: true`.
    pub correlated_response_expected: u32,
    /// Correlated messages referring to the most recent locally written reply.
    pub correlated_to_last_written_reply: u32,
    /// Such messages that also explicitly assert `responseExpected: true`.
    pub correlated_expected_to_last_written_reply: u32,
}

/// Saturating counts of valid, uninterpreted messages that asked for a reply.
/// These are untrusted claims and neither retain payloads nor authorize replies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnhandledRequestCounts {
    /// Requests seen before any hello was accepted.
    pub pre_hello: u32,
    /// Requests seen after the pre-hello phase.
    pub later: u32,
    /// Requests carrying a nonzero correlation ID, included in the totals above.
    pub correlated: u32,
}

/// Explicit policy for ambiguous correlated camera time-sync messages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TimeSyncPolicy {
    /// Ignore every correlated message, preserving the conservative default.
    #[default]
    UncorrelatedOnly,
    /// Also treat a correlated message as a request when it explicitly says
    /// `responseExpected: true`. This untrusted flag does not prove intent;
    /// messages correlated to one of our own time-sync replies are ignored,
    /// and at most eight replies are admitted. The owner must retain its
    /// existing effect, rate and message limits.
    ExplicitCorrelatedRequests,
    /// Permit bounded, fresh uncorrelated pre-hello requests and a clock
    /// exchange correlated to the preceding locally written reply. This is
    /// experimental, does not authenticate the peer, and grants no authority.
    /// A distinct operation and a live admission are still required for each
    /// reply. Duplicate camera message IDs and exchanges over 32 replies stop.
    /// The exchange was reported for a different camera model in
    /// <https://github.com/rjmotion/cuckoo/blob/2e18666e9d9998b31d908e3a8f1d9ebb658c467f/controller.py>;
    /// compatibility with any particular device remains unproven.
    BoundedPreHelloClockExchange,
    /// Like `BoundedPreHelloClockExchange`, but also admits fresh requests
    /// correlated to an older or unknown reply before hello. This matches the
    /// broader reply behavior of reference implementations, but its usefulness
    /// with a particular camera is unproven. The 32-reply, replay, pending
    /// reply and per-effect admission limits remain in force.
    BoundedAnyPreHelloClockExchange,
    /// Permit fresh time-sync requests, including correlated requests, both
    /// before and after hello. At most 32 replies are allowed per chain; a
    /// fresh uncorrelated request starts a new chain. The 32 most recent
    /// request IDs remain replay-fenced across chains. This experimental
    /// policy grants no effect authority or rate limit: each reply still
    /// needs a distinct journaled operation and current task admission.
    BoundedContinuingClockExchange,
}

/// One owner-driven session. No socket, clock, task, or peer identity is held.
pub struct Controller {
    identity: Identity,
    phase: Phase,
    next_id: Option<u64>,
    hello: Option<(u64, u32)>,
    time_sync: Option<u64>,
    agreement_id: Option<u64>,
    stream_request: Option<(u64, MessageKind)>,
    motion_request: Option<(u64, bool)>,
    prepared: Option<PreparedMessage>,
    rejected_message: Option<RejectedMessage>,
    time_sync_counts: TimeSyncCounts,
    unhandled_requests: UnhandledRequestCounts,
    time_sync_policy: TimeSyncPolicy,
    time_sync_reply_ids: [u64; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
    time_sync_request_ids: [u64; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
    time_sync_reply_count: usize,
    last_written_time_sync_reply: Option<u64>,
    pending_pre_hello_sync: bool,
    continuing_clock: Option<Box<ContinuingClock>>,
    event_reply: Option<(u64, fss_core::ContentDigest)>,
    event_reply_is_startup_request: bool,
    replied_event_ids: [u64; MAX_EVENT_REPLIES],
    replied_event_count: usize,
}

struct ContinuingClock {
    request_ids: [u64; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
    request_len: usize,
    request_next: usize,
    chain_replies: usize,
    pending: bool,
}

impl fmt::Debug for Controller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Controller")
            .field("phase", &self.phase)
            .field("time_sync_policy", &self.time_sync_policy)
            .field("has_time_sync", &self.time_sync.is_some())
            .field("prepared", &self.prepared)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// Start an isolated session with an explicitly supplied first controller ID.
    pub fn new(identity: Identity, first_message_id: u64) -> Result<Self, Error> {
        Self::new_with_time_sync_policy(identity, first_message_id, TimeSyncPolicy::default())
    }

    /// Start with an explicit time-sync policy for this one controller session.
    /// Selecting a policy grants no network, clock, or management authority.
    pub fn new_with_time_sync_policy(
        identity: Identity,
        first_message_id: u64,
        time_sync_policy: TimeSyncPolicy,
    ) -> Result<Self, Error> {
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
            motion_request: None,
            prepared: None,
            rejected_message: None,
            time_sync_counts: TimeSyncCounts::default(),
            unhandled_requests: UnhandledRequestCounts::default(),
            time_sync_policy,
            time_sync_reply_ids: [0; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
            time_sync_request_ids: [0; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
            time_sync_reply_count: 0,
            last_written_time_sync_reply: None,
            pending_pre_hello_sync: false,
            continuing_clock: (time_sync_policy == TimeSyncPolicy::BoundedContinuingClockExchange)
                .then(|| {
                    Box::new(ContinuingClock {
                        request_ids: [0; MAX_PRE_HELLO_TIME_SYNC_REPLIES],
                        request_len: 0,
                        request_next: 0,
                        chain_replies: 0,
                        pending: false,
                    })
                }),
            event_reply: None,
            event_reply_is_startup_request: false,
            replied_event_ids: [0; MAX_EVENT_REPLIES],
            replied_event_count: 0,
        })
    }

    /// Current local protocol state, independent of physical camera health.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Payload-free time-sync observations; these do not prove message delivery.
    pub fn time_sync_counts(&self) -> TimeSyncCounts {
        self.time_sync_counts
    }

    /// Counts of uninterpreted requests which asserted `responseExpected`.
    /// These do not include recognized messages and confer no reply authority.
    pub fn unhandled_request_counts(&self) -> UnhandledRequestCounts {
        self.unhandled_requests
    }

    /// Whether an observed event requires an explicit reply or omission.
    pub fn has_pending_event_reply(&self) -> bool {
        self.event_reply.is_some()
    }

    pub(crate) fn pending_event_reply(&self) -> Option<(u64, fss_core::ContentDigest)> {
        self.event_reply
    }

    /// Largest caller-supplied startup reply quota for this session policy.
    /// The caller must still supply a distinct authorized operation per reply.
    pub fn startup_time_sync_limit(&self) -> usize {
        if matches!(
            self.time_sync_policy,
            TimeSyncPolicy::BoundedPreHelloClockExchange
                | TimeSyncPolicy::BoundedAnyPreHelloClockExchange
                | TimeSyncPolicy::BoundedContinuingClockExchange
        ) {
            MAX_PRE_HELLO_TIME_SYNC_REPLIES
        } else {
            MAX_OPT_IN_TIME_SYNC_REPLIES
        }
    }

    /// Exact outstanding local message, if one was prepared.
    pub fn prepared(&self) -> Option<&PreparedMessage> {
        self.prepared.as_ref()
    }

    /// Parse one complete WebSocket message, never retaining its raw JSON or payload.
    pub fn observe(&mut self, bytes: &[u8]) -> Result<Observation, Error> {
        self.observe_inner(bytes, false, false)
    }

    /// Parse a message and classify event claims. The caller must separately
    /// retain source bytes if it needs event custody; no event is verified.
    pub fn observe_event_claims(&mut self, bytes: &[u8]) -> Result<Observation, Error> {
        self.observe_inner(bytes, true, false)
    }

    /// Opt in to capturing uncorrelated, response-requesting unknown functions
    /// before hello. The caller must retain the exact source and separately
    /// authorize any reply; this does not authenticate the sender.
    pub fn observe_startup_requests(&mut self, bytes: &[u8]) -> Result<Observation, Error> {
        self.observe_inner(bytes, true, true)
    }

    fn observe_inner(
        &mut self,
        bytes: &[u8],
        event_claims: bool,
        startup_requests: bool,
    ) -> Result<Observation, Error> {
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
        let response_expected = match fields.get("responseExpected") {
            Some(value) => value.boolean().ok_or(Error::InvalidEnvelope)?,
            None => false,
        };
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
                // Blindly echoing correlated replies can create a response loop.
                // Opt-in policies retain finite quotas and the single
                // pending-reply slot. Only the continuing policy applies after hello.
                let pre_hello_exchange = matches!(
                    self.time_sync_policy,
                    TimeSyncPolicy::BoundedPreHelloClockExchange
                        | TimeSyncPolicy::BoundedAnyPreHelloClockExchange
                ) && self.phase == Phase::AwaitHello;
                let continuing_exchange =
                    self.time_sync_policy == TimeSyncPolicy::BoundedContinuingClockExchange;
                if response_to != 0 {
                    self.time_sync_counts.correlated =
                        self.time_sync_counts.correlated.saturating_add(1);
                    let to_last_written = self.last_written_time_sync_reply == Some(response_to);
                    if to_last_written {
                        self.time_sync_counts.correlated_to_last_written_reply = self
                            .time_sync_counts
                            .correlated_to_last_written_reply
                            .saturating_add(1);
                    }
                    if response_expected {
                        self.time_sync_counts.correlated_response_expected = self
                            .time_sync_counts
                            .correlated_response_expected
                            .saturating_add(1);
                        if to_last_written {
                            self.time_sync_counts
                                .correlated_expected_to_last_written_reply = self
                                .time_sync_counts
                                .correlated_expected_to_last_written_reply
                                .saturating_add(1);
                        }
                    }
                    if !continuing_exchange && pre_hello_exchange {
                        if self.time_sync_policy == TimeSyncPolicy::BoundedPreHelloClockExchange
                            && self.time_sync_reply_count > 0
                            && self.time_sync_reply_ids[self.time_sync_reply_count - 1]
                                != response_to
                        {
                            return Ok(Observation::Other);
                        }
                    } else if !continuing_exchange {
                        if self.time_sync_reply_ids[..self.time_sync_reply_count]
                            .contains(&response_to)
                        {
                            return Ok(Observation::Other);
                        }
                        if !response_expected
                            || self.time_sync_policy != TimeSyncPolicy::ExplicitCorrelatedRequests
                        {
                            return Ok(Observation::Other);
                        }
                    }
                } else {
                    self.time_sync_counts.uncorrelated =
                        self.time_sync_counts.uncorrelated.saturating_add(1);
                }
                if self.time_sync_policy == TimeSyncPolicy::ExplicitCorrelatedRequests
                    && self.time_sync_reply_count == MAX_OPT_IN_TIME_SYNC_REPLIES
                {
                    return Err(Error::TimeSyncLimit);
                }
                if self.time_sync.is_some() {
                    return Err(Error::TimeSyncLimit);
                }
                if continuing_exchange {
                    let clock = self
                        .continuing_clock
                        .as_mut()
                        .expect("continuing clock policy state");
                    if clock.request_ids[..clock.request_len].contains(&id) {
                        return Err(Error::UnexpectedMessage);
                    }
                    if response_to == 0 {
                        clock.chain_replies = 0;
                    }
                    if clock.chain_replies == MAX_PRE_HELLO_TIME_SYNC_REPLIES {
                        return Err(Error::TimeSyncLimit);
                    }
                    clock.request_ids[clock.request_next] = id;
                    clock.request_next = (clock.request_next + 1) % MAX_PRE_HELLO_TIME_SYNC_REPLIES;
                    clock.request_len =
                        (clock.request_len + 1).min(MAX_PRE_HELLO_TIME_SYNC_REPLIES);
                    clock.pending = true;
                } else if pre_hello_exchange {
                    if self.time_sync_reply_count == MAX_PRE_HELLO_TIME_SYNC_REPLIES {
                        return Err(Error::TimeSyncLimit);
                    }
                    if self.time_sync_request_ids[..self.time_sync_reply_count].contains(&id) {
                        return Err(Error::UnexpectedMessage);
                    }
                    self.time_sync_request_ids[self.time_sync_reply_count] = id;
                    self.pending_pre_hello_sync = true;
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
                let Some((request_id, kind)) = self.stream_request else {
                    self.rejected_message = Some(RejectedMessage::VideoSettings);
                    return Err(Error::UnexpectedMessage);
                };
                let channel = match kind {
                    MessageKind::StartStream(channel) | MessageKind::QuiesceStream(channel) => {
                        channel
                    }
                    _ => return Err(Error::InvalidState),
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
                    kind,
                    status_code,
                    success,
                })
            }
            "ChangeSmartMotionSettings" => {
                let Some((request_id, enabled)) = self.motion_request else {
                    self.rejected_message = Some(RejectedMessage::MotionSettings);
                    return Err(Error::UnexpectedMessage);
                };
                if self.phase != Phase::AgreementReplyObserved || response_to != request_id {
                    self.rejected_message = Some(RejectedMessage::MotionSettings);
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
                self.motion_request = None;
                Ok(Observation::MotionSettingsReply {
                    request_id,
                    enabled,
                    status_code,
                    success,
                })
            }
            _ if event_claims && name.starts_with("Event") => {
                if response_expected && response_to == 0 {
                    if self.event_reply.is_some()
                        || self.replied_event_count == MAX_EVENT_REPLIES
                        || self.replied_event_ids[..self.replied_event_count].contains(&id)
                    {
                        return Err(Error::EventReplyLimit);
                    }
                    self.event_reply = Some((id, fss_core::ContentDigest::sha256(bytes)));
                    self.event_reply_is_startup_request = false;
                }
                Ok(Observation::CameraEvent {
                    kind: events::Kind::from_name(name),
                    message_id: id,
                    response_expected,
                })
            }
            _ if startup_requests
                && self.phase == Phase::AwaitHello
                && response_expected
                && response_to == 0 =>
            {
                if self.event_reply.is_some()
                    || self.replied_event_count == MAX_EVENT_REPLIES
                    || self.replied_event_ids[..self.replied_event_count].contains(&id)
                {
                    return Err(Error::EventReplyLimit);
                }
                self.event_reply = Some((id, fss_core::ContentDigest::sha256(bytes)));
                self.event_reply_is_startup_request = true;
                Ok(Observation::StartupRequest { message_id: id })
            }
            _ => {
                if response_expected {
                    let counts = &mut self.unhandled_requests;
                    if self.phase == Phase::AwaitHello {
                        counts.pre_hello = counts.pre_hello.saturating_add(1);
                    } else {
                        counts.later = counts.later.saturating_add(1);
                    }
                    if response_to != 0 {
                        counts.correlated = counts.correlated.saturating_add(1);
                    }
                }
                Ok(Observation::Other)
            }
        }
    }

    /// Prepare an echo only for the exact event or explicitly captured startup
    /// request observed by this controller. This is inert and confers no
    /// authority to send private data.
    pub fn prepare_event_reply(
        &mut self,
        source: &[u8],
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        let digest = fss_core::ContentDigest::sha256(source);
        let parts = events::reply_parts(source, self.event_reply_is_startup_request)?;
        if self.event_reply != Some((parts.message_id, digest)) {
            return Err(Error::InvalidState);
        }
        // Account for the bounded envelope before consuming a message ID.
        if parts
            .function
            .len()
            .checked_add(parts.payload.len())
            .and_then(|n| n.checked_add(timestamp.len()))
            .is_none_or(|n| n > MAX_MESSAGE_BYTES - 256)
        {
            return Err(Error::InvalidJson);
        }
        self.prepare(
            if self.event_reply_is_startup_request {
                MessageKind::StartupRequestReply
            } else {
                MessageKind::EventReply
            },
            &parts.function,
            parts.message_id,
            false,
            &parts.payload,
            timestamp,
        )?;
        let message = self.prepared.as_mut().ok_or(Error::InvalidState)?;
        message.source = Some(digest);
        Ok(message)
    }

    /// Explicitly omit an event or startup reply without claiming receipt.
    pub fn omit_event_reply(&mut self, source: fss_core::ContentDigest) -> Result<(), Error> {
        if self.prepared.is_some() || self.event_reply.is_none_or(|(_, digest)| digest != source) {
            return Err(Error::InvalidState);
        }
        let (id, _) = self.event_reply.take().ok_or(Error::InvalidState)?;
        self.event_reply_is_startup_request = false;
        self.replied_event_ids[self.replied_event_count] = id;
        self.replied_event_count += 1;
        Ok(())
    }

    /// Abandon only a locally unwritten event or startup reply. A committed
    /// permit still belongs to the caller and must be reconciled separately.
    pub fn abandon_event_reply(&mut self, source: fss_core::ContentDigest) -> Result<u64, Error> {
        let message = self.prepared.as_ref().ok_or(Error::InvalidState)?;
        if !matches!(
            message.kind,
            MessageKind::EventReply | MessageKind::StartupRequestReply
        ) || message.source != Some(source)
        {
            return Err(Error::InvalidState);
        }
        let mut message = self.prepared.take().ok_or(Error::InvalidState)?;
        message.bytes.fill(0);
        Ok(message.id)
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

    /// Prepare a one-track request that routes its serializer to the discard
    /// sink. The caller must authorize the track and shared audio mode. A
    /// correlated reply is not proof of delivery, restoration or inactivity.
    pub fn prepare_stream_quiesce(
        &mut self,
        channel: VideoChannel,
        audio: AudioCodec,
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        if self.phase != Phase::AgreementReplyObserved || self.stream_request.is_some() {
            return Err(Error::InvalidState);
        }
        let audio = match audio {
            AudioCodec::Aac => "\"withOpus\":false",
            AudioCodec::Opus => "\"withOpus\":true,\"opusSampleRate\":48000",
        };
        let payload = format!(
            "{{\"video\":{{\"{}\":{{\"avSerializer\":{{\"type\":\"extendedFlv\",\"parameters\":{{{audio}}},\"destinations\":[\"file:///dev/null\"]}}}}}}}}",
            channel.wire_name(),
        );
        self.prepare(
            MessageKind::QuiesceStream(channel),
            "ChangeVideoSettings",
            0,
            true,
            &payload,
            timestamp,
        )
    }

    /// Prepare a baseline motion-setting request for the supplied camera claim.
    /// The claim is not identity or authority; the caller must bind it to the
    /// admitted session and separately authorize the effect.
    pub fn prepare_motion(
        &mut self,
        mac: [u8; 6],
        enabled: bool,
        timestamp: &str,
    ) -> Result<&PreparedMessage, Error> {
        if self.phase != Phase::AgreementReplyObserved || self.motion_request.is_some() {
            return Err(Error::InvalidState);
        }
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::InvalidConfiguration);
        }
        let device_id: String = mac.iter().map(|b| format!("{b:02X}")).collect();
        let payload = format!("{{\"deviceID\":\"{device_id}\",\"enable\":{enabled}}}");
        self.prepare(
            MessageKind::SetMotion(enabled),
            "ChangeSmartMotionSettings",
            0,
            true,
            &payload,
            timestamp,
        )
    }

    /// Abandon a prepared stream request only when the owner knows no bytes
    /// were sent. This does not dispose of any journaled effect permit.
    pub fn abandon_prepared_stream(&mut self) -> Result<AbandonedStream, Error> {
        if self.phase != Phase::AgreementReplyObserved || self.stream_request.is_some() {
            return Err(Error::InvalidState);
        }
        let prepared = self.prepared.as_ref().ok_or(Error::InvalidState)?;
        if !matches!(
            prepared.kind,
            MessageKind::StartStream(_) | MessageKind::QuiesceStream(_)
        ) {
            return Err(Error::InvalidState);
        }
        let mut prepared = self.prepared.take().ok_or(Error::InvalidState)?;
        let abandoned = AbandonedStream {
            id: prepared.id,
            kind: prepared.kind,
        };
        prepared.bytes.fill(0);
        Ok(abandoned)
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
        self.prepared = Some(PreparedMessage {
            id,
            kind,
            bytes,
            source: None,
        });
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
                        self.last_written_time_sync_reply = Some(id);
                        if let Some(clock) = &mut self.continuing_clock {
                            if clock.pending {
                                clock.chain_replies += 1;
                                clock.pending = false;
                            }
                        }
                        if self.time_sync_policy == TimeSyncPolicy::ExplicitCorrelatedRequests
                            || self.pending_pre_hello_sync
                        {
                            self.time_sync_reply_ids[self.time_sync_reply_count] = id;
                            self.time_sync_reply_count += 1;
                        }
                        self.pending_pre_hello_sync = false;
                        self.time_sync = None;
                    }
                    MessageKind::EventReply | MessageKind::StartupRequestReply => {
                        let (request_id, _) = self.event_reply.take().ok_or(Error::InvalidState)?;
                        self.event_reply_is_startup_request = false;
                        self.replied_event_ids[self.replied_event_count] = request_id;
                        self.replied_event_count += 1;
                    }
                    kind @ (MessageKind::StartStream(_) | MessageKind::QuiesceStream(_)) => {
                        self.stream_request = Some((id, kind));
                    }
                    MessageKind::SetMotion(enabled) => self.motion_request = Some((id, enabled)),
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
            stream_request: self.stream_request.and_then(|(id, kind)| match kind {
                MessageKind::StartStream(channel) | MessageKind::QuiesceStream(channel) => {
                    Some((id, channel))
                }
                _ => None,
            }),
            stream_request_kind: self.stream_request.map(|(_, kind)| kind),
            motion_request: self.motion_request,
            event_reply: self.event_reply,
            event_reply_is_startup_request: self.event_reply_is_startup_request,
            unhandled_requests: self.unhandled_requests,
        };
        self.prepared = None;
        self.hello = None;
        self.time_sync = None;
        self.agreement_id = None;
        self.stream_request = None;
        self.motion_request = None;
        self.event_reply = None;
        self.event_reply_is_startup_request = false;
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
