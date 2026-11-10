#![forbid(unsafe_code)]
//! Bounded UniFi local camera requests and guarded controller handoff.
//!
//! This state machine grants no network, secret or media authority and does not
//! authenticate a camera. The caller must independently bind the peer, TLS,
//! credential lease and scoped task, frame complete bounded HTTP responses,
//! and account for I/O. A written request only proves local dispatch. An
//! interrupted write is fenced; the caller must reconcile the remote session.

use super::{handoff, metered::MeteredIo};
use asupersync::{
    Cx,
    http::h1::Response,
    io::{AsyncWrite, AsyncWriteExt},
    time::timeout_at,
};
use fss_core::{
    CanonicalEncoder, ContentDigest,
    json_input::{self, Value},
};
use fss_runtime::effect::CommittedEffect;
use std::{
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

const MAX_CREDENTIAL: usize = 4096;
const MAX_STATUS: usize = 262_144;
const MAX_JPEG: usize = 4 * 1024 * 1024;

/// Payload-free local API refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Peer, generation or credential input is outside the bounded profile.
    Configuration,
    /// The operation is not valid in the current session phase.
    State,
    /// The request originated in another session or has the wrong kind.
    RequestMismatch,
    /// The peer did not return a successful login, status or image response.
    HttpStatus,
    /// A unique, safe camera session cookie was not returned.
    Cookie,
    /// The status response was not a bounded, strict JSON object.
    Status,
    /// The settings response was not a bounded, strict JSON object.
    Settings,
    /// Current authority refused disclosure of retained serializer values.
    DisclosureDenied,
    /// The response was not a bounded JPEG-framed byte sequence.
    Image,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi camera API refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Local request outcome; a completed write does not prove peer acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// No request byte was sent; the caller may prepare again.
    NotWritten,
    /// All bytes were accepted locally; a response is now expected.
    Written,
    /// A partial or unknown write prevents automatic retry.
    Indeterminate,
}

/// Current local sequence, not a camera adoption or identity claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// A login may be prepared.
    Login,
    /// One request exists and its local write outcome is not yet reported.
    RequestPrepared,
    /// A login response is awaited.
    AwaitLogin,
    /// The first status request may be prepared.
    Status,
    /// A status response is awaited.
    AwaitStatus,
    /// A snapshot request may be prepared.
    Snapshot,
    /// A settings response is awaited.
    AwaitSettings,
    /// A snapshot response is awaited.
    AwaitSnapshot,
    /// A locally written controller change awaits an HTTP response.
    AwaitHandoff,
    /// A handoff response was accepted but requires fresh settings readback.
    ReconcileSettings,
    /// The local session must be retired or independently reconciled.
    Fenced,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Login,
    Status,
    Settings,
    SettingsAfterHandoff,
    Snapshot,
}

struct Private(Vec<u8>);
impl Drop for Private {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// A single exact request bound to its creating session.
/// Debug never exposes its bytes; drop clears them on a best-effort basis.
pub struct Request {
    owner: Arc<()>,
    kind: Kind,
    bytes: Private,
}
impl Request {
    /// Wire bytes for the independently authorized, owned transport only.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes.0
    }
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Sanitized status claims; all fields are untrusted remote claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusShape {
    /// The remote JSON contained a board object.
    pub board: bool,
    /// The remote JSON contained a firmware object.
    pub firmware: bool,
    /// The remote JSON contained a controller object.
    pub controller: bool,
    /// The camera's claimed controller port; not a reachability observation.
    pub controller_port: ControllerPort,
}

/// The untrusted camera status claim about its controller port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerPort {
    /// A nonzero TCP port was reported as an integer.
    Reported(u16),
    /// The controller object or port field was absent.
    Missing,
    /// The port field was explicitly null.
    Unset,
    /// The value was malformed, zero, or outside the TCP port range.
    Unsupported,
}

/// How the camera represented its current controller destination.
/// The value is an untrusted observation, not proof of identity or ownership.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ControllerAddress {
    /// The camera reported a syntactically valid IPv4 address.
    Reported(Ipv4Addr),
    /// The camera explicitly reported null or an empty string.
    Unset,
    /// The controller object or address field was absent.
    Missing,
    /// The field was present but outside the supported IPv4 profile.
    Unsupported,
}
impl fmt::Debug for ControllerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reported(_) => f.write_str("Reported(<redacted>)"),
            Self::Unset => f.write_str("Unset"),
            Self::Missing => f.write_str("Missing"),
            Self::Unsupported => f.write_str("Unsupported"),
        }
    }
}

/// The shape of one camera-reported serializer destination list.
/// This is an untrusted observation; none of these variants proves whether a
/// track is active, available, or safe to modify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoDestinationShape {
    /// The track, serializer, or destination list was missing or null.
    NotReported,
    /// The camera explicitly reported an empty destination list.
    Empty,
    /// Every reported destination was the discard sink.
    DiscardOnly,
    /// Every reported destination had the TCP scheme.
    TcpOnly,
    /// The list or its contents were mixed, malformed, or unsupported.
    Other,
}

/// An untrusted numeric camera setting, without guessing missing or malformed data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoMetric {
    /// The field or its enclosing object was absent or null.
    NotReported,
    /// The field or its enclosing object had an unsupported representation.
    Unsupported,
    /// A positive integer reported by the camera; this is not validated media.
    Reported(u32),
}

/// Camera-reported video dimensions and frame rate, not decoded stream properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoProfile {
    /// Reported pixel width.
    pub width: VideoMetric,
    /// Reported pixel height.
    pub height: VideoMetric,
    /// Reported maximum or configured frames per second.
    pub fps: VideoMetric,
}

/// One sanitized settings observation and, when representable, its local binding.
/// The controller digest binds only the controller claim to the caller-supplied
/// peer and generation. It does not cover video shapes or profiles, or authenticate,
/// timestamp, retain, or revalidate any observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsObservation {
    /// The reported controller destination or explicit reason it is unknown.
    pub controller: ControllerAddress,
    /// Digest only for a supported IPv4 or explicit unset value.
    pub binding: Option<ContentDigest>,
    /// Destination shapes for video1, video2 and video3, in that order.
    /// This omits destination values and is not a rollback record.
    pub video_destinations: [VideoDestinationShape; 3],
    /// Unauthenticated reported video1, video2 and video3 dimensions and rates.
    pub video_profiles: [VideoProfile; 3],
    /// Unauthenticated reported JPEG snapshot dimensions and rate.
    pub snapshot_profile: VideoProfile,
}

/// Caller-owned, untrusted serializer values from one settings response.
///
/// Values may contain private destinations or tokens. This is a semantic JSON
/// projection, not the original response bytes, a durable recovery record, or
/// evidence that sending the values back will restore the camera. Dropping it
/// clears owned value string buffers on a best-effort basis; object keys,
/// allocators, parsers and transports may retain sensitive material.
pub struct VideoSerializers {
    peer: Ipv4Addr,
    generation: u64,
    tracks: [Option<Value>; 3],
}
impl VideoSerializers {
    /// Revalidate current caller-owned disclosure authority, then inspect the
    /// three optional values in video1/video2/video3 order. The caller is
    /// responsible for privacy, further retention, and any copies it makes.
    pub fn visit<R>(
        &self,
        authorize: impl FnOnce(Ipv4Addr, u64) -> bool,
        inspect: impl FnOnce([Option<&Value>; 3]) -> R,
    ) -> Result<R, Error> {
        if !authorize(self.peer, self.generation) {
            return Err(Error::DisclosureDenied);
        }
        Ok(inspect(self.tracks.each_ref().map(Option::as_ref)))
    }

    /// Bind the exact parsed serializer values, peer and session generation for
    /// later precondition comparison. The caller must authorize disclosure of
    /// the digest, which can itself be sensitive. This is not device identity,
    /// capture time, durable custody, or proof that restoration is possible.
    pub fn binding(
        &self,
        authorize: impl FnOnce(Ipv4Addr, u64) -> bool,
    ) -> Result<ContentDigest, Error> {
        if !authorize(self.peer, self.generation) {
            return Err(Error::DisclosureDenied);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.unifi.camera-video-serializers.v1");
        encoder.bytes(&self.peer.octets());
        encoder.u64(self.generation);
        for track in &self.tracks {
            encoder.bool(track.is_some());
            if let Some(value) = track {
                encode_serializer_value(&mut encoder, value)?;
            }
        }
        let bytes = Private(encoder.finish_checked().map_err(|_| Error::Settings)?);
        Ok(ContentDigest::sha256(&bytes.0))
    }
}
impl fmt::Debug for VideoSerializers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VideoSerializers(<redacted>)")
    }
}
impl Drop for VideoSerializers {
    fn drop(&mut self) {
        for value in self.tracks.iter_mut().flatten() {
            clear_value(value);
        }
    }
}

/// Bounded, payload-free shape of a camera's handoff HTTP response body.
/// Values are unauthenticated peer claims, not evidence that a setting changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffResponseObservation {
    /// The server returned an empty body.
    Empty,
    /// The body was a strict JSON object. Only these optional scalars survive.
    Object {
        /// An explicitly boolean top-level `success`, if present.
        success: Option<bool>,
        /// A bounded numeric top-level `statusCode`, if present.
        status_code: Option<i64>,
    },
    /// The body was malformed, non-object, or outside the inspection bound.
    Other,
}

/// Revalidate the independently identified peer, current authority and lease.
/// Implementations must bind the transport to the intended peer and prevent
/// stale or revoked policy from authorizing a write. This check is repeated
/// before each transport write and flush; implementations must consult live state.
pub trait HandoffAuthority {
    /// Check the exact plan, current claims and one-use effect permit.
    fn permits(
        &self,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        permit: &CommittedEffect,
    ) -> bool;
}

struct GuardedHandoffWriter<'a, 'scope, 'task, IO> {
    io: &'a mut MeteredIo<'scope, 'task, IO>,
    cx: &'a Cx,
    plan: &'a handoff::Plan,
    current: handoff::Preconditions,
    permit: &'a CommittedEffect,
    authority: &'a dyn HandoffAuthority,
}

impl<IO: AsyncWrite + Unpin> GuardedHandoffWriter<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        if self.cx.checkpoint().is_err()
            || !self.authority.permits(self.plan, self.current, self.permit)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "handoff authority refused",
            ));
        }
        Ok(())
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for GuardedHandoffWriter<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}

/// Refusal before a handoff write begins; retains the unclaimed permit.
#[must_use]
#[derive(Debug)]
pub struct HandoffRefusal {
    /// Payload-free refusal reason.
    pub reason: HandoffError,
    /// The original permit, which has not been claimed by this dispatch.
    pub permit: CommittedEffect,
}
/// Payload-free refusal at the handoff dispatch boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The session, observed settings or transport context does not match.
    Session,
    /// Wait duration is zero or exceeds the bounded limit.
    Wait,
    /// The committed effect was not journal-backed.
    JournalRequired,
    /// The permit is for a different request, precondition, resource or fence.
    PermitMismatch,
    /// The current preconditions differ from the plan.
    Stale,
    /// The caller's live identity, policy or lease check refused dispatch.
    Denied,
    /// Runtime cancellation or clock capability refused dispatch.
    Context,
    /// The permit had already been claimed.
    PermitUsed,
    /// Bounded request assembly failed.
    Allocation,
}
/// Local write result; neither branch establishes the camera's remote state.
#[must_use]
#[derive(Debug)]
pub enum HandoffWrite {
    /// The complete request and flush were accepted by the local transport.
    Written {
        /// Claimed permit; retain for independent outcome reconciliation.
        permit: CommittedEffect,
    },
    /// A partial write, timeout or transport error requires reconciliation.
    Indeterminate {
        /// Claimed permit; it must not be dispatched again.
        permit: CommittedEffect,
    },
}

/// One bounded JPEG response, not proof of origin, capture time or decoding.
pub struct Snapshot {
    bytes: Private,
    digest: ContentDigest,
}
impl Snapshot {
    /// Original response body; the caller must separately authorize retention.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes.0
    }
    /// Digest computed locally over this response, not independent origin proof.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("bytes", &self.bytes.0.len())
            .finish_non_exhaustive()
    }
}

/// One locally ordered camera API session. A cookie never appears in Debug.
pub struct Session {
    peer: Ipv4Addr,
    generation: u64,
    owner: Arc<()>,
    phase: Phase,
    pending: Option<Kind>,
    cookie: Option<Private>,
    last_settings: Option<SettingsObservation>,
}
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("generation", &self.generation)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl Session {
    /// Bind a caller-authorized private or loopback IPv4 peer and nonzero generation.
    pub fn new(peer: Ipv4Addr, generation: u64) -> Result<Self, Error> {
        if generation == 0
            || !(peer.is_private() || peer.is_loopback() || peer.is_link_local())
            || peer.is_unspecified()
            || peer.is_multicast()
            || peer.is_broadcast()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            peer,
            generation,
            owner: Arc::new(()),
            phase: Phase::Login,
            pending: None,
            cookie: None,
            last_settings: None,
        })
    }
    /// Fence an interrupted request or response and discard the session cookie.
    /// A fresh authenticated session is required before any later operation.
    pub(crate) fn fence(&mut self) {
        self.pending = None;
        self.cookie = None;
        self.phase = Phase::Fenced;
    }

    /// Local sequence phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Prepare exactly one login from a bounded JSON object containing only username and password.
    pub fn prepare_login(&mut self, body: &[u8]) -> Result<Request, Error> {
        if self.phase != Phase::Login {
            return Err(Error::State);
        }
        if body.is_empty() || body.len() > MAX_CREDENTIAL {
            return Err(Error::Configuration);
        }
        let mut doc =
            json_input::parse(std::str::from_utf8(body).map_err(|_| Error::Configuration)?)
                .map_err(|_| Error::Configuration)?;
        let valid = doc.object().is_some_and(|obj| {
            obj.len() == 2
                && ["username", "password"].iter().all(|key| {
                    obj.get(*key)
                        .and_then(Value::text)
                        .is_some_and(|s| !s.is_empty() && s.len() <= 1024)
                })
        });
        clear_value(&mut doc);
        if !valid {
            return Err(Error::Configuration);
        }
        let head = format!(
            "POST /api/1.1/login HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n",
            self.peer,
            body.len()
        );
        let mut bytes = Vec::with_capacity(head.len() + body.len());
        bytes.extend_from_slice(head.as_bytes());
        bytes.extend_from_slice(body);
        self.prepare(Kind::Login, bytes)
    }
    /// Prepare the authenticated read-only status request.
    pub fn prepare_status(&mut self) -> Result<Request, Error> {
        if self.phase != Phase::Status {
            return Err(Error::State);
        }
        let bytes = self.get("/api/1.1/status", "application/json")?;
        self.prepare(Kind::Status, bytes)
    }
    /// Prepare one authenticated read-only JPEG request; may be repeated after a complete response.
    pub fn prepare_snapshot(&mut self) -> Result<Request, Error> {
        if self.phase != Phase::Snapshot {
            return Err(Error::State);
        }
        let bytes = self.get("/snap.jpeg", "image/jpeg")?;
        self.prepare(Kind::Snapshot, bytes)
    }
    /// Prepare a read-only camera settings request after status or a snapshot.
    pub fn prepare_settings(&mut self) -> Result<Request, Error> {
        let kind = match self.phase {
            Phase::Snapshot => Kind::Settings,
            Phase::ReconcileSettings => Kind::SettingsAfterHandoff,
            _ => return Err(Error::State),
        };
        let bytes = self.get("/api/1.1/settings", "application/json")?;
        self.prepare(kind, bytes)
    }
    fn get(&self, path: &str, accept: &str) -> Result<Vec<u8>, Error> {
        let cookie = &self.cookie.as_ref().ok_or(Error::State)?.0;
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nCookie: ",
            self.peer
        );
        let mut bytes = Vec::with_capacity(head.len() + cookie.len() + 4);
        bytes.extend_from_slice(head.as_bytes());
        bytes.extend_from_slice(cookie);
        bytes.extend_from_slice(b"\r\n\r\n");
        Ok(bytes)
    }
    fn prepare(&mut self, kind: Kind, bytes: Vec<u8>) -> Result<Request, Error> {
        if self.pending.is_some() {
            return Err(Error::State);
        }
        self.pending = Some(kind);
        self.phase = Phase::RequestPrepared;
        Ok(Request {
            owner: self.owner.clone(),
            kind,
            bytes: Private(bytes),
        })
    }
    /// Consume a prepared request and record its local transport outcome.
    pub fn finish_write(&mut self, request: Request, outcome: WriteOutcome) -> Result<(), Error> {
        if self.phase != Phase::RequestPrepared
            || self.pending != Some(request.kind)
            || !Arc::ptr_eq(&self.owner, &request.owner)
        {
            return Err(Error::RequestMismatch);
        }
        self.pending = None;
        self.phase = match (request.kind, outcome) {
            (_, WriteOutcome::Indeterminate) => Phase::Fenced,
            (Kind::Login, WriteOutcome::NotWritten) => Phase::Login,
            (Kind::Status, WriteOutcome::NotWritten) => Phase::Status,
            (Kind::Snapshot, WriteOutcome::NotWritten) => Phase::Snapshot,
            (Kind::Settings, WriteOutcome::NotWritten) => Phase::Snapshot,
            (Kind::SettingsAfterHandoff, WriteOutcome::NotWritten) => Phase::ReconcileSettings,
            (Kind::Login, WriteOutcome::Written) => Phase::AwaitLogin,
            (Kind::Status, WriteOutcome::Written) => Phase::AwaitStatus,
            (Kind::Snapshot, WriteOutcome::Written) => Phase::AwaitSnapshot,
            (Kind::Settings, WriteOutcome::Written) => Phase::AwaitSettings,
            (Kind::SettingsAfterHandoff, WriteOutcome::Written) => Phase::AwaitSettings,
        };
        Ok(())
    }
    /// Consume a complete login response; every refusal fences the session.
    pub fn accept_login(&mut self, response: Response) -> Result<(), Error> {
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitLogin {
            return Err(Error::State);
        }
        let result = if response.0.status == 200 {
            cookie(&response.0.headers)
        } else {
            Err(Error::HttpStatus)
        };
        match result {
            Ok(cookie) => {
                self.cookie = Some(cookie);
                self.phase = Phase::Status;
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Fenced;
                Err(error)
            }
        }
    }
    /// Consume a complete response and report only its bounded untrusted shape.
    pub fn accept_status(&mut self, response: Response) -> Result<StatusShape, Error> {
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitStatus {
            return Err(Error::State);
        }
        let result = if response.0.status == 200 {
            status_shape(&response.0.body)
        } else {
            Err(Error::HttpStatus)
        };
        match result {
            Ok(shape) => {
                self.phase = Phase::Snapshot;
                Ok(shape)
            }
            Err(error) => {
                self.phase = Phase::Fenced;
                Err(error)
            }
        }
    }
    /// Consume settings while exposing only sanitized controller and track shapes.
    /// Other settings, including possible secrets, are not returned or logged.
    pub fn accept_settings(&mut self, response: Response) -> Result<SettingsObservation, Error> {
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitSettings {
            return Err(Error::State);
        }
        let result = if response.0.status == 200 {
            settings(&response.0.body, self.peer, self.generation)
        } else {
            Err(Error::HttpStatus)
        };
        match result {
            Ok(observation) => {
                self.last_settings = Some(observation);
                self.phase = Phase::Snapshot;
                Ok(observation)
            }
            Err(error) => {
                self.phase = Phase::Fenced;
                Err(error)
            }
        }
    }
    /// Consume a settings response and retain its three serializer values in
    /// caller-owned memory. A transport owner must separately authorize this
    /// higher-disclosure operation before and during I/O. No value is write-ready.
    pub fn accept_settings_with_serializers(
        &mut self,
        response: Response,
    ) -> Result<(SettingsObservation, VideoSerializers), Error> {
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitSettings {
            return Err(Error::State);
        }
        let result = if response.0.status == 200 {
            settings_with_serializers(&response.0.body, self.peer, self.generation)
        } else {
            Err(Error::HttpStatus)
        };
        match result {
            Ok((observation, serializers)) => {
                self.last_settings = Some(observation);
                self.phase = Phase::Snapshot;
                Ok((observation, serializers))
            }
            Err(error) => {
                self.phase = Phase::Fenced;
                Err(error)
            }
        }
    }
    /// Dispatch a planned controller-address change on a caller-owned, metered
    /// plaintext stream above an independently qualified TLS transport. The
    /// authority implementation binds that exact transport to the intended peer.
    /// Once dispatch begins, a dropped or interrupted future leaves the session
    /// fenced. Dropping it before its first poll sends nothing and drops the permit.
    /// A successful write is local evidence only; its effect remains open.
    pub async fn dispatch_handoff<IO: AsyncWrite + Unpin>(
        &mut self,
        cx: &Cx,
        io: &mut MeteredIo<'_, '_, IO>,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        mut permit: CommittedEffect,
        authority: &dyn HandoffAuthority,
        wait: Duration,
    ) -> Result<HandoffWrite, HandoffRefusal> {
        macro_rules! refuse {
            ($reason:expr) => {
                return Err(HandoffRefusal {
                    reason: $reason,
                    permit,
                })
            };
        }
        if wait.is_zero() || wait > Duration::from_secs(30) {
            refuse!(HandoffError::Wait);
        }
        if self.phase != Phase::Snapshot
            || self.pending.is_some()
            || self.last_settings != Some(current.settings)
            || !plan.matches_session(self.peer, self.generation)
            || !std::ptr::eq(cx, io.runtime_context())
        {
            refuse!(HandoffError::Session);
        }
        if !permit.journal_backed() {
            refuse!(HandoffError::JournalRequired);
        }
        if permit.prepared().effect_class() != handoff::EFFECT_CLASS
            || permit.prepared().request_digest() != plan.request_digest()
            || permit.prepared().precondition_digest() != plan.precondition_digest()
            || permit.resource() != plan.resource()
            || permit.fence() != plan.fence()
        {
            refuse!(HandoffError::PermitMismatch);
        }
        if plan.check_current(current).is_err() {
            refuse!(HandoffError::Stale);
        }
        if !authority.permits(plan, current, &permit) {
            refuse!(HandoffError::Denied);
        }
        if !cx.has_timer() || cx.checkpoint().is_err() {
            refuse!(HandoffError::Context);
        }
        let Some(cookie) = self.cookie.as_ref() else {
            refuse!(HandoffError::Session);
        };
        let Ok(body) = plan.body() else {
            refuse!(HandoffError::Stale);
        };
        let framing_header = match plan.framing() {
            handoff::Framing::ContentLength => format!("Content-Length: {}\r\n", body.len()),
            handoff::Framing::Chunked => "Transfer-Encoding: chunked\r\n".to_owned(),
        };
        let head = format!(
            "PUT /api/1.1/settings HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\nCookie: ",
            self.peer, framing_header
        );
        let prefix = match plan.framing() {
            handoff::Framing::ContentLength => String::new(),
            handoff::Framing::Chunked => format!("{:x}\r\n", body.len()),
        };
        let suffix: &[u8] = match plan.framing() {
            handoff::Framing::ContentLength => b"",
            handoff::Framing::Chunked => b"\r\n0\r\n\r\n",
        };
        let mut bytes = Private(Vec::new());
        if bytes
            .0
            .try_reserve_exact(
                head.len() + cookie.0.len() + 4 + prefix.len() + body.len() + suffix.len(),
            )
            .is_err()
        {
            refuse!(HandoffError::Allocation);
        }
        bytes.0.extend_from_slice(head.as_bytes());
        bytes.0.extend_from_slice(&cookie.0);
        bytes.0.extend_from_slice(b"\r\n\r\n");
        bytes.0.extend_from_slice(prefix.as_bytes());
        bytes.0.extend_from_slice(body.as_bytes());
        bytes.0.extend_from_slice(suffix);
        if !permit.try_claim_dispatch() {
            refuse!(HandoffError::PermitUsed);
        }
        // Fence before the first poll so cancellation cannot make a partial
        // request retryable. The permit's obligation survives future drop.
        self.phase = Phase::Fenced;
        self.last_settings = None;
        let write = async {
            let mut guarded = GuardedHandoffWriter {
                io,
                cx,
                plan,
                current,
                permit: &permit,
                authority,
            };
            guarded.write_all(&bytes.0).await?;
            guarded.flush().await
        };
        match timeout_at(cx.now() + wait, write).await {
            Ok(Ok(())) => {
                self.phase = Phase::AwaitHandoff;
                Ok(HandoffWrite::Written { permit })
            }
            _ => Ok(HandoffWrite::Indeterminate { permit }),
        }
    }

    /// Observe the complete HTTP response to a locally written handoff. A 200
    /// requires fresh readback and does not settle the effect obligation.
    pub fn accept_handoff_response(&mut self, response: Response) -> Result<(), Error> {
        self.accept_handoff_response_observed(response).map(|_| ())
    }
    /// Accept the same response while returning only bounded peer claims.
    /// Even a positive claim requires fresh readback and effect reconciliation.
    pub fn accept_handoff_response_observed(
        &mut self,
        response: Response,
    ) -> Result<HandoffResponseObservation, Error> {
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitHandoff {
            return Err(Error::State);
        }
        if response.0.status != 200 {
            self.phase = Phase::Fenced;
            return Err(Error::HttpStatus);
        }
        let observation = handoff_response_observation(&response.0.body);
        self.phase = Phase::ReconcileSettings;
        Ok(observation)
    }
    /// Consume a complete JPEG response and transfer its bytes into a redacted handle.
    pub fn accept_snapshot(&mut self, response: Response) -> Result<Snapshot, Error> {
        let mut response = PrivateResponse(response);
        if self.phase != Phase::AwaitSnapshot {
            return Err(Error::State);
        }
        let body = &response.0.body;
        if response.0.status != 200 {
            self.phase = Phase::Fenced;
            return Err(Error::HttpStatus);
        }
        if body.len() < 4
            || body.len() > MAX_JPEG
            || !body.starts_with(&[0xff, 0xd8])
            || !body.ends_with(&[0xff, 0xd9])
        {
            self.phase = Phase::Fenced;
            return Err(Error::Image);
        }
        let digest = ContentDigest::sha256(body);
        let bytes = std::mem::take(&mut response.0.body);
        self.phase = Phase::Snapshot;
        Ok(Snapshot {
            bytes: Private(bytes),
            digest,
        })
    }
}

struct PrivateResponse(Response);
impl Drop for PrivateResponse {
    fn drop(&mut self) {
        self.0.body.fill(0);
        for (_, value) in self.0.headers.iter_mut().chain(self.0.trailers.iter_mut()) {
            let mut bytes = std::mem::take(value).into_bytes();
            bytes.fill(0);
        }
    }
}
fn cookie(headers: &[(String, String)]) -> Result<Private, Error> {
    let mut result = None;
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
    {
        let first = value.split(';').next().ok_or(Error::Cookie)?.trim();
        let Some(raw) = first.strip_prefix("authId=") else {
            continue;
        };
        if result.is_some()
            || raw.is_empty()
            || raw.len() > 512
            || !raw
                .bytes()
                .all(|b| matches!(b,0x21|0x23..=0x2b|0x2d..=0x3a|0x3c..=0x5b|0x5d..=0x7e))
        {
            return Err(Error::Cookie);
        }
        result = Some(Private(first.as_bytes().to_vec()));
    }
    result.ok_or(Error::Cookie)
}
fn status_shape(body: &[u8]) -> Result<StatusShape, Error> {
    if body.len() > MAX_STATUS {
        return Err(Error::Status);
    }
    let mut value = json_input::parse(std::str::from_utf8(body).map_err(|_| Error::Status)?)
        .map_err(|_| Error::Status)?;
    let result = value
        .object()
        .map(|o| StatusShape {
            board: o.get("board").and_then(Value::object).is_some(),
            firmware: o.get("fw").and_then(Value::object).is_some(),
            controller: o.get("controller").and_then(Value::object).is_some(),
            controller_port: match o.get("controller") {
                None => ControllerPort::Missing,
                Some(Value::Null) => ControllerPort::Unset,
                Some(Value::Object(controller)) => match controller.get("port") {
                    None => ControllerPort::Missing,
                    Some(Value::Null) => ControllerPort::Unset,
                    Some(Value::Number(_)) => controller
                        .get("port")
                        .and_then(Value::integer)
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|port| *port != 0)
                        .map_or(ControllerPort::Unsupported, ControllerPort::Reported),
                    Some(_) => ControllerPort::Unsupported,
                },
                Some(_) => ControllerPort::Unsupported,
            },
        })
        .ok_or(Error::Status);
    clear_value(&mut value);
    result
}

fn handoff_response_observation(body: &[u8]) -> HandoffResponseObservation {
    if body.is_empty() {
        return HandoffResponseObservation::Empty;
    }
    if body.len() > MAX_STATUS {
        return HandoffResponseObservation::Other;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return HandoffResponseObservation::Other;
    };
    let Ok(mut value) = json_input::parse(text) else {
        return HandoffResponseObservation::Other;
    };
    let result = value
        .object()
        .map_or(HandoffResponseObservation::Other, |object| {
            let status_code = match object.get("statusCode") {
                Some(Value::Number(_)) => object
                    .get("statusCode")
                    .and_then(Value::integer)
                    .filter(|number| (-9999..=9999).contains(number))
                    .and_then(|number| i64::try_from(number).ok()),
                _ => None,
            };
            HandoffResponseObservation::Object {
                success: object.get("success").and_then(Value::boolean),
                status_code,
            }
        });
    clear_value(&mut value);
    result
}

fn settings(body: &[u8], peer: Ipv4Addr, generation: u64) -> Result<SettingsObservation, Error> {
    settings_inner(body, peer, generation, false).map(|(observation, _)| observation)
}

fn settings_with_serializers(
    body: &[u8],
    peer: Ipv4Addr,
    generation: u64,
) -> Result<(SettingsObservation, VideoSerializers), Error> {
    let (observation, serializers) = settings_inner(body, peer, generation, true)?;
    serializers.map(|s| (observation, s)).ok_or(Error::Settings)
}

fn settings_inner(
    body: &[u8],
    peer: Ipv4Addr,
    generation: u64,
    retain_serializers: bool,
) -> Result<(SettingsObservation, Option<VideoSerializers>), Error> {
    if body.len() > MAX_STATUS {
        return Err(Error::Settings);
    }
    let mut value = json_input::parse(std::str::from_utf8(body).map_err(|_| Error::Settings)?)
        .map_err(|_| Error::Settings)?;
    let video_profiles = ["video1", "video2", "video3"].map(|track| video_profile(&value, track));
    let snapshot_profile = video_profile(&value, "mjpg");
    let video_destinations = ["video1", "video2", "video3"].map(|track| {
        let mut current = &value;
        for key in ["av", "video", track, "avSerializer", "destinations"] {
            current = match current {
                Value::Object(fields) => match fields.get(key) {
                    Some(value) => value,
                    None => return VideoDestinationShape::NotReported,
                },
                Value::Null => return VideoDestinationShape::NotReported,
                _ => return VideoDestinationShape::Other,
            };
        }
        match current {
            Value::Null => VideoDestinationShape::NotReported,
            Value::Array(items) if items.is_empty() => VideoDestinationShape::Empty,
            Value::Array(items) if items.len() <= 16 => {
                if items
                    .iter()
                    .all(|item| matches!(item, Value::Text(s) if s == "file:///dev/null"))
                {
                    VideoDestinationShape::DiscardOnly
                } else if items
                    .iter()
                    .all(|item| matches!(item, Value::Text(s) if s.starts_with("tcp://")))
                {
                    VideoDestinationShape::TcpOnly
                } else {
                    VideoDestinationShape::Other
                }
            }
            _ => VideoDestinationShape::Other,
        }
    });
    let parsed = value
        .object()
        .map(|root| {
            let controller = match root.get("controller") {
                None => return ControllerAddress::Missing,
                Some(Value::Object(controller)) => controller,
                Some(_) => return ControllerAddress::Unsupported,
            };
            match controller.get("addr") {
                None => ControllerAddress::Missing,
                Some(Value::Null) => ControllerAddress::Unset,
                Some(Value::Text(s)) if s.is_empty() => ControllerAddress::Unset,
                Some(Value::Text(s)) => match s.parse::<Ipv4Addr>() {
                    Ok(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() => {
                        ControllerAddress::Reported(ip)
                    }
                    _ => ControllerAddress::Unsupported,
                },
                Some(_) => ControllerAddress::Unsupported,
            }
        })
        .ok_or(Error::Settings);
    let controller = match parsed {
        Ok(controller) => controller,
        Err(error) => {
            clear_value(&mut value);
            return Err(error);
        }
    };
    let binding = match controller_binding(controller, peer, generation) {
        Ok(binding) => binding,
        Err(error) => {
            clear_value(&mut value);
            return Err(error);
        }
    };
    let serializers = retain_serializers.then(|| {
        let mut tracks = [None, None, None];
        if let Some(video) = field_mut(&mut value, "av").and_then(|v| field_mut(v, "video")) {
            for (index, name) in ["video1", "video2", "video3"].into_iter().enumerate() {
                if let Some(Value::Object(track)) = field_mut(video, name) {
                    tracks[index] = track.remove("avSerializer");
                }
            }
        }
        VideoSerializers {
            peer,
            generation,
            tracks,
        }
    });
    clear_value(&mut value);
    Ok((
        SettingsObservation {
            controller,
            binding,
            video_destinations,
            video_profiles,
            snapshot_profile,
        },
        serializers,
    ))
}

fn video_profile(root: &Value, track: &str) -> VideoProfile {
    let uniform = |metric| VideoProfile {
        width: metric,
        height: metric,
        fps: metric,
    };
    let mut current = root;
    for key in ["av", "video", track] {
        current = match current {
            Value::Object(fields) => match fields.get(key) {
                Some(Value::Null) | None => return uniform(VideoMetric::NotReported),
                Some(value) => value,
            },
            Value::Null => return uniform(VideoMetric::NotReported),
            _ => return uniform(VideoMetric::Unsupported),
        };
    }
    let fields = match current {
        Value::Object(fields) => fields,
        Value::Null => return uniform(VideoMetric::NotReported),
        _ => return uniform(VideoMetric::Unsupported),
    };
    let metric = |key: &str| match fields.get(key) {
        None | Some(Value::Null) => VideoMetric::NotReported,
        Some(value @ Value::Number(_)) => value
            .integer()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n != 0)
            .map_or(VideoMetric::Unsupported, VideoMetric::Reported),
        _ => VideoMetric::Unsupported,
    };
    VideoProfile {
        width: metric("width"),
        height: metric("height"),
        fps: metric("fps"),
    }
}

fn field_mut<'a>(value: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    match value {
        Value::Object(fields) => fields.get_mut(key),
        _ => None,
    }
}

fn encode_serializer_value(encoder: &mut CanonicalEncoder, value: &Value) -> Result<(), Error> {
    match value {
        Value::Null => encoder.tag(0),
        Value::Bool(value) => {
            encoder.tag(1);
            encoder.bool(*value);
        }
        Value::Number(value) => {
            encoder.tag(2);
            encoder.text(value);
        }
        Value::Text(value) => {
            encoder.tag(3);
            encoder.text(value);
        }
        Value::Array(values) => {
            encoder.tag(4);
            encoder.u64(u64::try_from(values.len()).map_err(|_| Error::Settings)?);
            for value in values {
                encode_serializer_value(encoder, value)?;
            }
        }
        Value::Object(values) => {
            encoder.tag(5);
            encoder.u64(u64::try_from(values.len()).map_err(|_| Error::Settings)?);
            for (key, value) in values {
                encoder.text(key);
                encode_serializer_value(encoder, value)?;
            }
        }
    }
    Ok(())
}

pub(super) fn controller_binding(
    controller: ControllerAddress,
    peer: Ipv4Addr,
    generation: u64,
) -> Result<Option<ContentDigest>, Error> {
    let binding = match controller {
        ControllerAddress::Reported(ip) => {
            let mut e = CanonicalEncoder::new();
            e.text("fss.unifi.camera-controller-observation.v1");
            e.text(&peer.to_string());
            e.u64(generation);
            e.text("ipv4");
            e.text(&ip.to_string());
            Some(ContentDigest::sha256(
                &e.finish_checked().map_err(|_| Error::Settings)?,
            ))
        }
        ControllerAddress::Unset => {
            let mut e = CanonicalEncoder::new();
            e.text("fss.unifi.camera-controller-observation.v1");
            e.text(&peer.to_string());
            e.u64(generation);
            e.text("unset");
            Some(ContentDigest::sha256(
                &e.finish_checked().map_err(|_| Error::Settings)?,
            ))
        }
        ControllerAddress::Missing | ControllerAddress::Unsupported => None,
    };
    Ok(binding)
}
fn clear_value(value: &mut Value) {
    match value {
        Value::Text(s) | Value::Number(s) => {
            let mut bytes = std::mem::take(s).into_bytes();
            bytes.fill(0);
        }
        Value::Array(a) => {
            for v in a {
                clear_value(v);
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                clear_value(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod handoff_response_tests {
    use super::{
        HandoffResponseObservation as Observation, MAX_STATUS, handoff_response_observation,
    };

    #[test]
    fn shape_is_bounded_and_does_not_retain_other_fields() {
        assert_eq!(handoff_response_observation(b""), Observation::Empty);
        let body = br#"{"success":true,"statusCode":200,"secret":"do-not-retain"}"#;
        let observed = handoff_response_observation(body);
        assert_eq!(
            observed,
            Observation::Object {
                success: Some(true),
                status_code: Some(200)
            }
        );
        assert!(!format!("{observed:?}").contains("do-not-retain"));
        assert_eq!(handoff_response_observation(b"[]"), Observation::Other);
        assert_eq!(handoff_response_observation(b"{broken"), Observation::Other);
        assert_eq!(
            handoff_response_observation(&vec![b' '; MAX_STATUS + 1]),
            Observation::Other
        );
        assert_eq!(
            handoff_response_observation(br#"{"success":"true","statusCode":999999}"#),
            Observation::Object {
                success: None,
                status_code: None
            }
        );
    }
}
