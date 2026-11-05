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

/// Sanitized shape only; all fields are untrusted remote claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusShape {
    /// The remote JSON contained a board object.
    pub board: bool,
    /// The remote JSON contained a firmware object.
    pub firmware: bool,
    /// The remote JSON contained a controller object.
    pub controller: bool,
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

/// One sanitized settings observation and, when representable, its local binding.
/// A digest binds claimed values to the caller-supplied peer and generation; it
/// does not authenticate, timestamp, retain, or revalidate that observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsObservation {
    /// The reported controller destination or explicit reason it is unknown.
    pub controller: ControllerAddress,
    /// Digest only for a supported IPv4 or explicit unset value.
    pub binding: Option<ContentDigest>,
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
    /// Consume settings while exposing only the controller destination claim.
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
        let head = format!(
            "PUT /api/1.1/settings HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\nCookie: ",
            self.peer,
            body.len()
        );
        let mut bytes = Private(Vec::new());
        if bytes
            .0
            .try_reserve_exact(head.len() + cookie.0.len() + 4 + body.len())
            .is_err()
        {
            refuse!(HandoffError::Allocation);
        }
        bytes.0.extend_from_slice(head.as_bytes());
        bytes.0.extend_from_slice(&cookie.0);
        bytes.0.extend_from_slice(b"\r\n\r\n");
        bytes.0.extend_from_slice(body.as_bytes());
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
        let response = PrivateResponse(response);
        if self.phase != Phase::AwaitHandoff {
            return Err(Error::State);
        }
        if response.0.status != 200 {
            self.phase = Phase::Fenced;
            return Err(Error::HttpStatus);
        }
        self.phase = Phase::ReconcileSettings;
        Ok(())
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
        })
        .ok_or(Error::Status);
    clear_value(&mut value);
    result
}

fn settings(body: &[u8], peer: Ipv4Addr, generation: u64) -> Result<SettingsObservation, Error> {
    if body.len() > MAX_STATUS {
        return Err(Error::Settings);
    }
    let mut value = json_input::parse(std::str::from_utf8(body).map_err(|_| Error::Settings)?)
        .map_err(|_| Error::Settings)?;
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
    clear_value(&mut value);
    let controller = parsed?;
    let binding = controller_binding(controller, peer, generation)?;
    Ok(SettingsObservation {
        controller,
        binding,
    })
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
