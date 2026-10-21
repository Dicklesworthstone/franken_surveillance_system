#![forbid(unsafe_code)]
//! Bounded native HTTP ownership for the three read-only ONVIF SOAP operations.
//!
//! The caller pins the peer, HTTP authority, generation and plaintext approval,
//! supplies a live authority and admission clock, and owns every wait. This owner
//! performs no DNS lookup, redirect, retry, secret acquisition, timer or task spawn.
//! Digest calculation remains owned by the existing RTSP authentication module.

mod framing;

use super::wire::SoapRequest;
use crate::rtsp::authentication::DigestAuthorization;
use fss_core::{CanonicalEncoder, ContentDigest};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// An exact approved route. Neither an advertised XAddr nor a successful budget
/// check grants this approval. Debug omits addresses, paths and approval handles.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpRoute {
    peer: SocketAddr,
    authority: String,
    target: String,
    generation: u64,
    plaintext_approval: ContentDigest,
    digest: ContentDigest,
}

impl HttpRoute {
    /// Pin one independently resolved address and HTTP origin. Explicit ports must
    /// equal the socket port; an omitted port means 80. IP-literal hosts must equal
    /// the socket IP. DNS names are never resolved here or refreshed after failure.
    /// Query strings, escapes, dot segments and userinfo are outside this profile.
    pub fn new(
        peer: SocketAddr,
        authority: &str,
        target: &str,
        generation: u64,
        plaintext_approval: ContentDigest,
    ) -> Result<Self, HttpError> {
        if peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || matches!(peer.ip(), IpAddr::V4(ip) if ip.is_broadcast())
            || generation == 0
            || plaintext_approval.bytes() == [0; 32]
            || !valid_authority(authority, peer)
            || !target.starts_with('/')
            || target.starts_with("//")
            || target.len() > 2048
            || !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
            || target.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(HttpError::Configuration);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.onvif.http-route.v1:explicit-plaintext:read-only");
        encoder.text(&peer.to_string());
        encoder.text(authority);
        encoder.text(target);
        encoder.u64(generation);
        encoder.digest(plaintext_approval);
        let digest = ContentDigest::sha256(
            &encoder
                .finish_checked()
                .map_err(|_| HttpError::Configuration)?,
        );
        Ok(Self {
            peer,
            authority: authority.to_owned(),
            target: target.to_owned(),
            generation,
            plaintext_approval,
            digest,
        })
    }

    /// Change only the target after the higher owner has admitted a same-origin
    /// service address. Every subsequent boundary still checks the new exact route.
    pub fn with_target(&self, target: &str) -> Result<Self, HttpError> {
        Self::new(
            self.peer,
            &self.authority,
            target,
            self.generation,
            self.plaintext_approval,
        )
    }

    /// Frozen network destination; no DNS or redirect may alter it.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
    /// Exact Host header and credential origin.
    pub fn authority(&self) -> &str {
        &self.authority
    }
    /// Exact origin-form target used for both HTTP and Digest calculations.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Device/onboarding generation checked by the live authority.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Owner-issued approval for the explicit plaintext limitation.
    pub fn plaintext_approval(&self) -> ContentDigest {
        self.plaintext_approval
    }
    /// Binding of peer, origin, target, generation and plaintext approval.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

impl fmt::Debug for HttpRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRoute")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

fn valid_authority(value: &str, peer: SocketAddr) -> bool {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return false;
    }
    let (host, port, literal) = if let Some(rest) = value.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = host.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        let port = if tail.is_empty() {
            80
        } else if let Some(port) = tail.strip_prefix(':') {
            match parse_port(port) {
                Some(port) => port,
                None => return false,
            }
        } else {
            return false;
        };
        (host, port, Some(IpAddr::V6(ip)))
    } else {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => match parse_port(port) {
                Some(port) => (host, port),
                None => return false,
            },
            None => (value, 80),
        };
        if host.is_empty()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return false;
        }
        (host, port, host.parse::<IpAddr>().ok())
    };
    !host.is_empty() && port == peer.port() && literal.is_none_or(|ip| ip == peer.ip())
}

fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.starts_with('0')
    {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Explicit live-authority boundaries; none implies permission for camera control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpOperation {
    /// One bounded TCP connection attempt.
    Connect,
    /// Query or configure the already connected socket.
    Configure,
    /// One bounded nonblocking request-prefix write.
    Write,
    /// One bounded nonblocking response read.
    Read,
    /// Parse a bounded owned response prefix.
    Parse,
    /// Transfer one completely framed response to the orchestration owner.
    Release,
    /// Revalidate authority while pending or between operations.
    Poll,
}

/// Payload-free live authority denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpDenial {
    /// Principal, route, generation or operation is not authorized.
    Unauthorized,
    /// A previous grant or secret lease was revoked.
    Revoked,
    /// The owning context requested cancellation.
    Cancelled,
    /// The owner's independent live clock passed the lease.
    Deadline,
    /// The owner's total operation allowance is exhausted.
    Budget,
}

/// Implement with the owning Cx or equivalent explicit capability. Each check
/// MUST verify actual elapsed time, principal, pinned route, generation, plaintext
/// policy and cancellation, including after syscalls. `now_ns` is admission time,
/// not a post-I/O clock sample. No permissive production implementation exists.
pub trait HttpAuthority {
    /// Revalidate this exact operation without exposing credentials or policy text.
    fn checkpoint(
        &self,
        route: &HttpRoute,
        operation: HttpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpDenial>;
}

/// Whole-exchange ceilings. Authentication retries are separate exchanges and
/// must also consume the higher owner's aggregate onboarding budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    /// Complete request including SOAP and Digest, 1..=65536 bytes.
    pub request_bytes: usize,
    /// All response heads combined and one trailer block, each 4..=32768 bytes.
    pub header_bytes: usize,
    /// Complete transfer-decoded response, 1..=1 MiB.
    pub body_bytes: usize,
    /// Entire response with framing, 4..=2 MiB.
    pub wire_bytes: usize,
    /// Maximum bytes offered to a single read/write, 1..=16384.
    pub io_bytes: usize,
    /// All connect/configure/read/write attempts, including WouldBlock/Interrupted.
    pub io_calls: u64,
    /// One blocking connect timeout, at most five seconds and the remaining lease.
    pub connect_timeout_ns: u64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            request_bytes: 32768,
            header_bytes: 16384,
            body_bytes: 262144,
            wire_bytes: 524288,
            io_bytes: 4096,
            io_calls: 16384,
            connect_timeout_ns: 5_000_000_000,
        }
    }
}

impl HttpLimits {
    fn validate(self) -> Result<(), HttpError> {
        if !(1..=65536).contains(&self.request_bytes)
            || !(4..=32768).contains(&self.header_bytes)
            || !(1..=1_048_576).contains(&self.body_bytes)
            || !(4..=2_097_152).contains(&self.wire_bytes)
            || !(1..=16384).contains(&self.io_bytes)
            || !(1..=1_000_000).contains(&self.io_calls)
            || !(1..=5_000_000_000).contains(&self.connect_timeout_ns)
        {
            return Err(HttpError::Configuration);
        }
        Ok(())
    }
}

/// Non-disclosing transport/framing failures. No error contains server text,
/// address, target, credential, nonce, SOAP body or operating-system error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    /// Invalid pinned route, bounded request, limit or lease.
    Configuration,
    /// Admission time regressed; this exchange is fenced.
    ClockReversed,
    /// The absolute exchange lease expired.
    Deadline,
    /// Live authority refused an operation.
    Denied(HttpDenial),
    /// A socket, wire, header, body or chunk count ceiling was reached.
    Limit,
    /// A bounded allocation was refused.
    Allocation,
    /// Actual connected peer differs from the frozen address.
    PeerMismatch,
    /// A nonempty write accepted no bytes.
    WriteZero,
    /// Eight consecutive interrupted syscalls, without an internal retry loop.
    Interrupted,
    /// Invalid/ambiguous HTTP framing or duplicate security-relevant headers.
    Malformed,
    /// Unsupported HTTP coding, upgrade or authentication scheme.
    Unsupported,
    /// Peer EOF before explicit framing completed.
    Truncated,
    /// Bytes followed a complete response in the same read.
    TrailingResponse,
    /// No fully framed response is available yet.
    NotComplete,
    /// The response was already taken or this owner retired.
    Closed,
    /// Payload-free classification of a syscall failure.
    Io {
        /// The failing socket boundary.
        operation: HttpOperation,
        /// OS error kind only.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ONVIF HTTP transport refused: {self:?}")
    }
}
impl std::error::Error for HttpError {}

/// Actual bounded socket work, including partial writes before a later refusal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpTotals {
    /// Connect, peer verification, configuration, read and write calls combined.
    pub io_calls: u64,
    /// Read calls, including EOF, WouldBlock and Interrupted.
    pub read_calls: u64,
    /// Write calls, including WouldBlock and Interrupted.
    pub write_calls: u64,
    /// Request bytes actually accepted by the socket.
    pub sent_bytes: u64,
    /// Response bytes actually returned by the socket.
    pub received_bytes: u64,
}

/// Bounded progress, never a claim of SOAP validity, device identity or streaming.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProgress {
    /// One bounded unit advanced; the response is not yet releasable.
    Advanced,
    /// WouldBlock/Interrupted; the owning runtime schedules the next bounded wait.
    Pending,
    /// HTTP framing is complete; release still checks live authority.
    Complete,
}

/// One fully framed response. Payload access is explicit and Debug is redacted.
pub struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    digest_challenge: Option<String>,
    body: Vec<u8>,
}

impl HttpResponse {
    /// Final HTTP status, distinct from SOAP success.
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Optional exact Content-Type with surrounding HTTP whitespace removed.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
    /// Complete transfer-decoded bytes; the SOAP owner must validate them.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// At most one bounded Digest challenge; the authentication owner must validate
    /// its pinned realm, algorithm, nonce and qop before any credential use.
    pub fn digest_challenge(&self) -> Option<&str> {
        self.digest_challenge.as_deref()
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        // Best-effort clearing only; this is not a guaranteed-zeroization claim.
        self.body.fill(0);
    }
}

trait HttpSocket: Read + Write + Send {}
impl HttpSocket for TcpStream {}

/// A single read-only POST and response, with no automatic authentication/retry.
/// Dropping closes its sole socket; cleanup needs no renewed network authority.
pub struct HttpExchange {
    route: HttpRoute,
    limits: HttpLimits,
    deadline_ns: u64,
    last_ns: u64,
    socket: Option<Box<dyn HttpSocket>>,
    request: Vec<u8>,
    written: usize,
    pending: Option<Vec<u8>>,
    eof: bool,
    decoder: framing::Decoder,
    totals: HttpTotals,
    failure: Option<HttpError>,
    interruptions: u8,
    taken: bool,
}

impl fmt::Debug for HttpExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpExchange")
            .field("route", &self.route)
            .field("totals", &self.totals)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl HttpExchange {
    /// Connect once to the pinned address. The typed request can only be built by
    /// the read-only ONVIF request constructors. The caller supplies Digest
    /// authorization only for this exact origin/target and revalidates its secret
    /// lease through the live authority at every subsequent socket boundary.
    pub fn connect(
        route: HttpRoute,
        request: &SoapRequest,
        authorization: Option<&DigestAuthorization>,
        limits: HttpLimits,
        now_ns: u64,
        deadline_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<Self, HttpError> {
        limits.validate()?;
        if now_ns >= deadline_ns {
            return Err(HttpError::Configuration);
        }
        let request = make_request(&route, request, authorization, limits.request_bytes)?;
        let mut owner = Self {
            route,
            limits,
            deadline_ns,
            last_ns: now_ns,
            socket: None,
            request,
            written: 0,
            pending: None,
            eof: false,
            decoder: framing::Decoder::new(limits),
            totals: HttpTotals::default(),
            failure: None,
            interruptions: 0,
            taken: false,
        };
        owner.io_admit(HttpOperation::Connect, now_ns, authority)?;
        let result = TcpStream::connect_timeout(
            &owner.route.peer,
            Duration::from_nanos(limits.connect_timeout_ns.min(deadline_ns - now_ns)),
        );
        owner.admit(HttpOperation::Connect, now_ns, authority)?;
        let socket = result.map_err(|error| io_error(HttpOperation::Connect, error))?;
        owner.io_admit(HttpOperation::Configure, now_ns, authority)?;
        let result = socket.peer_addr();
        owner.admit(HttpOperation::Configure, now_ns, authority)?;
        if result.map_err(|error| io_error(HttpOperation::Configure, error))? != owner.route.peer {
            return Err(HttpError::PeerMismatch);
        }
        owner.io_admit(HttpOperation::Configure, now_ns, authority)?;
        let result = socket.set_nonblocking(true);
        owner.admit(HttpOperation::Configure, now_ns, authority)?;
        result.map_err(|error| io_error(HttpOperation::Configure, error))?;
        owner.socket = Some(Box::new(socket));
        Ok(owner)
    }

    /// The immutable exact route checked at every boundary.
    pub fn route(&self) -> &HttpRoute {
        &self.route
    }
    /// Socket work observed so far, even after cancellation or partial I/O.
    pub fn totals(&self) -> HttpTotals {
        self.totals
    }
    /// First latched refusal; no step retries a failed exchange.
    pub fn failure(&self) -> Option<HttpError> {
        self.failure
    }

    /// Advance at most one socket read/write or one bounded parse unit. No wait,
    /// clock read, auth retry or background task is hidden inside this operation.
    pub fn step(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<HttpProgress, HttpError> {
        let result = self.advance(now_ns, authority);
        if let Err(error) = result {
            self.fence(error);
        }
        result
    }

    fn advance(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<HttpProgress, HttpError> {
        self.admit(HttpOperation::Poll, now_ns, authority)?;
        if self.taken {
            return Err(HttpError::Closed);
        }
        if self.decoder.complete() {
            self.socket = None;
            return Ok(HttpProgress::Complete);
        }
        if let Some(bytes) = self.pending.take() {
            self.admit(HttpOperation::Parse, now_ns, authority)?;
            let parsed = self.decoder.push(&bytes);
            self.admit(HttpOperation::Parse, now_ns, authority)?;
            parsed?;
            if self.decoder.complete() {
                self.socket = None;
                return Ok(HttpProgress::Complete);
            }
            return Ok(HttpProgress::Advanced);
        }
        if self.eof {
            self.admit(HttpOperation::Parse, now_ns, authority)?;
            let parsed = self.decoder.finish();
            self.admit(HttpOperation::Parse, now_ns, authority)?;
            parsed?;
            return Ok(HttpProgress::Complete);
        }
        if self.written < self.request.len() {
            return self.write_request(now_ns, authority);
        }
        self.read_response(now_ns, authority)
    }

    /// Transfer a complete response once. A cancelled/expired/revoked exchange
    /// cannot publish a success that arrived just before its authority changed.
    pub fn take_response(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<HttpResponse, HttpError> {
        if let Err(error) = self.admit(HttpOperation::Release, now_ns, authority) {
            self.fence(error);
            return Err(error);
        }
        if self.taken {
            return Err(HttpError::Closed);
        }
        let response = self.decoder.take_response()?;
        self.socket = None;
        self.taken = true;
        Ok(response)
    }

    fn admit(
        &mut self,
        operation: HttpOperation,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<(), HttpError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now_ns < self.last_ns {
            return Err(HttpError::ClockReversed);
        }
        if now_ns >= self.deadline_ns {
            return Err(HttpError::Deadline);
        }
        authority
            .checkpoint(&self.route, operation, now_ns, self.deadline_ns)
            .map_err(HttpError::Denied)?;
        self.last_ns = now_ns;
        Ok(())
    }

    fn io_admit(
        &mut self,
        operation: HttpOperation,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<(), HttpError> {
        if self.totals.io_calls >= self.limits.io_calls {
            return Err(HttpError::Limit);
        }
        self.admit(operation, now_ns, authority)?;
        self.totals.io_calls += 1;
        Ok(())
    }

    fn fence(&mut self, error: HttpError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.socket = None;
        self.request.fill(0);
        self.request.clear();
    }

    fn write_request(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<HttpProgress, HttpError> {
        let end = self.request.len().min(self.written + self.limits.io_bytes);
        self.io_admit(HttpOperation::Write, now_ns, authority)?;
        self.totals.write_calls += 1;
        let result = self
            .socket
            .as_mut()
            .ok_or(HttpError::Closed)?
            .write(&self.request[self.written..end]);
        if let Ok(count) = result {
            self.written += count;
            self.totals.sent_bytes += count as u64;
        }
        self.admit(HttpOperation::Write, now_ns, authority)?;
        match result {
            Ok(0) => Err(HttpError::WriteZero),
            Ok(_) => {
                self.interruptions = 0;
                if self.written == self.request.len() {
                    self.request.fill(0);
                    self.request.clear();
                    self.written = 0;
                }
                Ok(HttpProgress::Advanced)
            }
            Err(error) => self.pending_io(HttpOperation::Write, error),
        }
    }

    fn read_response(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpAuthority,
    ) -> Result<HttpProgress, HttpError> {
        let remaining = self
            .limits
            .wire_bytes
            .saturating_sub(self.totals.received_bytes as usize);
        if remaining == 0 {
            return Err(HttpError::Limit);
        }
        let count = remaining.min(self.limits.io_bytes);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| HttpError::Allocation)?;
        bytes.resize(count, 0);
        self.io_admit(HttpOperation::Read, now_ns, authority)?;
        self.totals.read_calls += 1;
        let result = self
            .socket
            .as_mut()
            .ok_or(HttpError::Closed)?
            .read(&mut bytes);
        if let Ok(count) = result {
            bytes.truncate(count);
            self.totals.received_bytes += count as u64;
            if count == 0 {
                self.eof = true;
                self.socket = None;
            } else {
                // Account for actual returned bytes before post-I/O revocation.
                // They cannot be parsed or released after a subsequent denial.
                self.pending = Some(bytes);
            }
        }
        self.admit(HttpOperation::Read, now_ns, authority)?;
        match result {
            Ok(_) => {
                self.interruptions = 0;
                Ok(HttpProgress::Advanced)
            }
            Err(error) => self.pending_io(HttpOperation::Read, error),
        }
    }

    fn pending_io(
        &mut self,
        operation: HttpOperation,
        error: io::Error,
    ) -> Result<HttpProgress, HttpError> {
        match error.kind() {
            io::ErrorKind::WouldBlock => {
                self.interruptions = 0;
                Ok(HttpProgress::Pending)
            }
            io::ErrorKind::Interrupted => {
                self.interruptions += 1;
                if self.interruptions >= 8 {
                    Err(HttpError::Interrupted)
                } else {
                    Ok(HttpProgress::Pending)
                }
            }
            _ => Err(io_error(operation, error)),
        }
    }
}

impl Drop for HttpExchange {
    fn drop(&mut self) {
        self.request.fill(0);
        if let Some(bytes) = &mut self.pending {
            bytes.fill(0);
        }
    }
}

fn io_error(operation: HttpOperation, error: io::Error) -> HttpError {
    HttpError::Io {
        operation,
        kind: error.kind(),
    }
}

fn make_request(
    route: &HttpRoute,
    request: &SoapRequest,
    authorization: Option<&DigestAuthorization>,
    limit: usize,
) -> Result<Vec<u8>, HttpError> {
    let action = request.action();
    if !matches!(
        action,
        "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
            | "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
            | "http://www.onvif.org/ver10/media/wsdl/GetProfiles"
            | "http://www.onvif.org/ver10/media/wsdl/GetStreamUri"
            | "http://www.onvif.org/ver10/device/wsdl/GetServices"
            | "http://www.onvif.org/ver20/media/wsdl/GetProfiles"
            | "http://www.onvif.org/ver20/media/wsdl/GetStreamUri"
    ) || request.body().len() > limit
        || (authorization.is_some() && request.has_username_token())
    {
        return Err(HttpError::Configuration);
    }
    let authentication = authorization
        .map(|value| format!("Authorization: {}\r\n", value.expose()))
        .unwrap_or_default();
    let mut header = format!(
        concat!(
            "POST {} HTTP/1.1\r\nHost: {}\r\n",
            "Content-Type: application/soap+xml; charset=utf-8; action=\"{}\"\r\n",
            "Accept: application/soap+xml\r\nAccept-Encoding: identity\r\n",
            "Content-Length: {}\r\n{}Connection: close\r\n\r\n"
        ),
        route.target,
        route.authority,
        action,
        request.body().len(),
        authentication,
    )
    .into_bytes();
    if header
        .len()
        .checked_add(request.body().len())
        .is_none_or(|total| total > limit)
    {
        header.fill(0);
        return Err(HttpError::Limit);
    }
    header
        .try_reserve_exact(request.body().len())
        .map_err(|_| HttpError::Allocation)?;
    header.extend_from_slice(request.body());
    Ok(header)
}

#[cfg(test)]
mod tests;
