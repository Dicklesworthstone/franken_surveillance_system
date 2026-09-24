#![forbid(unsafe_code)]
//! Owner-authorized native HTTP MJPEG acquisition. No DNS, redirects, credentials,
//! reconnect, worker, clock reads or invented camera timestamps. The existing HTTP
//! and multipart parsers own protocol semantics. Raw reads must be acknowledged
//! before parsing; acknowledgement is a caller custody obligation, not proof of it.

use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::http::{
    EntityData, HttpEnd, HttpError, HttpEvent, HttpLimits, HttpRemainder, HttpResponseStream,
    ResponseHead,
};
use fss_codec_mjpeg::http_mjpeg::{
    HttpJpegFrame, HttpMjpegEnd, HttpMjpegError, HttpMjpegRemainder, HttpMultipartStream,
};
use fss_codec_mjpeg::multipart::MultipartLimits;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// No implicit plaintext fallback, and no claim of authenticated camera identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCameraSecurity {
    /// Independently approved plaintext on this exact operator-owned route.
    OwnerApprovedPlaintext,
}
/// Immutable requested route, not a capability. Debug omits address and target.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpCameraRoute {
    basis: StreamBasis,
    peer: SocketAddr,
    authority: String,
    target: String,
    security: HttpCameraSecurity,
}
impl HttpCameraRoute {
    /// Resolve the exact peer outside this API. Targets are absolute ASCII paths;
    /// query strings, userinfo, percent escapes and fragments are deliberately not
    /// admitted, so credentials cannot accidentally become request/archive text.
    pub fn new(
        basis: StreamBasis,
        peer: SocketAddr,
        authority: &str,
        target: &str,
        security: HttpCameraSecurity,
    ) -> Result<Self, HttpCameraError> {
        if basis.source == [0; 32]
            || basis.generation == 0
            || peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || authority.is_empty()
            || authority.len() > 512
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            || !target.starts_with('/')
            || target.starts_with("//")
            || target.len() > 2048
            || !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
        {
            return Err(HttpCameraError::Configuration);
        }
        Ok(Self {
            basis,
            peer,
            authority: authority.to_owned(),
            target: target.to_owned(),
            security,
        })
    }
    /// Original plaintext-response identity and independently issued generation.
    pub fn basis(&self) -> StreamBasis {
        self.basis
    }
    /// Exact authorized peer; never resolved or redirected here.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
    /// Exact owner-supplied Host mapping approved independently by the authority owner.
    pub fn authority(&self) -> &str {
        &self.authority
    }
    /// Explicit non-secret request path.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Explicit transport-protection limitation.
    pub fn security(&self) -> HttpCameraSecurity {
        self.security
    }
}
impl fmt::Debug for HttpCameraRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCameraRoute")
            .field("basis", &self.basis)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}
/// Every I/O and state-advancement boundary is checked by the same live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCameraOperation {
    /// One bounded TCP attempt.
    Connect,
    /// Configure/check the connected socket.
    Configure,
    /// One nonblocking request write, including post-I/O revalidation.
    Write,
    /// One nonblocking read, including post-I/O revalidation.
    Read,
    /// Parse previously acknowledged source bytes.
    Parse,
    /// Run or resume bounded learned analysis of this exact retained frame.
    Analyze,
    /// Owner explicitly accepted responsibility for the complete derived result.
    ReleaseResult,
    /// Owner explicitly accepted responsibility for these exact raw bytes.
    AcknowledgeWire,
    /// Transfer one complete source-mapped frame out of this owner.
    ReleaseFrame,
    /// Check revocation/deadline while backpressured or waiting.
    Poll,
}
/// Non-disclosing live-authority refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCameraDenial {
    /// Exact route or operation is not authorized.
    Unauthorized,
    /// Previously granted authority was revoked.
    Revoked,
    /// Owner requested cancellation.
    Cancelled,
    /// Independent live clock passed the deadline.
    Deadline,
    /// Independent owner resource allowance exhausted.
    Budget,
}
/// Implement with the owning Cx or equivalent explicit capability. This probe MUST
/// check actual elapsed time, route, principal, generation, cancellation and current
/// authorization itself, including after connect/read/write. `now_ns` is admission
/// time, not a post-syscall wall-clock observation. No permissive implementation exists.
pub trait HttpCameraAuthority {
    /// Check this exact operation and lease without exposing policy/secret strings.
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        operation: HttpCameraOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpCameraDenial>;
}
/// Connection-wide bounds; none refill automatically on a new frame.
#[derive(Clone, Copy, Debug)]
pub struct HttpCameraLimits {
    /// Existing complete HTTP/header/entity/transfer ceilings.
    pub http: HttpLimits,
    /// Existing complete MIME frame/header/wrapper ceilings.
    pub multipart: MultipartLimits,
    /// At most 65536 bytes in a socket read and its retained raw buffer.
    pub read_bytes: usize,
    /// Combined read/write attempts, including WouldBlock and Interrupted.
    pub io_calls: u64,
    /// Stop after this many complete parts; hitting it is NOT clean response EOF.
    pub frames: u64,
    /// Complete JPEG source-map bound, never a top-k span selection.
    pub source_runs: usize,
    /// One blocking connect timeout, capped by the lease and 60 seconds.
    pub connect_timeout_ns: u64,
}
impl Default for HttpCameraLimits {
    fn default() -> Self {
        Self {
            http: HttpLimits::default(),
            multipart: MultipartLimits::default(),
            read_bytes: 16384,
            io_calls: 1_000_000,
            frames: 100_000,
            source_runs: 65536,
            connect_timeout_ns: 5_000_000_000,
        }
    }
}
impl HttpCameraLimits {
    fn validate(self, basis: StreamBasis) -> Result<HttpResponseStream, HttpCameraError> {
        if !(1..=65536).contains(&self.read_bytes)
            || self.io_calls == 0
            || !(1..=1_000_000).contains(&self.frames)
            || !(1..=65536).contains(&self.source_runs)
            || !(1..=60_000_000_000).contains(&self.connect_timeout_ns)
            || !(4..=16 * 1024 * 1024).contains(&self.multipart.frame_bytes)
            || !(4..=16384).contains(&self.multipart.header_bytes)
            || self.multipart.wrapper_bytes > 65536
        {
            return Err(HttpCameraError::Configuration);
        }
        HttpResponseStream::new(basis, self.http).map_err(HttpCameraError::Http)
    }
}
/// Errors never disclose HTTP headers, paths, addresses, pixels or operating-system text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCameraError {
    /// Invalid route, limits or lease before connection.
    Configuration,
    /// Admission time regressed. This caller error does not advance the owner.
    ClockReversed,
    /// Exact raw/frame acknowledgement did not match; input remains owned.
    ReceiptMismatch,
    /// Absolute session lease expired.
    Deadline,
    /// Live authority refused; socket closes and source remains recoverable.
    Denied(HttpCameraDenial),
    /// Socket byte/call allowance exhausted; NOT EOF.
    NetworkLimit,
    /// Owner-selected part count reached; NOT EOF or scene absence.
    FrameLimit,
    /// Bounded allocation failed.
    Allocation,
    /// Connected peer differs from the requested route.
    PeerMismatch,
    /// Nonempty write accepted zero bytes; sent prefix remains accounted for.
    WriteZero,
    /// Eight consecutive interrupted syscalls, without an internal retry loop.
    Interrupted,
    /// A second response/trailing byte was returned in the same read.
    TrailingResponse,
    /// Existing HTTP parser refused. Its original source is still retained/acknowledged.
    Http(HttpError),
    /// Existing MIME/source-map parser refused.
    Multipart(HttpMjpegError),
    /// Payload-free OS error classification.
    Io {
        /// Boundary producing the error.
        operation: HttpCameraOperation,
        /// OS error class only.
        kind: io::ErrorKind,
    },
}
impl fmt::Display for HttpCameraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP camera refused: {self:?}")
    }
}
impl std::error::Error for HttpCameraError {}
/// Connection attempt is distinguished from refusal-before-I/O.
#[derive(Debug)]
pub struct HttpCameraConnectFailure {
    /// Non-disclosing reason; any created socket has been released.
    pub reason: HttpCameraError,
    /// The peer may have seen TCP connect, not an HTTP request or a frame.
    pub attempted: bool,
}
impl fmt::Display for HttpCameraConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HttpCameraConnectFailure {}
/// Exact immutable raw-read acknowledgement key. A matching hash is NOT a custody proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpWireReceipt {
    /// Original plaintext response stream.
    pub basis: StreamBasis,
    /// Half-open absolute plaintext-response offsets, before HTTP dechunking.
    pub range: [u64; 2],
    /// Hash of all bytes returned by this successful read.
    pub sha256: [u8; 32],
    /// Owner admission time of the read; NEVER camera capture time.
    pub admitted_ns: u64,
}
/// Raw input remains borrowed until acknowledged and fully parsed. Debug hides bytes.
pub struct HttpWireRead {
    receipt: HttpWireReceipt,
    bytes: Vec<u8>,
    acknowledged: bool,
    parsed: usize,
}
impl HttpWireRead {
    /// Exact unchanged bytes, including possibly sensitive response headers.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact original range/hash/owner-admission time.
    pub fn receipt(&self) -> HttpWireReceipt {
        self.receipt
    }
    /// Whether the caller accepted custody responsibility, not proof of durable storage.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }
    /// Prefix already supplied to HTTP framing, including any failed call's prefix.
    pub fn parsed_bytes(&self) -> usize {
        self.parsed
    }
}
impl fmt::Debug for HttpWireRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpWireRead")
            .field("receipt", &self.receipt)
            .field("acknowledged", &self.acknowledged)
            .field("parsed", &self.parsed)
            .finish()
    }
}
/// Counts describe local I/O only, not remote acknowledgement, capture or durability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpCameraTotals {
    /// Exact locally accepted GET prefix.
    pub sent_bytes: u64,
    /// All successful raw reads, including a post-read revocation.
    pub received_bytes: u64,
    /// Read attempts, including bounded nonblocking/interruption results.
    pub read_calls: u64,
    /// Write attempts, including bounded nonblocking/interruption results.
    pub write_calls: u64,
    /// Complete source-mapped MIME parts, not necessarily decodable pictures.
    pub frames: u64,
    /// An actual zero-byte socket read occurred, not limit exhaustion.
    pub peer_eof: bool,
}
/// Bounded owner progress; waiting never spins inside the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpCameraStep {
    /// WouldBlock or bounded interruption; wait externally for readiness/deadline.
    Pending,
    /// One request prefix or one framing operation advanced.
    Advanced,
    /// Save/handle pending_wire() and acknowledge its exact receipt before parsing.
    WireReady(HttpWireReceipt),
    /// A complete part is retained until take_frame(); no new source is read meanwhile.
    FrameReady,
    /// Both HTTP and MIME terminated successfully. Inspect completion() for how.
    Complete,
}
// The owner may move into a runtime-owned task; no borrowed I/O state is stored.
trait CameraSocket: Read + Write + Send {}
impl<T: Read + Write + Send> CameraSocket for T {}

/// One native connection and one outstanding raw read/entity/frame. Drop closes only;
/// it sends no further request. Call retire() to recover all unfinished source objects.
pub struct HttpCamera {
    route: HttpCameraRoute,
    limits: HttpCameraLimits,
    deadline: u64,
    clock: u64,
    socket: Option<Box<dyn CameraSocket>>,
    request: Vec<u8>,
    sent: usize,
    http: HttpResponseStream,
    multipart: Option<HttpMultipartStream>,
    head: Option<ResponseHead>,
    wire: Option<HttpWireRead>,
    entity: Option<(EntityData, usize)>,
    frame: Option<HttpJpegFrame>,
    end: Option<HttpEnd>,
    complete: Option<HttpMjpegEnd>,
    totals: HttpCameraTotals,
    failure: Option<HttpCameraError>,
    interruptions: u8,
}
impl fmt::Debug for HttpCamera {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCamera")
            .field("route", &self.route)
            .field("totals", &self.totals)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
impl HttpCamera {
    /// One connection attempt after complete route/limit/request validation. No DNS,
    /// fallback peer, TLS downgrade, authentication, redirect or automatic retry.
    pub fn connect(
        route: HttpCameraRoute,
        limits: HttpCameraLimits,
        now_ns: u64,
        deadline_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<Self, HttpCameraConnectFailure> {
        let mut attempted = false;
        let result = (|| {
            let http = limits.validate(route.basis)?;
            if now_ns >= deadline_ns {
                return Err(HttpCameraError::Configuration);
            }
            let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nAccept: multipart/x-mixed-replace\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", route.target, route.authority).into_bytes();
            authority
                .checkpoint(&route, HttpCameraOperation::Connect, now_ns, deadline_ns)
                .map_err(HttpCameraError::Denied)?;
            attempted = true;
            let socket = TcpStream::connect_timeout(
                &route.peer,
                Duration::from_nanos(limits.connect_timeout_ns.min(deadline_ns - now_ns)),
            )
            .map_err(|e| io_error(HttpCameraOperation::Connect, e))?;
            authority
                .checkpoint(&route, HttpCameraOperation::Configure, now_ns, deadline_ns)
                .map_err(HttpCameraError::Denied)?;
            if socket
                .peer_addr()
                .map_err(|e| io_error(HttpCameraOperation::Configure, e))?
                != route.peer
            {
                return Err(HttpCameraError::PeerMismatch);
            }
            socket
                .set_nonblocking(true)
                .map_err(|e| io_error(HttpCameraOperation::Configure, e))?;
            authority
                .checkpoint(&route, HttpCameraOperation::Configure, now_ns, deadline_ns)
                .map_err(HttpCameraError::Denied)?;
            Ok(Self {
                route,
                limits,
                deadline: deadline_ns,
                clock: now_ns,
                socket: Some(Box::new(socket)),
                request,
                sent: 0,
                http,
                multipart: None,
                head: None,
                wire: None,
                entity: None,
                frame: None,
                end: None,
                complete: None,
                totals: HttpCameraTotals::default(),
                failure: None,
                interruptions: 0,
            })
        })();
        result.map_err(|reason| HttpCameraConnectFailure { reason, attempted })
    }
    /// Fixed route and source generation.
    pub fn route(&self) -> &HttpCameraRoute {
        &self.route
    }
    /// Local syscall/byte/part accounting, including unsuccessful progress.
    pub fn totals(&self) -> HttpCameraTotals {
        self.totals
    }
    /// First terminal error. Later polling never retries this connection.
    pub fn failure(&self) -> Option<HttpCameraError> {
        self.failure
    }
    /// Original read to retain before acknowledging. Available even after fatal refusal.
    pub fn pending_wire(&self) -> Option<&HttpWireRead> {
        self.wire.as_ref()
    }
    /// Original admitted HTTP header; response values must not be logged by default.
    pub fn response_head(&self) -> Option<&ResponseHead> {
        self.head.as_ref()
    }
    /// Original complete source-mapped frame, including after revocation/cancellation.
    pub fn pending_frame(&self) -> Option<&HttpJpegFrame> {
        self.frame.as_ref()
    }
    /// Both termination receipts; no successful completion is fabricated on disconnect/limit.
    pub fn completion(&self) -> Option<&HttpMjpegEnd> {
        self.complete.as_ref()
    }
    /// Explicitly accept custody responsibility for this raw read. Save it FIRST.
    /// This method performs no storage write and makes no durable-publication claim.
    pub fn acknowledge_wire(
        &mut self,
        receipt: HttpWireReceipt,
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<(), HttpCameraError> {
        if self.wire.as_ref().is_none_or(|w| w.receipt != receipt) {
            return Err(HttpCameraError::ReceiptMismatch);
        }
        self.admit(HttpCameraOperation::AcknowledgeWire, now_ns, authority)?;
        if let Some(wire) = &mut self.wire {
            wire.acknowledged = true;
        }
        Ok(())
    }
    /// Transfer exactly the named part. Camera capture time is intentionally absent;
    /// the downstream owner must supply independent capture/clock evidence.
    pub fn take_frame(
        &mut self,
        ordinal: u64,
        encoded_sha256: [u8; 32],
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
    ) -> Result<HttpJpegFrame, HttpCameraError> {
        if self.frame.as_ref().is_none_or(|f| {
            let r = f.part().receipt();
            r.ordinal != ordinal || r.encoded_sha256 != encoded_sha256
        }) {
            return Err(HttpCameraError::ReceiptMismatch);
        }
        self.admit(HttpCameraOperation::ReleaseFrame, now_ns, authority)?;
        self.frame.take().ok_or(HttpCameraError::ReceiptMismatch)
    }
    /// At most one nonblocking syscall OR one existing parser call. All previously
    /// accepted source is retained before post-I/O authority checks. A parser failure
    /// is terminal, not a request to replay its partially consumed input.
    pub fn step(
        &mut self,
        now_ns: u64,
        authority: &dyn HttpCameraAuthority,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<HttpCameraStep, HttpCameraError> {
        self.admit(HttpCameraOperation::Poll, now_ns, authority)?;
        let result = self.advance(now_ns, authority, budget);
        if let Err(error) = result {
            self.fence(error);
        }
        result
    }
    fn advance(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
        budget: &mut DecodeBudget<'_>,
    ) -> Result<HttpCameraStep, HttpCameraError> {
        if self.frame.is_some() {
            return Ok(HttpCameraStep::FrameReady);
        }
        if self.complete.is_some() {
            return Ok(HttpCameraStep::Complete);
        }
        if self.totals.frames == self.limits.frames {
            return Err(HttpCameraError::FrameLimit);
        }
        if self.sent < self.request.len() {
            return self.write_request(now, auth);
        }
        if let Some(wire) = &self.wire
            && !wire.acknowledged
        {
            return Ok(HttpCameraStep::WireReady(wire.receipt));
        }
        if self.entity.is_some() {
            self.admit(HttpCameraOperation::Parse, now, auth)?;
            let (data, cursor) = self.entity.as_mut().ok_or(HttpCameraError::Configuration)?;
            let parser = self
                .multipart
                .as_mut()
                .ok_or(HttpCameraError::Configuration)?;
            let step = parser.push(data, *cursor, budget);
            match step {
                Err(e) => {
                    *cursor += e.consumed;
                    return Err(HttpCameraError::Multipart(e.error));
                }
                Ok(s) => {
                    *cursor += s.consumed;
                    if let Some(frame) = s.frame {
                        self.frame = Some(frame);
                        self.totals.frames += 1;
                    }
                    if *cursor == data.bytes().len() {
                        self.entity = None;
                    }
                }
            }
            return Ok(if self.frame.is_some() {
                HttpCameraStep::FrameReady
            } else {
                HttpCameraStep::Advanced
            });
        }
        if self.wire.as_ref().is_some_and(|w| w.parsed < w.bytes.len()) {
            self.admit(HttpCameraOperation::Parse, now, auth)?;
            if self.http.body_complete() {
                return Err(HttpCameraError::TrailingResponse);
            }
            let wire = self.wire.as_mut().ok_or(HttpCameraError::Configuration)?;
            let step = self.http.push(
                wire.receipt.range[0] + wire.parsed as u64,
                &wire.bytes[wire.parsed..],
                budget,
            );
            let event = match step {
                Err(e) => {
                    wire.parsed += e.consumed;
                    return Err(HttpCameraError::Http(e.error));
                }
                Ok(s) => {
                    wire.parsed += s.consumed;
                    s.event
                }
            };
            match event {
                Some(HttpEvent::Head(head)) => {
                    self.head = Some(head);
                    self.multipart = Some(
                        HttpMultipartStream::new(
                            self.head.as_ref().ok_or(HttpCameraError::Configuration)?,
                            self.limits.multipart,
                            self.limits.source_runs,
                            budget,
                        )
                        .map_err(HttpCameraError::Multipart)?,
                    );
                }
                Some(HttpEvent::Data(data)) => self.entity = Some((data, 0)),
                Some(HttpEvent::Control(_)) | None => {} // exact raw wire was acknowledged first
            }
            return Ok(HttpCameraStep::Advanced);
        }
        // Only acknowledged AND fully parsed raw buffers can leave this owner.
        self.wire = None;
        if self.http.body_complete() || self.totals.peer_eof {
            self.admit(HttpCameraOperation::Parse, now, auth)?;
            let end = self.http.finish(budget).map_err(HttpCameraError::Http)?;
            self.end = Some(end); // survives a later multipart finalization failure
            let mut complete = self
                .multipart
                .as_mut()
                .ok_or(HttpCameraError::Configuration)?
                .finish(end, budget)
                .map_err(HttpCameraError::Multipart)?;
            self.frame = complete.final_frame.take();
            if self.frame.is_some() {
                self.totals.frames += 1;
            }
            self.complete = Some(complete);
            self.socket = None;
            return Ok(if self.frame.is_some() {
                HttpCameraStep::FrameReady
            } else {
                HttpCameraStep::Complete
            });
        }
        self.read_source(now, auth)
    }
    fn admit(
        &mut self,
        op: HttpCameraOperation,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<(), HttpCameraError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.clock {
            return Err(HttpCameraError::ClockReversed);
        }
        let result = if now >= self.deadline {
            Err(HttpCameraError::Deadline)
        } else {
            auth.checkpoint(&self.route, op, now, self.deadline)
                .map_err(HttpCameraError::Denied)
        };
        if let Err(e) = result {
            self.fence(e);
            return Err(e);
        }
        self.clock = now;
        Ok(())
    }
    fn fence(&mut self, error: HttpCameraError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.socket = None;
    }
    fn io_room(&self) -> Result<(), HttpCameraError> {
        if self.totals.read_calls >= self.limits.io_calls.saturating_sub(self.totals.write_calls) {
            Err(HttpCameraError::NetworkLimit)
        } else {
            Ok(())
        }
    }
    fn write_request(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<HttpCameraStep, HttpCameraError> {
        self.io_room()?;
        self.admit(HttpCameraOperation::Write, now, auth)?;
        self.totals.write_calls += 1;
        let end = self.request.len().min(self.sent + self.limits.read_bytes);
        let result = self
            .socket
            .as_mut()
            .ok_or(HttpCameraError::Configuration)?
            .write(&self.request[self.sent..end]);
        if let Ok(n) = result {
            self.sent += n;
            self.totals.sent_bytes += n as u64;
        }
        self.admit(HttpCameraOperation::Write, now, auth)?;
        match result {
            Ok(0) => Err(HttpCameraError::WriteZero),
            Ok(_) => {
                self.interruptions = 0;
                Ok(HttpCameraStep::Advanced)
            }
            Err(e) => self.nonblocking(HttpCameraOperation::Write, e),
        }
    }
    fn read_source(
        &mut self,
        now: u64,
        auth: &dyn HttpCameraAuthority,
    ) -> Result<HttpCameraStep, HttpCameraError> {
        self.io_room()?;
        let remaining = self
            .limits
            .http
            .wire_bytes
            .saturating_sub(self.totals.received_bytes);
        if remaining == 0 {
            return Err(HttpCameraError::NetworkLimit);
        }
        let n = remaining.min(self.limits.read_bytes as u64) as usize;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(n)
            .map_err(|_| HttpCameraError::Allocation)?;
        bytes.resize(n, 0);
        self.admit(HttpCameraOperation::Read, now, auth)?;
        self.totals.read_calls += 1;
        let result = self
            .socket
            .as_mut()
            .ok_or(HttpCameraError::Configuration)?
            .read(&mut bytes);
        if let Ok(n) = result {
            if n == 0 {
                self.totals.peer_eof = true;
                self.socket = None;
            } else {
                bytes.truncate(n);
                let start = self.totals.received_bytes;
                self.totals.received_bytes += n as u64;
                let receipt = HttpWireReceipt {
                    basis: self.route.basis,
                    range: [start, self.totals.received_bytes],
                    sha256: ContentDigest::sha256(&bytes).bytes(),
                    admitted_ns: now,
                };
                // Preserve actual source BEFORE post-read cancellation/revocation is consulted.
                self.wire = Some(HttpWireRead {
                    receipt,
                    bytes,
                    acknowledged: false,
                    parsed: 0,
                });
            }
        }
        self.admit(HttpCameraOperation::Read, now, auth)?;
        match result {
            Ok(0) => {
                self.interruptions = 0;
                Ok(HttpCameraStep::Advanced)
            }
            Ok(_) => {
                self.interruptions = 0;
                Ok(HttpCameraStep::WireReady(
                    self.wire
                        .as_ref()
                        .ok_or(HttpCameraError::Configuration)?
                        .receipt,
                ))
            }
            Err(e) => self.nonblocking(HttpCameraOperation::Read, e),
        }
    }
    fn nonblocking(
        &mut self,
        op: HttpCameraOperation,
        e: io::Error,
    ) -> Result<HttpCameraStep, HttpCameraError> {
        match e.kind() {
            io::ErrorKind::WouldBlock => {
                self.interruptions = 0;
                Ok(HttpCameraStep::Pending)
            }
            io::ErrorKind::Interrupted => {
                self.interruptions += 1;
                if self.interruptions >= 8 {
                    Err(HttpCameraError::Interrupted)
                } else {
                    Ok(HttpCameraStep::Pending)
                }
            }
            _ => Err(io_error(op, e)),
        }
    }
    /// Release the socket and transfer every unfinished source owner without I/O,
    /// allocation, cancellation polling, or replaying a possibly sent request.
    pub fn retire(mut self) -> HttpCameraRetirement {
        self.socket = None;
        HttpCameraRetirement {
            route: self.route,
            totals: self.totals,
            reason: self.failure,
            request: self.request,
            request_sent: self.sent,
            head: self.head,
            wire: self.wire,
            entity: self.entity,
            frame: self.frame,
            http: self.http.abort(),
            multipart: self.multipart.map(HttpMultipartStream::abort),
            end: self.end,
            complete: self.complete,
        }
    }
}
/// A terminal owner handoff, NOT a reconnect/retry or successful capture certificate.
#[must_use]
pub struct HttpCameraRetirement {
    /// Exact original route, kept private in Debug output.
    pub route: HttpCameraRoute,
    /// Actual local I/O and part counts.
    pub totals: HttpCameraTotals,
    /// First terminal reason, or None for explicit owner stopping/completion.
    pub reason: Option<HttpCameraError>,
    /// Original non-secret GET request, with its exact locally accepted prefix.
    pub request: Vec<u8>,
    /// Already sent prefix; never blindly resend it on another connection.
    pub request_sent: usize,
    /// Complete response head, if admitted.
    pub head: Option<ResponseHead>,
    /// Unacknowledged or incompletely parsed raw socket read.
    pub wire: Option<HttpWireRead>,
    /// Current HTTP entity record and its multipart-consumed prefix.
    pub entity: Option<(EntityData, usize)>,
    /// Complete mapped frame not transferred to a downstream owner.
    pub frame: Option<HttpJpegFrame>,
    /// HTTP parser's unexposed source and exact position.
    pub http: HttpRemainder,
    /// MIME parser's unfinished original bytes and source spans.
    pub multipart: Option<HttpMjpegRemainder>,
    /// HTTP end retained even when downstream finalization refused.
    pub end: Option<HttpEnd>,
    /// Both successful termination receipts, when actually completed.
    pub complete: Option<HttpMjpegEnd>,
}
impl fmt::Debug for HttpCameraRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCameraRetirement")
            .field("route", &self.route)
            .field("totals", &self.totals)
            .field("reason", &self.reason)
            .field("request_sent", &self.request_sent)
            .finish_non_exhaustive()
    }
}
fn io_error(operation: HttpCameraOperation, error: io::Error) -> HttpCameraError {
    HttpCameraError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests;

/// Source-preserving native camera to existing learned JPEG/trajectory/zone processing.
pub mod learned;

/// Source-preserving native HTTP camera to neural RGB detection, tracking and zones.
pub mod rgb;
