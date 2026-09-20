#![forbid(unsafe_code)]
//! Bounded native TCP ownership for an explicitly authorized RTSP route.
//!
//! No DNS, redirects, retries, thread, timer, reactor, or authentication protocol
//! is implemented here. The owner supplies an exact peer, a live authority probe,
//! a monotonic admission clock and a lease. Polling performs at most one socket
//! read or write. Socket acceptance is NOT a remote command acknowledgement.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use fss_packet::StreamKey;
use super::client::ClientRequest;
use super::framed::{MAX_WIRE_CHUNK, WIRE_LIFETIME_NS};

/// Explicit opt-in to unencrypted RTSP. There is deliberately no default, TLS
/// fallback, or implication that Digest protects media or the entire session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpSecurityPolicy {
    /// The transport owner independently approved plaintext for this exact route.
    OwnerApprovedPlaintext,
}

/// Immutable owner-approved address/authority mapping. This is a requested scope,
/// not a capability: TcpAuthority must approve it at each network boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct TcpBinding {
    key: StreamKey,
    peer: SocketAddr,
    authority: String,
    security: TcpSecurityPolicy,
}
impl TcpBinding {
    /// Bind a caller-resolved address and exact RTSP authority (host[:port]).
    /// No hostname is resolved and no alternate address is tried by this layer.
    pub fn new(key: StreamKey, peer: SocketAddr, authority: &str, security: TcpSecurityPolicy)
        -> Result<Self, TcpError>
    {
        if key.ingress == 0 || key.generation == 0 || peer.port() == 0
            || peer.ip().is_unspecified() || peer.ip().is_multicast()
            || authority.is_empty() || authority.len() > 512
            || !authority.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        { return Err(TcpError::Configuration); }
        Ok(Self { key, peer, authority: authority.to_owned(), security })
    }
    /// Expected ingress, stream generation and SSRC. SSRC is not authentication.
    pub fn key(&self) -> StreamKey { self.key }
    /// Exact peer that the live authority must permit.
    pub fn peer(&self) -> SocketAddr { self.peer }
    /// Exact owner-supplied RTSP authority mapping; may be sensitive metadata.
    pub fn authority(&self) -> &str { &self.authority }
    /// Explicit plaintext approval, not a transport-protection certificate.
    pub fn security(&self) -> TcpSecurityPolicy { self.security }
}
impl fmt::Debug for TcpBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpBinding").field("key", &self.key)
            .field("security", &self.security).finish_non_exhaustive()
    }
}

/// Network boundary presented to the same owner on every attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpOperation {
    /// One bounded connection attempt to the exact supplied socket address.
    Connect,
    /// Inspect/configure the owned socket, without enabling another route.
    Configure,
    /// Admit a prepared protocol request; no bytes are sent by admission.
    QueueRequest,
    /// Attempt one nonblocking read, or validate its post-I/O authority.
    Read,
    /// Attempt one nonblocking write, or validate its post-I/O authority.
    Write,
    /// Timer/lease/revocation check when no socket operation is necessary.
    Poll,
}

/// Preserve revocation/cancellation/deadline distinctions without logging policy text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDenial {
    /// The exact route/operation is not granted by the owning authority.
    Unauthorized,
    /// Authority or its generation was revoked.
    Revoked,
    /// Owner requested cancellation; stop effects and retire retained bytes.
    Cancelled,
    /// The owner's live deadline expired, including during a blocking connect.
    Deadline,
    /// The owner's independent operation/byte/resource allowance is exhausted.
    Budget,
}

/// Explicit runtime/authorization boundary. Implement using the owning Cx or
/// equivalent capability. The owner must validate route, principal, generation,
/// plaintext policy, live cancellation and actual elapsed deadline here.
///
/// now_ns is admission time, not an assertion of current time after a syscall.
/// The probe must enforce live deadline/revocation itself. No default permissive
/// implementation is supplied. Cleanup always releases the socket even if the
/// authority has been revoked; it never sends a best-effort TEARDOWN in Drop.
pub trait TcpAuthority {
    /// Admit this exact operation under the same route and absolute lease.
    fn checkpoint(&self, binding: &TcpBinding, operation: TcpOperation,
        now_ns: u64, deadline_ns: u64) -> Result<(), TcpDenial>;
}

/// Independent connection-wide work/byte ceilings. No unbounded reconnect or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpLimits {
    /// Total bytes this connection may read; not a retention/custody budget.
    pub max_received_bytes: u64,
    /// Total bytes this connection may write; whole requests reserve against it.
    pub max_sent_bytes: u64,
    /// Combined read/write calls, including WouldBlock and Interrupted attempts.
    pub max_io_calls: u64,
    /// One original prepared request may occupy at most this many bytes.
    pub max_request_bytes: usize,
    /// Maximum bytes per socket call, in 1..=MAX_WIRE_CHUNK.
    pub chunk_bytes: usize,
    /// Single blocking connect timeout, in 1..=60 seconds, also capped by the lease.
    pub connect_timeout_ns: u64,
}
impl Default for TcpLimits {
    fn default() -> Self {
        Self { max_received_bytes: 1024 * 1024 * 1024, max_sent_bytes: 1024 * 1024,
            max_io_calls: 1_000_000, max_request_bytes: 32 * 1024,
            chunk_bytes: MAX_WIRE_CHUNK, connect_timeout_ns: 5_000_000_000 }
    }
}
impl TcpLimits {
    /// Validate all bounds before any network operation or retained allocation.
    pub fn validate(self) -> Result<(), TcpError> {
        if self.max_received_bytes == 0 || self.max_sent_bytes == 0 || self.max_io_calls == 0
            || !(1..=32 * 1024).contains(&self.max_request_bytes)
            || !(1..=MAX_WIRE_CHUNK).contains(&self.chunk_bytes)
            || !(1..=60_000_000_000).contains(&self.connect_timeout_ns)
        { return Err(TcpError::Configuration); }
        Ok(())
    }
}

/// Typed, payload-free transport failure. The owned socket closes on fatal errors;
/// retire the link to recover buffered source and any partially dispatched request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpError {
    /// Invalid key, route, lease or resource ceiling.
    Configuration,
    /// Owner-supplied admission time reversed; no state or socket operation changed.
    ClockReversed,
    /// Absolute connection lease expired.
    Deadline,
    /// Complete read bytes reached their original residence deadline.
    ReadDeadline,
    /// Explicit live authority refused this operation.
    Denied(TcpDenial),
    /// No more network admission on a closed/retired connection.
    Closed,
    /// Consume the existing read/request before admitting another.
    Backpressure,
    /// A request does not fit its independent size or remaining send-byte reservation.
    RequestBudget,
    /// Receive-byte or socket-call budget is exhausted; this is NOT clean EOF.
    WorkBudget,
    /// Bounded allocation or timestamp arithmetic failed.
    Exhausted,
    /// Peer address differs from the exact owner-approved route.
    PeerMismatch,
    /// A socket error, with no OS path, URL, challenge or payload string.
    Io { operation: TcpOperation, kind: io::ErrorKind },
    /// Eight consecutive interrupted attempts in one direction; no busy retry loop.
    Interrupted,
    /// A nonempty write returned zero; its already-sent prefix remains explicit.
    WriteZero,
}
impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP TCP refusal: {self:?}")
    }
}
impl std::error::Error for TcpError {}

/// Connect failure distinguishes refusal-before-I/O from an attempted connection.
#[derive(Debug)]
pub struct TcpConnectFailure {
    /// Typed failure; any owned socket was released before this value returned.
    pub reason: TcpError,
    /// A TCP attempt was made. The peer may have observed a connection, not RTSP bytes.
    pub connection_attempted: bool,
}
impl fmt::Display for TcpConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for TcpConnectFailure {}

/// Byte and work observations, never remote execution or source-custody proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpTotals {
    /// Bytes actually returned by successful socket reads.
    pub received_bytes: u64,
    /// Bytes the local socket accepted for sending, not peer acknowledgements.
    pub sent_bytes: u64,
    /// Read attempts including WouldBlock/Interrupted.
    pub read_calls: u64,
    /// Write attempts including WouldBlock/Interrupted.
    pub write_calls: u64,
    /// Last request fully accepted by the local socket; not an RTSP response receipt.
    pub last_sent_cseq: Option<u32>,
    /// A read returned zero. Work-budget exhaustion never sets this flag.
    pub peer_eof: bool,
}

/// Original read bytes. Admission time is host-owner time, not camera capture time.
pub struct TcpReadChunk { bytes: Vec<u8>, admitted_ns: u64, deadline_ns: u64 }
impl TcpReadChunk {
    /// Exact TCP bytes, possibly containing authentication material. Do not log.
    pub fn expose(&self) -> &[u8] { &self.bytes }
    /// Owner clock at this read's admission, not a post-syscall clock measurement.
    pub fn admitted_ns(&self) -> u64 { self.admitted_ns }
}
impl fmt::Debug for TcpReadChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpReadChunk").field("bytes", &self.bytes.len())
            .field("admitted_ns", &self.admitted_ns).finish()
    }
}

struct PendingRequest { request: ClientRequest, sent: usize }
/// Every queue refusal returns the unconsumed prepared request. Preparing the
/// request may already have advanced its session; the session owner must reconcile.
#[derive(Debug)]
#[must_use]
pub struct TcpRequestRefusal { /// Typed queue refusal.
    pub reason: TcpError, /// Original request, including any borrowed-owner Digest result.
    pub request: ClientRequest }
impl fmt::Display for TcpRequestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for TcpRequestRefusal {}

/// One nonblocking write attempt. No variant certifies remote RTSP execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpWriteStep {
    /// No queued request exists.
    Idle,
    /// WouldBlock or a bounded interruption; wait for writability/timer before polling.
    Pending,
    /// A prefix was accepted; resume only its unsent suffix on this same connection.
    Advanced { /// Correlation sequence.
        cseq: u32, /// Total bytes sent from this request so far.
        sent: usize, /// Complete request size.
        total: usize },
    /// All request bytes entered the local socket. Await the matching RTSP response.
    Sent { /// Correlation sequence.
        cseq: u32, /// Complete request byte count.
        bytes: usize },
}
/// One nonblocking read attempt; bytes stay retained until explicitly acknowledged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpReadStep { /// Wait for readability or a timer; no bytes were read.
    Pending, /// Exact bytes are available through pending_read().
    Buffered, /// Zero-byte read; the socket is released, and accepted protocol input must drain.
    Eof }

/// Retirement preserves the exact partially dispatched command and unprocessed
/// source bytes. Never replay that command on a new connection based on this receipt.
#[derive(Debug)]
#[must_use]
pub struct TcpRetirement {
    /// Exact route/generation requested by the owner.
    pub binding: TcpBinding,
    /// Observed byte/call totals, not remote execution or retained evidence claims.
    pub totals: TcpTotals,
    /// Original request whose dispatch was incomplete; None after a complete send.
    pub request: Option<ClientRequest>,
    /// Prefix of request already accepted by the socket; zero does not mean an older request failed.
    pub request_sent_bytes: usize,
    /// Original read bytes not acknowledged by the protocol owner.
    pub unread: Option<TcpReadChunk>,
}

trait SocketIo: Read + Write + Send {}
impl<T: Read + Write + Send> SocketIo for T {}

/// One native socket, one request cursor, and one bounded read chunk. No public
/// arbitrary-stream injection, socket cloning, detached work, or retry-in-place API.
#[must_use]
pub struct RtspTcpLink {
    socket: Option<Box<dyn SocketIo>>,
    binding: TcpBinding,
    limits: TcpLimits,
    deadline_ns: u64,
    last_ns: u64,
    totals: TcpTotals,
    request: Option<PendingRequest>,
    read: Option<TcpReadChunk>,
    interrupted_read: u8,
    interrupted_write: u8,
}
impl fmt::Debug for RtspTcpLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspTcpLink").field("binding", &self.binding)
            .field("totals", &self.totals).field("closed", &self.socket.is_none())
            .field("read", &self.read).field("request_pending", &self.request.is_some())
            .finish_non_exhaustive()
    }
}
impl RtspTcpLink {
    /// Make exactly one connection attempt, then configure a nonblocking socket.
    /// No DNS, fallback peer, automatic reconnect, TLS downgrade, or RTSP send.
    /// connect_timeout is not preemptible by this API; live authority is rechecked
    /// afterwards, and a denied/late socket is closed without any protocol write.
    pub fn connect(binding: TcpBinding, limits: TcpLimits, now_ns: u64, deadline_ns: u64,
        authority: &dyn TcpAuthority) -> Result<Self, TcpConnectFailure>
    {
        let fail = |reason, attempted| TcpConnectFailure { reason, connection_attempted: attempted };
        limits.validate().map_err(|e| fail(e, false))?;
        if now_ns >= deadline_ns { return Err(fail(TcpError::Deadline, false)); }
        authority.checkpoint(&binding, TcpOperation::Connect, now_ns, deadline_ns)
            .map_err(|e| fail(TcpError::Denied(e), false))?;
        let timeout = Duration::from_nanos(limits.connect_timeout_ns.min(deadline_ns - now_ns));
        let socket = TcpStream::connect_timeout(&binding.peer, timeout)
            .map_err(|e| fail(TcpError::Io { operation: TcpOperation::Connect, kind: e.kind() }, true))?;
        authority.checkpoint(&binding, TcpOperation::Configure, now_ns, deadline_ns)
            .map_err(|e| fail(TcpError::Denied(e), true))?;
        if socket.peer_addr().map_err(|e| fail(TcpError::Io {
            operation: TcpOperation::Configure, kind: e.kind() }, true))? != binding.peer {
            return Err(fail(TcpError::PeerMismatch, true));
        }
        authority.checkpoint(&binding, TcpOperation::Configure, now_ns, deadline_ns)
            .map_err(|e| fail(TcpError::Denied(e), true))?;
        socket.set_nonblocking(true).map_err(|e| fail(TcpError::Io {
            operation: TcpOperation::Configure, kind: e.kind() }, true))?;
        authority.checkpoint(&binding, TcpOperation::Poll, now_ns, deadline_ns)
            .map_err(|e| fail(TcpError::Denied(e), true))?;
        Ok(Self { socket: Some(Box::new(socket)), binding, limits, deadline_ns, last_ns: now_ns,
            totals: TcpTotals::default(), request: None, read: None,
            interrupted_read: 0, interrupted_write: 0 })
    }
    /// Exact scope for the owning runtime's readiness/authorization registration.
    pub fn binding(&self) -> &TcpBinding { &self.binding }
    /// Current observations only; a full local send is not a server acknowledgement.
    pub fn totals(&self) -> TcpTotals { self.totals }
    /// Whether a request has an unsent suffix on this connection.
    pub fn has_pending_request(&self) -> bool { self.request.is_some() }
    /// Exact retained source chunk. Acknowledgement transfers responsibility to the caller.
    pub fn pending_read(&self) -> Option<&TcpReadChunk> { self.read.as_ref() }
    /// Transfer a chunk only after the next semantic owner has accepted it, or to
    /// an explicit source-retention owner. This does not establish durable custody.
    pub fn acknowledge_read(&mut self) -> Option<TcpReadChunk> { self.read.take() }
    /// Earliest hard local timer even when no socket readiness arrives.
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.socket.as_ref()?;
        Some(self.read.as_ref().map_or(self.deadline_ns, |r| r.deadline_ns.min(self.deadline_ns)))
    }
    /// Revalidate the same absolute lease and authority without doing socket I/O.
    pub fn check(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), TcpError> {
        self.admit(now, TcpOperation::Poll, authority)
    }
    /// Retain one original prepared request. No write, nonce retry or session advance occurs here.
    pub fn queue_request(&mut self, request: ClientRequest, now: u64, authority: &dyn TcpAuthority)
        -> Result<(), TcpRequestRefusal>
    {
        let result = self.admit(now, TcpOperation::QueueRequest, authority).and_then(|()| {
            if self.request.is_some() { return Err(TcpError::Backpressure); }
            if request.bytes().len() > self.limits.max_request_bytes
                || request.bytes().len() as u64 > self.limits.max_sent_bytes - self.totals.sent_bytes {
                return Err(TcpError::RequestBudget);
            }
            Ok(())
        });
        if let Err(reason) = result { return Err(TcpRequestRefusal { reason, request }); }
        self.request = Some(PendingRequest { request, sent: 0 });
        Ok(())
    }
    /// Attempt exactly one write, preserving the offset across short writes and
    /// WouldBlock. Any fatal error releases the socket without replaying its prefix.
    pub fn write_step(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<TcpWriteStep, TcpError> {
        self.admit(now, TcpOperation::Write, authority)?;
        if self.request.is_none() { return Ok(TcpWriteStep::Idle); }
        self.reserve_call()?;
        let pending = self.request.as_ref().ok_or(TcpError::Closed)?;
        let end = pending.request.bytes().len().min(pending.sent + self.limits.chunk_bytes);
        self.totals.write_calls += 1;
        let result = self.socket.as_mut().ok_or(TcpError::Closed)?.write(&pending.request.bytes()[pending.sent..end]);
        match result {
            Ok(0) => self.stop(TcpError::WriteZero),
            Ok(n) => {
                self.interrupted_write = 0;
                let pending = self.request.as_mut().ok_or(TcpError::Closed)?;
                pending.sent += n;
                self.totals.sent_bytes += n as u64;
                // Charge and preserve the accepted prefix BEFORE live post-I/O checks.
                let complete = pending.sent == pending.request.bytes().len();
                let cseq = pending.request.cseq();
                let sent = pending.sent;
                let total = pending.request.bytes().len();
                if let Err(e) = authority.checkpoint(&self.binding, TcpOperation::Write, now, self.deadline_ns) {
                    return self.stop(TcpError::Denied(e));
                }
                if complete {
                    self.totals.last_sent_cseq = Some(cseq);
                    self.request = None;
                    Ok(TcpWriteStep::Sent { cseq, bytes: total })
                } else { Ok(TcpWriteStep::Advanced { cseq, sent, total }) }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.interrupted_write = 0;
                Ok(TcpWriteStep::Pending)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                self.interrupted_write += 1;
                if self.interrupted_write >= 8 { self.stop(TcpError::Interrupted) }
                else { Ok(TcpWriteStep::Pending) }
            }
            Err(e) => self.stop(TcpError::Io { operation: TcpOperation::Write, kind: e.kind() }),
        }
    }
    /// Attempt one bounded read. Never overread a full caller queue or manufacture
    /// EOF at a budget limit. Post-read revocation leaves exact bytes for retirement.
    pub fn read_step(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<TcpReadStep, TcpError> {
        self.admit(now, TcpOperation::Read, authority)?;
        if self.read.is_some() { return Err(TcpError::Backpressure); }
        self.reserve_call()?;
        let remaining = self.limits.max_received_bytes - self.totals.received_bytes;
        if remaining == 0 { return self.stop(TcpError::WorkBudget); }
        let length = remaining.min(self.limits.chunk_bytes as u64) as usize;
        let Some(deadline_ns) = now.checked_add(WIRE_LIFETIME_NS) else { return self.stop(TcpError::Exhausted); };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() { return self.stop(TcpError::Exhausted); }
        bytes.resize(length, 0);
        self.totals.read_calls += 1;
        match self.socket.as_mut().ok_or(TcpError::Closed)?.read(&mut bytes) {
            Ok(0) => {
                self.totals.peer_eof = true;
                self.socket = None;
                authority.checkpoint(&self.binding, TcpOperation::Read, now, self.deadline_ns)
                    .map_err(TcpError::Denied)?;
                Ok(TcpReadStep::Eof)
            }
            Ok(n) => {
                self.interrupted_read = 0;
                bytes.truncate(n);
                self.totals.received_bytes += n as u64;
                self.read = Some(TcpReadChunk { bytes, admitted_ns: now, deadline_ns });
                if let Err(e) = authority.checkpoint(&self.binding, TcpOperation::Read, now, self.deadline_ns) {
                    return self.stop(TcpError::Denied(e));
                }
                Ok(TcpReadStep::Buffered)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.interrupted_read = 0;
                Ok(TcpReadStep::Pending)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                self.interrupted_read += 1;
                if self.interrupted_read >= 8 { self.stop(TcpError::Interrupted) }
                else { Ok(TcpReadStep::Pending) }
            }
            Err(e) => self.stop(TcpError::Io { operation: TcpOperation::Read, kind: e.kind() }),
        }
    }
    /// Release the native socket and return all undispatched/unprocessed originals.
    /// No implicit TEARDOWN, retry, secret logging or source deletion occurs.
    pub fn retire(mut self) -> TcpRetirement {
        self.socket = None;
        let (request, request_sent_bytes) = match self.request.take() {
            Some(p) => (Some(p.request), p.sent), None => (None, 0),
        };
        TcpRetirement { binding: self.binding, totals: self.totals,
            request, request_sent_bytes, unread: self.read }
    }
    fn admit(&mut self, now: u64, operation: TcpOperation, authority: &dyn TcpAuthority) -> Result<(), TcpError> {
        if now < self.last_ns { return Err(TcpError::ClockReversed); }
        if self.socket.is_none() { return Err(TcpError::Closed); }
        self.last_ns = now;
        if now >= self.deadline_ns { return self.stop(TcpError::Deadline); }
        if self.read.as_ref().is_some_and(|r| now >= r.deadline_ns) { return self.stop(TcpError::ReadDeadline); }
        if let Err(e) = authority.checkpoint(&self.binding, operation, now, self.deadline_ns) {
            return self.stop(TcpError::Denied(e));
        }
        Ok(())
    }
    fn reserve_call(&mut self) -> Result<(), TcpError> {
        if self.totals.read_calls.checked_add(self.totals.write_calls)
            .is_none_or(|n| n >= self.limits.max_io_calls) { return self.stop(TcpError::WorkBudget); }
        Ok(())
    }
    fn stop<T>(&mut self, error: TcpError) -> Result<T, TcpError> {
        self.socket = None;
        Err(error)
    }
}

#[cfg(test)]
mod tests;
