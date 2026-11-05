#![forbid(unsafe_code)]
//! Bounded task-owned HTTP upgrade into a UniFi management session.
//!
//! The caller supplies an already admitted transport and is responsible for
//! authenticating its peer, TLS, listening, and supervising the resulting
//! session. A claimed MAC is untrusted. Dropping this future drops the stream;
//! no partially written response can be reused as an upgraded connection.

use asupersync::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout_at,
};
use std::{fmt, io, time::Duration};

use super::{
    Controller, Dispatch,
    metered::MeteredIo,
    receive::{self, Session},
    upgrade::{self, PreparedUpgrade, ProtocolPolicy},
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 4096;

/// Policy evaluated after parsing the untrusted claim and before any response.
///
/// Implementations must bind the claim to independently established peer
/// identity, current owner authorization, and the accepted transport. This
/// callback is not itself proof that any of those facts were established.
/// It must be bounded and nonblocking: the async deadline cannot preempt it.
pub trait PeerAdmission {
    /// Revalidate the exact claim for this connection.
    fn permits(&self, claimed_mac: [u8; 6]) -> bool;
}

/// Payload-free failure; all variants retire the owned stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A zero or excessive total time limit was supplied.
    WaitLimit,
    /// Request collection exhausted the total time limit.
    RequestTimeout,
    /// The peer closed before a complete HTTP request was received.
    RequestEof,
    /// A request read failed.
    RequestIo(io::ErrorKind),
    /// Bounded request allocation failed.
    Allocation,
    /// The HTTP request or WebSocket offer was invalid.
    Request(upgrade::Error),
    /// Current peer admission refused the claimed identity.
    PeerDenied,
    /// A response write or flush failed or timed out after it was attempted.
    ResponseIndeterminate,
    /// The locally written response could not be transferred into a session.
    Session(receive::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi upgrade owner refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Collect one bounded HTTP request, admit its peer, and transfer the upgraded
/// stream to the management owner. `wait` is one total deadline across request,
/// response and flush, not a renewable per-read timeout.
///
/// Request bytes already read beyond the HTTP header remain available to the
/// WebSocket parser. No response is attempted for invalid or denied requests.
/// A successful result proves local response completion only, not delivery,
/// authentication, camera adoption, or streaming. TLS plaintext and wire
/// meters, if both present, must share the same task-bound `MeteredClock`.
pub async fn accept<'scope, 'task, IO, A>(
    mut io: MeteredIo<'scope, 'task, IO>,
    policy: ProtocolPolicy,
    admission: &A,
    controller: Controller,
    wait: Duration,
) -> Result<Session<'scope, 'task, IO>, Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    A: PeerAdmission,
{
    if wait.is_zero() || wait > MAX_WAIT {
        return Err(Error::WaitLimit);
    }
    let cx = io.runtime_context();
    let deadline = cx.now() + wait;
    let mut request = Vec::new();
    request
        .try_reserve_exact(upgrade::MAX_HEADER_BYTES + READ_CHUNK)
        .map_err(|_| Error::Allocation)?;
    let mut chunk = [0_u8; READ_CHUNK];
    let mut scan_from = 0;
    loop {
        let count = match timeout_at(deadline, io.read(&mut chunk)).await {
            Err(_) => return Err(Error::RequestTimeout),
            Ok(Err(error)) => return Err(Error::RequestIo(error.kind())),
            Ok(Ok(0)) => return Err(Error::RequestEof),
            Ok(Ok(count)) => count,
        };
        request.extend_from_slice(&chunk[..count]);
        let header_end = request[scan_from..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| scan_from + offset + 4);
        if let Some(end) = header_end {
            if end > upgrade::MAX_HEADER_BYTES {
                return Err(Error::Request(upgrade::Error::InvalidRequest));
            }
            break;
        }
        if request.len() >= upgrade::MAX_HEADER_BYTES {
            return Err(Error::Request(upgrade::Error::InvalidRequest));
        }
        scan_from = request.len().saturating_sub(3);
    }
    let prepared = PreparedUpgrade::parse(&request, policy).map_err(Error::Request)?;
    if !admission.permits(prepared.claimed_mac()) {
        return Err(Error::PeerDenied);
    }
    let response = prepared.response_bytes();
    let mut offset = 0;
    while offset < response.len() {
        match timeout_at(deadline, io.write(&response[offset..])).await {
            Ok(Ok(count)) if count > 0 => offset += count,
            _ => return Err(Error::ResponseIndeterminate),
        }
    }
    match timeout_at(deadline, io.flush()).await {
        Ok(Ok(())) => {}
        _ => return Err(Error::ResponseIndeterminate),
    }
    Session::from_upgrade(prepared, io, Dispatch::Written, controller).map_err(Error::Session)
}
