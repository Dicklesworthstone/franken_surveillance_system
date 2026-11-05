#![forbid(unsafe_code)]
//! Bounded task-owned camera-local HTTP over a caller-admitted transport.
//!
//! This does not establish TLS, authenticate a device, acquire credentials,
//! provision Wi-Fi or change a camera. The caller must bind the exact transport
//! and lease to independently authorized peer identity. A cancelled or failed
//! exchange fences the session; the owner must retire it, not reuse the socket.

use super::{
    camera_api,
    metered::{MeteredClock, MeteredIo},
};
use asupersync::{
    Cx,
    bytes::BytesMut,
    codec::Decoder,
    http::h1::{Http1ClientCodec, Response},
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::execution::TaskCx;
use std::{
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

const MAX_REQUEST: usize = 8192;
const MAX_RESPONSE: usize = 4 * 1024 * 1024 + 20 * 1024;
const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_RESOURCE: usize = 1024;

/// The exact camera operation being checked on every transport poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Send a credential to establish a camera-local session.
    Login,
    /// Read the camera status.
    Status,
    /// Read the camera's reported controller address.
    Settings,
    /// Read one JPEG frame.
    Snapshot,
}
impl Operation {
    fn grant(self) -> RuntimeGrant {
        match self {
            Self::Login => RuntimeGrant::AdapterAuth,
            Self::Status | Self::Settings => RuntimeGrant::ObserveStatus,
            Self::Snapshot => RuntimeGrant::ReadMedia,
        }
    }
}

/// Independently established, current permission for the exact peer and session.
/// Implementations must bind the actual transport, TLS identity and credential
/// lease to the intended camera, and be bounded and nonblocking.
pub trait Authority {
    /// Revalidate before each read, write and flush, including pending polls.
    fn permits(&self, peer: Ipv4Addr, generation: u64, operation: Operation) -> bool;
}

/// Payload-free failure of a bounded camera-local exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Task, clock, resource, or time bounds are invalid.
    Configuration,
    /// Current authority refused the operation.
    Denied,
    /// The total operation deadline elapsed.
    Deadline,
    /// Transport closed or failed.
    Io(io::ErrorKind),
    /// Response framing or unexpected trailing data was invalid.
    Protocol,
    /// Response byte, iteration or interim-response limit was exceeded.
    Limit,
    /// The camera API state or response was refused.
    Camera(camera_api::Error),
    /// The session is fenced after an incomplete operation.
    Fenced,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi camera HTTP exchange refused: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<camera_api::Error> for Error {
    fn from(value: camera_api::Error) -> Self {
        Self::Camera(value)
    }
}

struct Guarded<'a, 'scope, 'task, IO> {
    io: &'a mut MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    authority: &'a dyn Authority,
    peer: Ipv4Addr,
    generation: u64,
    operation: Operation,
    resource: &'a str,
}
impl<IO> Guarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        if !self
            .authority
            .permits(self.peer, self.generation, self.operation)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // A live policy may itself consult this task and advance its clock.
        // Sample only after it returns so this admission cannot regress time.
        let now = self.clock.now().map_err(|_| io::ErrorKind::Interrupted)?;
        self.task
            .checkpoint_for(
                self.operation.grant(),
                self.resource,
                now,
                &BudgetVector::ZERO,
            )
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for Guarded<'_, '_, '_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for Guarded<'_, '_, '_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut *self.io).poll_write(cx, buf)
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
struct Attempt<'a> {
    session: &'a mut camera_api::Session,
    request: Option<camera_api::Request>,
    finished: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.session.fence();
        }
    }
}
struct SensitiveResponse(Option<Response>);
impl Drop for SensitiveResponse {
    fn drop(&mut self) {
        if let Some(response) = &mut self.0 {
            response.body.fill(0);
            for (_, value) in response
                .headers
                .iter_mut()
                .chain(response.trailers.iter_mut())
            {
                let mut bytes = std::mem::take(value).into_bytes();
                bytes.fill(0);
            }
        }
    }
}
struct SensitiveBuffer(BytesMut);
impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

/// One sequential camera-local session on an already admitted transport.
/// The transport is never returned to the caller after a failed exchange.
pub struct Owner<'scope, 'task, 'policy, IO> {
    io: MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    authority: &'policy dyn Authority,
    peer: Ipv4Addr,
    generation: u64,
    resource: String,
    session: camera_api::Session,
}
impl<IO> fmt::Debug for Owner<'_, '_, '_, IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CameraHttpOwner")
            .field("phase", &self.session.phase())
            .finish_non_exhaustive()
    }
}
impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin> Owner<'scope, 'task, 'policy, IO> {
    /// Attach an owned stream. This does not authenticate the supplied peer.
    pub fn new(
        io: MeteredIo<'scope, 'task, IO>,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        authority: &'policy dyn Authority,
        peer: Ipv4Addr,
        generation: u64,
        resource: &str,
    ) -> Result<Self, Error> {
        if resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || !clock.matches(task, cx)
            || !io.clock().same_mapping(&clock)
            || io.resource() != resource
            || !std::ptr::eq(io.runtime_context(), cx)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            io,
            task,
            clock,
            authority,
            peer,
            generation,
            resource: resource.to_owned(),
            session: camera_api::Session::new(peer, generation)?,
        })
    }
    /// Current local state; no remote identity or adoption is implied.
    pub fn phase(&self) -> camera_api::Phase {
        self.session.phase()
    }
    fn admit(&mut self, operation: Operation, wait: Duration) -> Result<(), Error> {
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        if self.session.phase() == camera_api::Phase::Fenced {
            return Err(Error::Fenced);
        }
        let permitted = self
            .authority
            .permits(self.peer, self.generation, operation)
            && self.clock.now().ok().is_some_and(|now| {
                self.task
                    .checkpoint_for(operation.grant(), &self.resource, now, &BudgetVector::ZERO)
                    .is_ok()
            });
        if !permitted {
            self.session.fence();
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Authenticate using caller-owned credential bytes; this owner does not store them.
    pub async fn login(&mut self, credential: &[u8], wait: Duration) -> Result<(), Error> {
        self.admit(Operation::Login, wait)?;
        let request = self.session.prepare_login(credential)?;
        let response = self.perform(request, Operation::Login, wait).await?;
        self.session.accept_login(response).map_err(Error::Camera)
    }
    /// Read the camera's bounded, untrusted status shape.
    pub async fn status(&mut self, wait: Duration) -> Result<camera_api::StatusShape, Error> {
        self.admit(Operation::Status, wait)?;
        let request = self.session.prepare_status()?;
        let response = self.perform(request, Operation::Status, wait).await?;
        self.session.accept_status(response).map_err(Error::Camera)
    }
    /// Read a bounded, untrusted controller-address claim.
    pub async fn settings(
        &mut self,
        wait: Duration,
    ) -> Result<camera_api::SettingsObservation, Error> {
        self.admit(Operation::Settings, wait)?;
        let request = self.session.prepare_settings()?;
        let response = self.perform(request, Operation::Settings, wait).await?;
        self.session
            .accept_settings(response)
            .map_err(Error::Camera)
    }
    /// Read one bounded original JPEG without implying decoded content or capture time.
    pub async fn snapshot(&mut self, wait: Duration) -> Result<camera_api::Snapshot, Error> {
        self.admit(Operation::Snapshot, wait)?;
        let request = self.session.prepare_snapshot()?;
        let response = self.perform(request, Operation::Snapshot, wait).await?;
        self.session
            .accept_snapshot(response)
            .map_err(Error::Camera)
    }
    async fn perform(
        &mut self,
        request: camera_api::Request,
        operation: Operation,
        wait: Duration,
    ) -> Result<Response, Error> {
        let cx = self.io.runtime_context();
        let attempt = Attempt {
            session: &mut self.session,
            request: Some(request),
            finished: false,
        };
        let mut guarded = Guarded {
            io: &mut self.io,
            task: self.task,
            clock: self.clock,
            authority: self.authority,
            peer: self.peer,
            generation: self.generation,
            operation,
            resource: &self.resource,
        };
        let result = timeout_at(
            cx.now() + wait,
            exchange(
                &mut guarded,
                attempt.request.as_ref().ok_or(Error::Protocol)?.bytes(),
            ),
        )
        .await;
        let mut response = SensitiveResponse(Some(match result {
            Err(_) => return Err(Error::Deadline),
            Ok(result) => result?,
        }));
        guarded.check().map_err(classify_io)?;
        let mut attempt = attempt;
        let request = attempt.request.take().ok_or(Error::Protocol)?;
        attempt
            .session
            .finish_write(request, camera_api::WriteOutcome::Written)?;
        attempt.finished = true;
        response.0.take().ok_or(Error::Protocol)
    }
}
fn classify_io(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::Interrupted => Error::Denied,
        kind => Error::Io(kind),
    }
}
async fn exchange<IO: AsyncRead + AsyncWrite + Unpin>(
    io: &mut IO,
    request: &[u8],
) -> Result<Response, Error> {
    if request.is_empty() || request.len() > MAX_REQUEST {
        return Err(Error::Limit);
    }
    io.write_all(request).await.map_err(classify_io)?;
    io.flush().await.map_err(classify_io)?;
    let mut codec = Http1ClientCodec::new()
        .max_headers_size(16 * 1024)
        .max_body_size(4 * 1024 * 1024)
        .max_trailers_size(4096);
    let mut buffer = SensitiveBuffer(BytesMut::new());
    let mut total = 0usize;
    let mut interim = 0u8;
    let mut input = [0u8; 4096];
    for _ in 0..4096 {
        loop {
            match codec.decode(&mut buffer.0).map_err(|_| Error::Protocol)? {
                Some(response) if (100..200).contains(&response.status) => {
                    interim += 1;
                    if interim > 8 || response.status == 101 {
                        return Err(Error::Protocol);
                    }
                }
                Some(response) => {
                    if !buffer.0.is_empty() {
                        return Err(Error::Protocol);
                    }
                    return Ok(response);
                }
                None => break,
            }
        }
        let n = io.read(&mut input).await.map_err(classify_io)?;
        if n == 0 {
            return Err(Error::Io(io::ErrorKind::UnexpectedEof));
        }
        total = total.checked_add(n).ok_or(Error::Limit)?;
        if total > MAX_RESPONSE {
            return Err(Error::Limit);
        }
        buffer.0.extend_from_slice(&input[..n]);
        input.fill(0);
    }
    Err(Error::Limit)
}
