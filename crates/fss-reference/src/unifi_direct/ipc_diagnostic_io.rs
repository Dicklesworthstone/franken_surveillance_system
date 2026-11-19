#![forbid(unsafe_code)]
//! Single-use, task-owned I/O for experimental diagnostic framing.
//!
//! The caller must supply an already admitted, metered transport and bind it
//! to its intended peer. No SSH or Unix-socket bridge is provided here. A
//! correlated response is an untrusted claim and does not settle any effect.
//! Cancellation or any attempted exchange spends the owner; do not reuse its
//! stream or retry without a newly admitted transport and request.

use super::{
    camera_http, ipc_diagnostic,
    metered::{MeteredClock, MeteredIo},
};
use asupersync::{
    Cx,
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

const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_RESOURCE: usize = 1024;

/// Payload-free refusal for an experimental diagnostic exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Task, resource, peer, clock, or deadline configuration was invalid.
    Configuration,
    /// Task or camera-status authority was denied or cancelled.
    Denied,
    /// The complete exchange exceeded its deadline.
    Deadline,
    /// Transport failed or closed before a complete frame.
    Io(io::ErrorKind),
    /// Framing or response correlation failed.
    Protocol(ipc_diagnostic::Error),
    /// This owner has already attempted an exchange.
    Spent,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi diagnostic I/O refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Guarded<'a, 'scope, 'task, IO> {
    io: &'a mut MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    authority: &'a dyn camera_http::Authority,
    peer: Ipv4Addr,
    generation: u64,
    resource: &'a str,
}
impl<IO> Guarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        if !self.authority.permits(
            self.peer,
            self.generation,
            camera_http::Operation::SettingsSerializers,
        ) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let now = self.clock.now().map_err(|_| io::ErrorKind::Interrupted)?;
        self.task
            .checkpoint_for(
                RuntimeGrant::ObserveStatus,
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

/// One caller-admitted transport, usable for at most one diagnostic exchange.
pub struct Owner<'scope, 'task, 'policy, IO> {
    io: MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    authority: &'policy dyn camera_http::Authority,
    peer: Ipv4Addr,
    generation: u64,
    resource: String,
    spent: bool,
}
impl<IO> fmt::Debug for Owner<'_, '_, '_, IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticOwner")
            .field("spent", &self.spent)
            .finish_non_exhaustive()
    }
}
impl<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin> Owner<'scope, 'task, 'policy, IO> {
    /// Attach an owned stream; this does not connect or authenticate its peer.
    pub fn new(
        io: MeteredIo<'scope, 'task, IO>,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        authority: &'policy dyn camera_http::Authority,
        peer: Ipv4Addr,
        generation: u64,
        resource: &str,
    ) -> Result<Self, Error> {
        if resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || peer.is_unspecified()
            || generation == 0
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
            spent: false,
        })
    }

    /// Whether an exchange was attempted; a spent owner cannot be reused.
    pub fn is_spent(&self) -> bool {
        self.spent
    }

    /// Send one request and read exactly one bounded frame under one deadline.
    /// Partial writes, cancellation and lost responses remain indeterminate.
    pub async fn observe(
        &mut self,
        request: &ipc_diagnostic::Request,
        wait: Duration,
    ) -> Result<ipc_diagnostic::Response, Error> {
        if self.spent {
            return Err(Error::Spent);
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::Configuration);
        }
        self.spent = true;
        let cx = self.io.runtime_context();
        let mut guarded = Guarded {
            io: &mut self.io,
            task: self.task,
            clock: self.clock,
            authority: self.authority,
            peer: self.peer,
            generation: self.generation,
            resource: &self.resource,
        };
        guarded.check().map_err(classify_io)?;
        let result = timeout_at(cx.now() + wait, exchange(&mut guarded, request)).await;
        let response = match result {
            Err(_) => return Err(Error::Deadline),
            Ok(value) => value?,
        };
        guarded.check().map_err(classify_io)?;
        Ok(response)
    }
}

fn classify_io(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::Interrupted => Error::Denied,
        kind => Error::Io(kind),
    }
}

struct Sensitive(Vec<u8>);
impl Drop for Sensitive {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

async fn exchange<IO: AsyncRead + AsyncWrite + Unpin>(
    io: &mut IO,
    request: &ipc_diagnostic::Request,
) -> Result<ipc_diagnostic::Response, Error> {
    io.write_all(request.bytes()).await.map_err(classify_io)?;
    io.flush().await.map_err(classify_io)?;
    let mut header = [0u8; 4];
    io.read_exact(&mut header).await.map_err(classify_io)?;
    let size = u32::from_be_bytes(header) as usize;
    if !(1..=ipc_diagnostic::MAX_FRAME).contains(&size) {
        return Err(Error::Protocol(ipc_diagnostic::Error::InvalidInput));
    }
    let mut body = Sensitive(vec![0; size]);
    io.read_exact(&mut body.0).await.map_err(classify_io)?;
    request.response(&body.0).map_err(Error::Protocol)
}
