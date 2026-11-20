#![forbid(unsafe_code)]
//! Explicitly admitted local Unix-socket transport for diagnostic I/O.
//!
//! This connects to an existing socket on the current host only. A pathname
//! and caller-provided camera claim do not authenticate the peer or prove that
//! it is the intended physical camera. It does not install a remote bridge,
//! change camera settings, settle earlier effects, or provide video capture.

use super::{
    camera_http, ipc_diagnostic_io,
    metered::{MAX_POLL_BYTES, MeteredClock, MeteredIo},
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::unix::UnixStream,
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::execution::TaskCx;
use std::{
    io,
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Explicit owner policy for one exact local pathname and camera claim.
pub trait Admission {
    /// Permit this pathname and claim at the current operation boundary.
    fn permits(&self, path: &Path, camera: Ipv4Addr, generation: u64) -> bool;
}

/// A local stream that rechecks its path admission before each I/O poll.
/// It exposes no raw stream or pathname through its public API.
pub struct Transport<'policy> {
    socket: UnixStream,
    policy: &'policy dyn Admission,
    path: PathBuf,
    camera: Ipv4Addr,
    generation: u64,
}

impl Transport<'_> {
    fn check(&self) -> io::Result<()> {
        if self
            .policy
            .permits(&self.path, self.camera, self.generation)
        {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
}

impl AsyncRead for Transport<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for Transport<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut self.socket).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

fn checkpoint<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    resource: &str,
) -> Result<(), ipc_diagnostic_io::Error> {
    if !clock.matches(task, cx) {
        return Err(ipc_diagnostic_io::Error::Configuration);
    }
    let now = clock.now().map_err(|_| ipc_diagnostic_io::Error::Denied)?;
    for grant in [RuntimeGrant::AdapterNet, RuntimeGrant::ObserveStatus] {
        task.checkpoint_for(grant, resource, now, &BudgetVector::ZERO)
            .map_err(|_| ipc_diagnostic_io::Error::Denied)?;
    }
    Ok(())
}

/// Connect one admitted local pathname and return a single-use diagnostic owner.
///
/// Path admission is repeated after connection and on every I/O poll. The
/// operating system can resolve a pathname differently between checks; this
/// interface neither authenticates socket identity nor prevents path races.
/// Connection cancellation drops its socket; an attempted diagnostic request
/// retains the existing owner's spent-on-attempt semantics.
#[allow(clippy::too_many_arguments)]
pub async fn connect<'scope, 'task, 'policy>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    camera_policy: &'policy dyn camera_http::Authority,
    path_policy: &'policy dyn Admission,
    camera: Ipv4Addr,
    generation: u64,
    path: &Path,
    resource: &str,
    max_poll: usize,
    wait: Duration,
) -> Result<
    ipc_diagnostic_io::Owner<'scope, 'task, 'policy, Transport<'policy>>,
    ipc_diagnostic_io::Error,
> {
    use ipc_diagnostic_io::Error;
    if camera.is_unspecified()
        || generation == 0
        || resource.is_empty()
        || resource.len() > 1024
        || !(1..=MAX_POLL_BYTES).contains(&max_poll)
        || wait.is_zero()
        || wait > Duration::from_secs(30)
        || !path.is_absolute()
        || path.as_os_str().len() > 4096
        || !path
            .components()
            .any(|part| matches!(part, Component::Normal(_)))
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::Configuration);
    }
    let permitted = || {
        camera_policy.permits(
            camera,
            generation,
            camera_http::Operation::SettingsSerializers,
        ) && path_policy.permits(path, camera, generation)
    };
    checkpoint(task, cx, clock, resource)?;
    if !permitted() {
        return Err(Error::Denied);
    }
    let socket = timeout_at(cx.now() + wait, UnixStream::connect(path))
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|error| Error::Io(error.kind()))?;
    checkpoint(task, cx, clock, resource)?;
    if !permitted() {
        return Err(Error::Denied);
    }
    let transport = Transport {
        socket,
        policy: path_policy,
        path: path.to_owned(),
        camera,
        generation,
    };
    let io =
        MeteredIo::with_clock(transport, clock, resource, max_poll).map_err(|error| match error
            .kind()
        {
            io::ErrorKind::PermissionDenied | io::ErrorKind::Interrupted => Error::Denied,
            _ => Error::Configuration,
        })?;
    ipc_diagnostic_io::Owner::new(
        io,
        task,
        cx,
        clock,
        camera_policy,
        camera,
        generation,
        resource,
    )
}
