#![forbid(unsafe_code)]
//! Task-owned, read-only local D-Bus handshake and BlueZ-name observation.
//!
//! The caller supplies an already connected, independently admitted local bus
//! stream. This does not connect to BlueZ, enumerate adapters, contact cameras,
//! establish Bluetooth identity, or configure Wi-Fi. No session is returned:
//! success, failure, timeout and cancellation all retire the owned stream.

use super::metered::{MeteredClock, MeteredIo};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_packet::dbus_handshake as wire;
use fss_runtime::execution::TaskCx;
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_SIGNALS: usize = 8;
const MAX_AUTH_BYTES: usize = 128;

/// Handshake stage passed to the caller's current policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Authenticate the local Unix peer using the owner-supplied UID.
    Authentication,
    /// Register this transient connection with the bus.
    Hello,
    /// Ask the bus whether its `org.bluez` name has an owner.
    BluezPresence,
}

/// Independently authorized local bus policy. It must bind the connected socket
/// and resource to the intended local bus and remain bounded and nonblocking.
pub trait Admission {
    /// Revalidate the exact operation on every transport poll.
    fn permits(&self, resource: &str, stage: Stage) -> bool;
}

/// Payload-free refusal. Every error retires the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Clock, task, resource or deadline did not match the supplied transport.
    Configuration,
    /// Current task or local-bus policy denied I/O.
    Denied,
    /// Cancellation or the total deadline interrupted the exchange.
    Interrupted,
    /// Socket I/O failed or ended early.
    Io(io::ErrorKind),
    /// The restricted D-Bus profile refused the received bytes.
    Protocol(wire::Error),
    /// Allocation or the bounded signal count was exhausted.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlueZ bus observation refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One current bus response; it does not prove an adapter or camera exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// The admitted bus reported an owner for `org.bluez`.
    pub bluez_name_owned: bool,
    /// Number of bounded signal frames discarded during the handshake.
    pub signals_skipped: usize,
}

struct Guarded<'a, 'scope, 'task, IO> {
    io: &'a mut MeteredIo<'scope, 'task, IO>,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    admission: &'a dyn Admission,
    resource: &'a str,
    stage: Stage,
}
impl<IO> Guarded<'_, '_, '_, IO> {
    fn check(&self) -> io::Result<()> {
        if !self.admission.permits(self.resource, self.stage) {
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

fn io_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied => Error::Denied,
        io::ErrorKind::Interrupted => Error::Interrupted,
        kind => Error::Io(kind),
    }
}
async fn read_exact<IO: AsyncRead + Unpin>(io: &mut IO, bytes: &mut [u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = io.read(&mut bytes[offset..]).await.map_err(io_error)?;
        if count == 0 {
            return Err(Error::Io(io::ErrorKind::UnexpectedEof));
        }
        offset += count;
    }
    Ok(())
}
async fn message<IO: AsyncRead + Unpin>(io: &mut IO) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 16];
    read_exact(io, &mut header).await?;
    let total = wire::declared_message_len(&header)
        .map_err(Error::Protocol)?
        .ok_or(Error::Protocol(wire::Error::Invalid))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&header);
    bytes.resize(total, 0);
    read_exact(io, &mut bytes[16..]).await?;
    Ok(bytes)
}

async fn response<IO: AsyncRead + Unpin>(
    io: &mut IO,
    skipped: &mut usize,
) -> Result<Vec<u8>, Error> {
    loop {
        let frame = message(io).await?;
        if frame[1] != 4 {
            return Ok(frame);
        }
        if *skipped == MAX_SIGNALS {
            return Err(Error::Limit);
        }
        *skipped += 1;
    }
}

/// Run one bounded observation over an already connected and admitted stream.
/// The caller must separately authorize socket connection, bind the path to the
/// local system bus, supply its own Unix UID, and enforce any wider time budget.
/// A partial write or read cannot be retried on this connection: it is dropped.
pub async fn observe<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    mut io: MeteredIo<'scope, 'task, IO>,
    admission: &dyn Admission,
    uid: u32,
    wait: Duration,
) -> Result<Observation, Error> {
    if wait.is_zero()
        || wait > MAX_WAIT
        || !clock.matches(task, cx)
        || !clock.same_mapping(&io.clock())
    {
        return Err(Error::Configuration);
    }
    let resource = io.resource().to_owned();
    let mut guarded = Guarded {
        io: &mut io,
        task,
        clock,
        admission,
        resource: &resource,
        stage: Stage::Authentication,
    };
    let exchange = async {
        guarded
            .write_all(&wire::external_request(uid))
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut line = Vec::new();
        line.try_reserve_exact(MAX_AUTH_BYTES)
            .map_err(|_| Error::Limit)?;
        loop {
            if wire::parse_auth_ok(&line)
                .map_err(Error::Protocol)?
                .is_some()
            {
                break;
            }
            if line.len() == MAX_AUTH_BYTES {
                return Err(Error::Limit);
            }
            let mut byte = [0u8; 1];
            read_exact(&mut guarded, &mut byte).await?;
            line.push(byte[0]);
        }
        guarded.write_all(wire::BEGIN).await.map_err(io_error)?;
        guarded.stage = Stage::Hello;
        guarded
            .write_all(&wire::hello(1).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let mut skipped = 0;
        let hello = response(&mut guarded, &mut skipped).await?;
        let parsed = wire::parse_hello_reply(&hello, 1)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if parsed.consumed() != hello.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        guarded.stage = Stage::BluezPresence;
        guarded
            .write_all(&wire::bluez_name_has_owner(2).map_err(Error::Protocol)?)
            .await
            .map_err(io_error)?;
        guarded.flush().await.map_err(io_error)?;
        let reply = response(&mut guarded, &mut skipped).await?;
        let owner = wire::parse_bluez_owner_reply(&reply, 2)
            .map_err(Error::Protocol)?
            .ok_or(Error::Protocol(wire::Error::Invalid))?;
        if owner.consumed != reply.len() {
            return Err(Error::Protocol(wire::Error::Invalid));
        }
        guarded.check().map_err(io_error)?;
        Ok(Observation {
            bluez_name_owned: owner.present,
            signals_skipped: skipped,
        })
    };
    timeout_at(cx.now() + wait, exchange)
        .await
        .map_err(|_| Error::Interrupted)?
}
