#![forbid(unsafe_code)]
//! Poll-level task authority and conservative byte debits for owned I/O.
//!
//! Place this wrapper immediately around the raw network transport, *below*
//! any TLS implementation, to meter actual network bytes. Read and write
//! reservations are separately prepaid and retained across pending polls;
//! authority is checked on every poll. Unused credit is not refunded and is
//! forfeited on the corresponding I/O error. The caller must supervise
//! cancellation, deadlines and closure, and cannot extract the inner stream.

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
};
use fss_core::{BudgetVector, RuntimeGrant, TimestampNs};
use fss_runtime::execution::TaskCx;
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

/// Maximum number of bytes admitted for any one transport poll.
pub const MAX_POLL_BYTES: usize = 16 * 1024;
const MAX_RESOURCE_BYTES: usize = 1024;

/// A single task-bound mapping between its canonical clock and the runtime timer.
///
/// Reuse the same value for nested transport layers. Independently sampling
/// their origins can make an inner poll appear older than its outer poll.
#[derive(Clone, Copy)]
pub struct MeteredClock<'scope, 'task> {
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    origin: TimestampNs,
    runtime_origin_ns: u64,
}

impl<'scope, 'task> MeteredClock<'scope, 'task> {
    /// Check that a caller uses the exact task and runtime which own this clock.
    pub fn matches(&self, owner: &TaskCx<'task>, cx: &Cx) -> bool {
        std::ptr::eq(self.owner, owner) && std::ptr::eq(self.cx, cx)
    }

    pub(crate) fn same_mapping(&self, other: &MeteredClock<'_, '_>) -> bool {
        std::ptr::eq(
            std::ptr::from_ref(self.owner).cast::<()>(),
            std::ptr::from_ref(other.owner).cast::<()>(),
        ) && std::ptr::eq(self.cx, other.cx)
            && self.origin == other.origin
            && self.runtime_origin_ns == other.runtime_origin_ns
    }
    /// Capture one mapping. `now` must be a current observation in the
    /// canonical task's clock domain, co-observed with this runtime timer.
    pub fn new(owner: &'scope TaskCx<'task>, cx: &'scope Cx, now: TimestampNs) -> io::Result<Self> {
        if !cx.has_timer() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing runtime timer",
            ));
        }
        cx.checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "runtime cancelled"))?;
        Ok(Self {
            owner,
            cx,
            origin: now,
            runtime_origin_ns: cx.now().as_nanos(),
        })
    }

    /// Observe the same task clock mapping used by every bound I/O layer.
    /// The owner must still admit the resulting timestamp at the relevant
    /// authority or effect boundary; this observation grants no permission.
    pub fn now(&self) -> io::Result<TimestampNs> {
        self.cx
            .checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "runtime cancelled"))?;
        self.at(self.cx.now().as_nanos())
    }

    fn at(&self, runtime_now: u64) -> io::Result<TimestampNs> {
        let elapsed = runtime_now
            .checked_sub(self.runtime_origin_ns)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "runtime clock regressed"))?;
        self.origin
            .0
            .checked_add(i128::from(elapsed))
            .map(TimestampNs)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "transport clock overflow"))
    }
}

/// Owned stream bound for its entire lifetime to one canonical task and Cx.
pub struct MeteredIo<'scope, 'task, IO> {
    inner: IO,
    clock: MeteredClock<'scope, 'task>,
    resource: String,
    last_runtime_ns: u64,
    max_poll: usize,
    read_credit: usize,
    write_credit: usize,
}

impl<IO> fmt::Debug for MeteredIo<'_, '_, IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeteredIo")
            .field("max_poll", &self.max_poll)
            .finish_non_exhaustive()
    }
}

impl<'scope, 'task, IO> MeteredIo<'scope, 'task, IO> {
    pub(crate) fn clock(&self) -> MeteredClock<'scope, 'task> {
        self.clock
    }
    pub(crate) fn runtime_context(&self) -> &'scope Cx {
        self.clock.cx
    }
    pub(crate) fn resource(&self) -> &str {
        &self.resource
    }

    /// Bind an already-owned stream and a co-observed canonical clock sample.
    /// The caller must supply `now` from the task's clock domain at this
    /// boundary; runtime timer elapsed time advances subsequent observations.
    pub fn new(
        inner: IO,
        owner: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        now: TimestampNs,
        resource: &str,
        max_poll: usize,
    ) -> io::Result<Self> {
        Self::with_clock(
            inner,
            MeteredClock::new(owner, cx, now)?,
            resource,
            max_poll,
        )
    }

    /// Bind a stream using an existing task clock, including when composing
    /// an outer plaintext meter with an inner encrypted-wire meter.
    pub fn with_clock(
        inner: IO,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        max_poll: usize,
    ) -> io::Result<Self> {
        if resource.is_empty()
            || resource.len() > MAX_RESOURCE_BYTES
            || !(1..=MAX_POLL_BYTES).contains(&max_poll)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid metered transport configuration",
            ));
        }
        clock
            .cx
            .checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "runtime cancelled"))?;
        let runtime_now = clock.cx.now().as_nanos();
        let now = clock.at(runtime_now)?;
        clock
            .owner
            .checkpoint_for(RuntimeGrant::AdapterNet, resource, now, &BudgetVector::ZERO)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transport authority refused",
                )
            })?;
        Ok(Self {
            inner,
            clock,
            resource: resource.to_owned(),
            last_runtime_ns: runtime_now,
            max_poll,
            read_credit: 0,
            write_credit: 0,
        })
    }

    fn admit(&mut self, requested: usize) -> io::Result<()> {
        self.clock
            .cx
            .checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "runtime cancelled"))?;
        let runtime_now = self.clock.cx.now().as_nanos();
        if runtime_now < self.last_runtime_ns {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime clock regressed",
            ));
        }
        let now = self.clock.at(runtime_now)?;
        let mut cost = BudgetVector::ZERO;
        cost.network_bytes = u64::try_from(requested).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "transport request too large")
        })?;
        self.clock
            .owner
            .checkpoint_for(RuntimeGrant::AdapterNet, &self.resource, now, &cost)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transport authority or budget refused",
                )
            })?;
        self.last_runtime_ns = runtime_now;
        Ok(())
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for MeteredIo<'_, '_, IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let requested = buf.remaining().min(this.max_poll);
        let reserve = if this.read_credit == 0 { requested } else { 0 };
        if let Err(e) = this.admit(reserve) {
            return Poll::Ready(Err(e));
        }
        this.read_credit += reserve;
        let cap = requested.min(this.read_credit);
        if cap == 0 {
            return Poll::Ready(Ok(()));
        }
        let (result, count) = {
            let mut limited = ReadBuf::new(&mut buf.unfilled()[..cap]);
            let result = Pin::new(&mut this.inner).poll_read(task, &mut limited);
            (result, limited.filled().len())
        };
        match result {
            Poll::Ready(Ok(())) => {
                buf.advance(count);
                if count == 0 {
                    this.read_credit = 0;
                } else {
                    this.read_credit -= count;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending if count == 0 => Poll::Pending,
            Poll::Ready(Err(e)) if count == 0 => {
                this.read_credit = 0;
                Poll::Ready(Err(e))
            }
            _ => {
                this.read_credit = 0;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transport changed buffer without a completed read",
                )))
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for MeteredIo<'_, '_, IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let requested = bytes.len().min(this.max_poll);
        let reserve = if this.write_credit == 0 { requested } else { 0 };
        if let Err(e) = this.admit(reserve) {
            return Poll::Ready(Err(e));
        }
        this.write_credit += reserve;
        let cap = requested.min(this.write_credit);
        if cap == 0 {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut this.inner).poll_write(task, &bytes[..cap]) {
            Poll::Ready(Ok(n)) if n > cap => {
                this.write_credit = 0;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transport reported an oversized write",
                )))
            }
            Poll::Ready(Ok(n)) => {
                this.write_credit -= n;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.write_credit = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.admit(0) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_flush(task)
    }
    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.admit(0) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_shutdown(task)
    }
}
