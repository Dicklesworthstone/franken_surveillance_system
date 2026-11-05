#![forbid(unsafe_code)]
//! Bounded, task-owned UniFi controller TCP accepts.
//!
//! The socket's source address is an admission hint, not camera identity.
//! The caller must apply independently established identity, current policy,
//! TLS and protocol admission before sending any management response. Each
//! The one-shot `accept` consumes the listener. `accept_next` borrows it for
//! sequential attempts; retry limits and supervision belong to the caller.

use super::{
    listener,
    metered::{MAX_POLL_BYTES, MeteredClock, MeteredIo},
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::execution::TaskCx;
use std::{
    cell::Cell,
    future::poll_fn,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_RESOURCE: usize = 1024;

fn valid_ip(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_loopback() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
}
fn valid_wait(wait: Duration) -> bool {
    !wait.is_zero() && wait <= MAX_WAIT
}

/// Shared, connection-bound admission state for both raw and decrypted I/O.
/// It does not establish cryptographic identity. Apply it to the TLS stream
/// built from this exact accepted socket, before any application-level I/O.
#[derive(Clone)]
pub struct AdmissionGate<'policy> {
    state: Rc<GateState<'policy>>,
}
struct GateState<'policy> {
    policy: &'policy dyn listener::Admission,
    requested: SocketAddrV4,
    bound: SocketAddrV4,
    source: SocketAddrV4,
    fenced: Cell<bool>,
}
impl<'policy> AdmissionGate<'policy> {
    /// Revalidate admission and permanently fence this connection on denial.
    /// Protocol owners must call this before handling already-buffered messages.
    pub fn check(&self) -> io::Result<()> {
        let state = &self.state;
        if !state.fenced.get()
            && state.policy.listener(state.requested, Some(state.bound))
            && state.policy.peer(state.bound, state.source)
        {
            Ok(())
        } else {
            state.fenced.set(true);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controller peer admission revoked",
            ))
        }
    }
    /// The source-address observation associated with this gate; not identity.
    pub fn source(&self) -> SocketAddrV4 {
        self.state.source
    }
    /// Guard an I/O layer built from this same accepted connection. All wrappers
    /// share a permanent fence; the caller must not attach this to another peer.
    pub fn wrap<IO>(&self, io: IO) -> GuardedIo<'policy, IO> {
        GuardedIo {
            inner: io,
            gate: self.clone(),
        }
    }
}

/// I/O layer with shared peer-policy revalidation before every poll. A denial
/// fences all layers of this connection even if policy is later restored.
pub struct GuardedIo<'policy, IO> {
    inner: IO,
    gate: AdmissionGate<'policy>,
}
impl<IO: AsyncRead + Unpin> AsyncRead for GuardedIo<'_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.gate.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for GuardedIo<'_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.gate.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.gate.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.gate.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// One controller listener and its explicit authority and peer policy.
pub struct Listener<'scope, 'task, 'policy> {
    listener: TcpListener,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    policy: &'policy dyn listener::Admission,
    requested: SocketAddrV4,
    bound: SocketAddrV4,
    resource: String,
}

impl<'scope, 'task, 'policy> Listener<'scope, 'task, 'policy> {
    fn check(
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
    ) -> Result<(), listener::Error> {
        if !clock.matches(task, cx) {
            return Err(listener::Error::Configuration);
        }
        let now = clock.now().map_err(|_| listener::Error::Authority)?;
        task.checkpoint_for(RuntimeGrant::AdapterNet, resource, now, &BudgetVector::ZERO)
            .map_err(|_| listener::Error::Authority)
    }

    /// Bind one scoped interface; port zero requests a policy-checked OS port.
    pub async fn bind(
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        policy: &'policy dyn listener::Admission,
        requested: SocketAddrV4,
        resource: &str,
        wait: Duration,
    ) -> Result<Self, listener::Error> {
        if !valid_ip(*requested.ip())
            || resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || !valid_wait(wait)
        {
            return Err(listener::Error::Configuration);
        }
        Self::check(task, cx, clock, resource)?;
        if !policy.listener(requested, None) {
            return Err(listener::Error::Denied);
        }
        let socket = timeout_at(
            cx.now() + wait,
            TcpListener::bind(SocketAddr::V4(requested)),
        )
        .await
        .map_err(|_| listener::Error::Deadline)?
        .map_err(|error| listener::Error::Io(error.kind()))?;
        Self::check(task, cx, clock, resource)?;
        let bound = match socket
            .local_addr()
            .map_err(|error| listener::Error::Io(error.kind()))?
        {
            SocketAddr::V4(address) => address,
            _ => return Err(listener::Error::Configuration),
        };
        if !valid_ip(*bound.ip()) || bound.port() == 0 || !policy.listener(requested, Some(bound)) {
            return Err(listener::Error::Denied);
        }
        Ok(Self {
            listener: socket,
            task,
            cx,
            clock,
            policy,
            requested,
            bound,
            resource: resource.to_owned(),
        })
    }

    /// Bound address. This establishes neither peer identity nor reachability.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.bound
    }

    /// Accept one currently admitted peer and meter ciphertext at the raw socket.
    /// Dropping the pending future closes its listener. Returned sockets still
    /// recheck this policy at every raw poll. Wrap the resulting TLS stream
    /// with the returned gate before reading or writing decrypted data. TLS,
    /// independent identity and protocol authorization remain caller-owned.
    pub async fn accept(
        mut self,
        max_poll: usize,
        wait: Duration,
    ) -> Result<
        (
            MeteredIo<'scope, 'task, GuardedIo<'policy, TcpStream>>,
            AdmissionGate<'policy>,
        ),
        listener::Error,
    > {
        self.accept_next(max_poll, wait).await
    }

    /// Accept one peer while retaining the listener for a later sequential
    /// attempt. Dropping this future leaves the caller-owned listener open;
    /// callers must bound attempts, total time, and any protocol effects.
    pub async fn accept_next(
        &mut self,
        max_poll: usize,
        wait: Duration,
    ) -> Result<
        (
            MeteredIo<'scope, 'task, GuardedIo<'policy, TcpStream>>,
            AdmissionGate<'policy>,
        ),
        listener::Error,
    > {
        if !(1..=MAX_POLL_BYTES).contains(&max_poll) || !valid_wait(wait) {
            return Err(listener::Error::Configuration);
        }
        let accept = poll_fn(|context| {
            if let Err(error) = Self::check(self.task, self.cx, self.clock, &self.resource) {
                return Poll::Ready(Err(error));
            }
            if !self.policy.listener(self.requested, Some(self.bound)) {
                return Poll::Ready(Err(listener::Error::Denied));
            }
            match self.listener.poll_accept(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(connection)) => Poll::Ready(Ok(connection)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(listener::Error::Io(error.kind()))),
            }
        });
        let (socket, source) = timeout_at(self.cx.now() + wait, accept)
            .await
            .map_err(|_| listener::Error::Deadline)??;
        Self::check(self.task, self.cx, self.clock, &self.resource)?;
        let source = match source {
            SocketAddr::V4(address) => address,
            _ => return Err(listener::Error::Denied),
        };
        if !valid_ip(*source.ip())
            || !self.policy.listener(self.requested, Some(self.bound))
            || !self.policy.peer(self.bound, source)
        {
            return Err(listener::Error::Denied);
        }
        let gate = AdmissionGate {
            state: Rc::new(GateState {
                policy: self.policy,
                requested: self.requested,
                bound: self.bound,
                source,
                fenced: Cell::new(false),
            }),
        };
        let guarded = gate.wrap(socket);
        let io = MeteredIo::with_clock(guarded, self.clock, &self.resource, max_poll)
            .map_err(|_| listener::Error::Source)?;
        Ok((io, gate))
    }
}
