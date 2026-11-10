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
    cell::{Cell, OnceCell},
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
    listener_identity: Rc<()>,
    camera: OnceCell<CameraBinding>,
}
struct CameraBinding {
    listener_resource: String,
    camera_resource: String,
}
impl<'policy> AdmissionGate<'policy> {
    /// Revalidate admission and permanently fence this connection on denial.
    /// Protocol owners must call this before handling already-buffered messages.
    pub fn check(&self) -> io::Result<()> {
        let state = &self.state;
        if !state.fenced.get()
            && state.policy.listener(state.requested, Some(state.bound))
            && state.policy.peer(state.bound, state.source)
            && state.camera.get().is_none_or(|camera| {
                camera.listener_resource == camera.camera_resource
                    || state.policy.controller_camera(
                        state.bound,
                        &camera.listener_resource,
                        &camera.camera_resource,
                        *state.source.ip(),
                    )
            })
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
    identity: Rc<()>,
    accepting: Cell<bool>,
}

struct AcceptLease<'a>(&'a Cell<bool>);
impl Drop for AcceptLease<'_> {
    fn drop(&mut self) { self.0.set(false); }
}

/// One accepted, camera-scoped connection. Its source and inventory index are
/// untrusted routing claims, not authenticated device identity. The active
/// slot stays owned until this value (including any TLS wrapper) is dropped.
pub struct Routed<'scope, 'task, 'policy> {
    io: MeteredIo<'scope, 'task, GuardedIo<'policy, TcpStream>>,
    gate: AdmissionGate<'policy>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: String,
    index: usize,
    mac: [u8; 6],
    active: Rc<Cell<bool>>,
}

impl<'scope, 'task, 'policy> Routed<'scope, 'task, 'policy> {
    /// Inventory entry selected by the untrusted source address.
    pub fn enrollment_index(&self) -> usize { self.index }
    /// Owner-inventory MAC associated with this route. This is a claim, not
    /// proof of the connecting peer's identity.
    pub fn claimed_mac(&self) -> [u8; 6] { self.mac }
    /// Clone the same permanently fencing gate for the TLS/plaintext layer.
    pub fn gate(&self) -> AdmissionGate<'policy> { self.gate.clone() }

    /// Use the identical task clock when metering the plaintext TLS layer.
    pub fn clock(&self) -> MeteredClock<'scope, 'task> { self.clock }

    /// Camera-specific resource associated with both layers of this route.
    pub fn resource(&self) -> &str { &self.resource }

    /// Check that the protocol driver uses the route's runtime context.
    pub fn matches_context(&self, cx: &Cx) -> bool { std::ptr::eq(self.cx, cx) }

    fn admit(&self) -> io::Result<()> {
        self.gate.check()?;
        if Listener::check(self.task, self.cx, self.clock, &self.resource).is_err() {
            self.gate.state.fenced.set(true);
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "camera route authority refused"));
        }
        Ok(())
    }
}

impl Drop for Routed<'_, '_, '_> {
    fn drop(&mut self) { self.active.set(false); }
}

impl AsyncRead for Routed<'_, '_, '_> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.admit() { return Poll::Ready(Err(error)); }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Routed<'_, '_, '_> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if let Err(error) = self.admit() { return Poll::Ready(Err(error)); }
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.admit() { return Poll::Ready(Err(error)); }
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.admit() { return Poll::Ready(Err(error)); }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
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
            identity: Rc::new(()),
            accepting: Cell::new(false),
        })
    }

    /// Bound address. This establishes neither peer identity nor reachability.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.bound
    }

    pub(crate) fn runtime_context(&self) -> &'scope Cx {
        self.cx
    }

    /// Recheck task and camera policy before holding an early socket.
    pub(crate) fn can_hold(&self, gate: &AdmissionGate<'_>, resource: &str) -> bool {
        Rc::ptr_eq(&self.identity, &gate.state.listener_identity)
            && gate.check().is_ok()
            && self.ready_for(self.task, self.cx, &self.clock, resource, self.bound, *gate.source().ip())
    }

    /// Revalidate this exact bound socket against its task, clock, resource,
    /// endpoint and live listener policy. This does not prove reachability.
    pub(crate) fn ready_for(
        &self,
        task: &TaskCx<'_>,
        cx: &Cx,
        clock: &MeteredClock<'_, '_>,
        resource: &str,
        endpoint: SocketAddrV4,
        claimed_peer: Ipv4Addr,
    ) -> bool {
        endpoint.port() != 0
            && self.bound == endpoint
            && std::ptr::eq(
                std::ptr::from_ref(self.task).cast::<()>(),
                std::ptr::from_ref(task).cast::<()>(),
            )
            && std::ptr::eq(self.cx, cx)
            && self.clock.same_mapping(clock)
            && self.policy.listener(self.requested, Some(self.bound))
            && (self.resource == resource
                || self.policy.controller_camera(
                    self.bound, &self.resource, resource, claimed_peer,
                ))
            // Policy evaluation may itself consume time or revoke task
            // authority. Recheck both scoped resources after it returns.
            && Self::check(self.task, self.cx, self.clock, &self.resource).is_ok()
            && (self.resource == resource
                || Self::check(self.task, self.cx, self.clock, resource).is_ok())
    }

    /// Accept one currently admitted peer and meter ciphertext at the raw socket.
    /// Dropping the pending future closes its listener. Returned sockets still
    /// recheck this policy at every raw poll. Wrap the resulting TLS stream
    /// with the returned gate before reading or writing decrypted data. TLS,
    /// independent identity and protocol authorization remain caller-owned.
    pub async fn accept(
        self,
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

    /// Accept one peer while retaining the listener for a later attempt.
    /// A concurrent accept is refused; dropping this future releases its
    /// accept slot and leaves the caller-owned listener open. Setup may hold
    /// a shared listener reference while this future is pending.
    pub async fn accept_next(
        &self,
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
        if self.accepting.replace(true) {
            return Err(listener::Error::Busy);
        }
        let _lease = AcceptLease(&self.accepting);
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
                listener_identity: Rc::clone(&self.identity),
                camera: OnceCell::new(),
            }),
        };
        let guarded = gate.wrap(socket);
        let io = MeteredIo::with_clock(guarded, self.clock, &self.resource, max_poll)
            .map_err(|_| listener::Error::Source)?;
        Ok((io, gate))
    }

    /// Attach one camera resource to a socket accepted by this exact listener.
    /// Called only after a fleet has selected a unique admitted source claim.
    pub(crate) fn route_accepted(
        &self,
        io: MeteredIo<'scope, 'task, GuardedIo<'policy, TcpStream>>,
        gate: AdmissionGate<'policy>,
        index: usize,
        mac: [u8; 6],
        resource: String,
        active: Rc<Cell<bool>>,
    ) -> Result<Routed<'scope, 'task, 'policy>, listener::Error> {
        if !Rc::ptr_eq(&self.identity, &gate.state.listener_identity)
            || active.get()
            || resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || !self.ready_for(self.task, self.cx, &self.clock, &resource, self.bound, *gate.source().ip())
        {
            return Err(listener::Error::Denied);
        }
        let mut listener_resource = String::new();
        let mut camera_resource = String::new();
        listener_resource.try_reserve_exact(self.resource.len()).map_err(|_| listener::Error::Source)?;
        camera_resource.try_reserve_exact(resource.len()).map_err(|_| listener::Error::Source)?;
        listener_resource.push_str(&self.resource);
        camera_resource.push_str(&resource);
        gate.state.camera.set(CameraBinding { listener_resource, camera_resource })
            .map_err(|_| listener::Error::Denied)?;
        gate.check().map_err(|_| listener::Error::Denied)?;
        // The gate policy can itself consume authority; check the camera and
        // listener task scopes again before handing the socket to its owner.
        Self::check(self.task, self.cx, self.clock, &self.resource)?;
        Self::check(self.task, self.cx, self.clock, &resource)?;
        active.set(true);
        Ok(Routed { io, gate, task: self.task, cx: self.cx, clock: self.clock,
            resource, index, mac, active })
    }
}
