#![forbid(unsafe_code)]
//! Bounded matching and setup for an owner-supplied camera inventory.
//!
//! Discovery is unauthenticated. Inventory entries, certificate fingerprints,
//! and credential handles are caller claims, not authority or peer proof. The
//! supplied setup owner and camera transport must independently authenticate and
//! revalidate the exact peer and credential. Interrupted attempts remain in
//! flight and are never automatically retried.

use super::{Report, SelectionError};
use crate::unifi_direct::{camera_http, controller_listener, handoff, setup};
use asupersync::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Notify,
    time::timeout_at,
    types::Time,
};
use fss_core::{ContentDigest, DigestAlgorithm, OperationId};
use std::{
    cell::{Cell, OnceCell},
    fmt,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

const MAX_INVENTORY: usize = 128;

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}

/// One caller-supplied camera binding, with opaque credential and pin handles.
/// No credentials or certificates are stored here; the handles alone do not
/// authenticate a transport or authorize a camera operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Enrollment {
    mac: [u8; 6],
    camera: ContentDigest,
    peer_admission: ContentDigest,
    certificate: ContentDigest,
    credential: ContentDigest,
    generation: u64,
}

impl Enrollment {
    /// Bind an owner inventory claim to a certificate digest and opaque secret
    /// handle. A caller must still bind these to an authenticated transport.
    pub fn new(
        mac: [u8; 6],
        camera: ContentDigest,
        peer_admission: ContentDigest,
        certificate: ContentDigest,
        credential: ContentDigest,
        generation: u64,
    ) -> Result<Self, Error> {
        if mac == [0; 6]
            || mac[0] & 1 != 0
            || generation == 0
            || ![camera, peer_admission, certificate, credential]
                .into_iter()
                .all(valid_digest)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            mac,
            camera,
            peer_admission,
            certificate,
            credential,
            generation,
        })
    }

    /// Untrusted inventory MAC claim; this is not camera identity proof.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    /// Caller-supplied camera identity claim.
    pub fn camera(&self) -> ContentDigest {
        self.camera
    }
    /// Caller-supplied admission binding; it is not an authentication result.
    pub fn peer_admission(&self) -> ContentDigest {
        self.peer_admission
    }
    /// Expected certificate digest, requiring transport-bound verification.
    pub fn certificate(&self) -> ContentDigest {
        self.certificate
    }
    /// Opaque credential lookup handle, not a secret or a grant.
    pub fn credential(&self) -> ContentDigest {
        self.credential
    }
    /// Camera-local session generation that the caller must revalidate.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrollment").finish_non_exhaustive()
    }
}

/// Current setup eligibility for one inventory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// One unconflicted claim matched the owner inventory in this window.
    Ready { candidate: usize },
    /// This completed window did not observe the MAC; absence is not proven.
    NotObserved,
    /// The window contains ambiguous or incomplete claims for this MAC.
    Conflicted,
    /// An attempt was entered and may have been cancelled or interrupted.
    InFlight { candidate: usize },
    /// The setup future returned; its outcome and trace remain caller-owned.
    Finished { candidate: usize },
}

/// Payload-free fleet planning or attempt refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid inventory, duplicate MAC or duplicate camera claim.
    Configuration,
    /// Discovery stopped early or has inconsistent bounded counters.
    IncompleteReport,
    /// A selected entry is not ready for its first attempt.
    NotReady,
    /// Certificate or credential handle does not match the selected entry.
    Binding,
    /// The operation identity has already been reserved in this fleet.
    DuplicateOperation,
    /// A bounded allocation could not be made.
    Allocation,
    /// The existing listener-bound setup owner refused or stopped.
    Setup(setup::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi fleet setup refused: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Record {
    enrollment: Enrollment,
    state: Cell<State>,
    operation: OnceCell<OperationId>,
    route_ready: Cell<bool>,
    active: Rc<Cell<bool>>,
    setup_live: Cell<bool>,
    waiting: Cell<bool>,
    changed: Notify,
}

struct SetupLease<'a> {
    record: &'a Record,
    completed: bool,
}
impl Drop for SetupLease<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.record.setup_live.set(false);
            self.record.changed.notify_waiters();
        }
    }
}

struct WaitingLease<'a>(&'a Cell<bool>);
impl Drop for WaitingLease<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// A payload-free refusal when routing one accepted controller socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// The shared listener could not accept the next scoped connection.
    Listener(crate::unifi_direct::listener::Error),
    /// No eligible inventory entry matched this untrusted source address.
    UnknownPeer,
    /// Multiple eligible entries matched the same source; no route is chosen.
    AmbiguousPeer,
    /// This fleet instance already owns an active route for the camera.
    AlreadyActive,
    /// An early connection is already waiting for this camera's setup.
    AlreadyPending,
    /// Setup was interrupted; its effect remains unresolved.
    SetupInterrupted,
    /// Setup completed without authorizing a connection attempt.
    SetupRejected,
    /// The total accept and setup-wait deadline elapsed.
    SetupDeadline,
    /// The router's bounded pending-socket capacity is full.
    PendingCapacity,
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi fleet route refused: {self:?}")
    }
}
impl std::error::Error for RouteError {}

/// One accepted connection, either ready for TLS or owned while setup finishes.
/// Neither variant authenticates the source address or MAC claim.
#[must_use = "route or drop the accepted connection"]
pub enum AcceptedRoute<'fleet, 'scope, 'task, 'policy> {
    /// Setup already permits protocol admission.
    Ready(controller_listener::Routed<'scope, 'task, 'policy>),
    /// The caller owns an early socket and must resolve it or drop it.
    Waiting(PendingRoute<'fleet, 'scope, 'task, 'policy>),
}

/// A bounded early socket without an implicitly spawned task.
///
/// The original accept deadline is retained, but it is not actively enforced
/// until `resolve` is polled. A caller must promptly schedule `resolve` or
/// drop this value, including during shutdown. Dropping it releases the socket
/// and the fleet's one-pending-socket slot.
#[must_use = "promptly resolve or drop this early socket"]
pub struct PendingRoute<'fleet, 'scope, 'task, 'policy> {
    record: &'fleet Record,
    listener: &'fleet controller_listener::Listener<'scope, 'task, 'policy>,
    io: crate::unifi_direct::metered::MeteredIo<
        'scope,
        'task,
        controller_listener::GuardedIo<'policy, TcpStream>,
    >,
    gate: controller_listener::AdmissionGate<'policy>,
    resource: String,
    index: usize,
    deadline: Time,
    lease: WaitingLease<'fleet>,
}

impl<'fleet, 'scope, 'task, 'policy> PendingRoute<'fleet, 'scope, 'task, 'policy> {
    /// Inventory index selected by an unauthenticated source address.
    pub fn enrollment_index(&self) -> usize {
        self.index
    }

    /// Wait for the original setup and revalidate policy before routing.
    /// Dropping this future closes the socket and releases its pending slot.
    pub async fn resolve(
        self,
    ) -> Result<controller_listener::Routed<'scope, 'task, 'policy>, RouteError> {
        let Self {
            record,
            listener,
            io,
            gate,
            resource,
            index,
            deadline,
            lease,
        } = self;
        let cx = listener.runtime_context();
        cx.checkpoint()
            .map_err(|_| RouteError::Listener(crate::unifi_direct::listener::Error::Authority))?;
        if cx.now() >= deadline {
            return Err(RouteError::SetupDeadline);
        }
        if timeout_at(
            deadline,
            record.changed.wait_until(|| !record.setup_live.get()),
        )
        .await
        .is_err()
        {
            cx.checkpoint().map_err(|_| {
                RouteError::Listener(crate::unifi_direct::listener::Error::Authority)
            })?;
            return Err(RouteError::SetupDeadline);
        }
        cx.checkpoint()
            .map_err(|_| RouteError::Listener(crate::unifi_direct::listener::Error::Authority))?;
        if cx.now() >= deadline {
            return Err(RouteError::SetupDeadline);
        }
        if matches!(record.state.get(), State::InFlight { .. }) {
            return Err(RouteError::SetupInterrupted);
        }
        if !record.route_ready.get() {
            return Err(RouteError::SetupRejected);
        }
        let routed = listener
            .route_accepted(
                io,
                gate,
                index,
                record.enrollment.mac,
                resource,
                Rc::clone(&record.active),
            )
            .map_err(RouteError::Listener);
        drop(lease);
        routed
    }
}

type PendingFuture<'fleet, 'scope, 'task, 'policy> = Pin<
    Box<
        dyn Future<Output = Result<controller_listener::Routed<'scope, 'task, 'policy>, RouteError>>
            + 'fleet,
    >,
>;
type AcceptFuture<'fleet, 'scope, 'task, 'policy> = Pin<
    Box<
        dyn Future<Output = Result<AcceptedRoute<'fleet, 'scope, 'task, 'policy>, RouteError>>
            + 'fleet,
    >,
>;

/// One routed connection or one bounded, payload-free admission refusal.
#[must_use = "handle or retire the routed socket or refusal"]
pub enum RouterEvent<'scope, 'task, 'policy> {
    /// The caller owns this connection, including its active slot.
    Ready(controller_listener::Routed<'scope, 'task, 'policy>),
    /// A connection or one already-matched pending route was refused.
    Refused {
        /// Owner-inventory index if the source had already been matched.
        index: Option<usize>,
        /// Payload-free reason; this does not settle any camera effect.
        reason: RouteError,
    },
}

/// Caller-owned bounded accept and pending-route pump. No task is spawned.
///
/// Each `next` polls all held waits and one accept. A caller must keep polling
/// it, process every returned event, and supervise returned sessions. Dropping
/// it closes held sockets and cancels the pending accept. It neither discovers
/// cameras nor authenticates peers, retries effects, or provides restart
/// recovery. Runtime context, policy, and setup owners remain caller-owned.
pub struct Router<'fleet, 'report, 'scope, 'task, 'policy> {
    fleet: &'fleet Fleet<'report>,
    listener: &'fleet controller_listener::Listener<'scope, 'task, 'policy>,
    pending: Vec<(usize, PendingFuture<'fleet, 'scope, 'task, 'policy>)>,
    accept: Option<AcceptFuture<'fleet, 'scope, 'task, 'policy>>,
    capacity: usize,
    max_poll: usize,
    wait: Duration,
}

impl<'fleet, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, 'policy: 'fleet>
    Router<'fleet, 'report, 'scope, 'task, 'policy>
{
    /// Create a router with an explicit finite pending-socket bound.
    pub fn new(
        fleet: &'fleet Fleet<'report>,
        listener: &'fleet controller_listener::Listener<'scope, 'task, 'policy>,
        capacity: usize,
        max_poll: usize,
        wait: Duration,
    ) -> Result<Self, Error> {
        if !(1..=MAX_INVENTORY).contains(&capacity)
            || !(1..=crate::unifi_direct::metered::MAX_POLL_BYTES).contains(&max_poll)
            || wait.is_zero()
            || wait > Duration::from_secs(30)
        {
            return Err(Error::Configuration);
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            fleet,
            listener,
            pending,
            accept: None,
            capacity,
            max_poll,
            wait,
        })
    }

    /// Number of early sockets currently owned by this router.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Drive until a connection is ready or a refusal must be handled.
    /// Dropping this future preserves the router and its pending owners.
    pub async fn next(&mut self) -> RouterEvent<'scope, 'task, 'policy> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Poll one event while retaining any in-flight accepts and early routes.
    /// The caller must continue polling and supervise all returned sockets.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<RouterEvent<'scope, 'task, 'policy>> {
        for i in 0..self.pending.len() {
            if let Poll::Ready(result) = self.pending[i].1.as_mut().poll(cx) {
                let (index, finished) = self.pending.swap_remove(i);
                drop(finished);
                return Poll::Ready(match result {
                    Ok(route) => RouterEvent::Ready(route),
                    Err(reason) => RouterEvent::Refused {
                        index: Some(index),
                        reason,
                    },
                });
            }
        }
        if self.accept.is_none() {
            self.accept = Some(Box::pin(self.fleet.accept_one(
                self.listener,
                self.max_poll,
                self.wait,
            )));
        }
        let Some(accept) = self.accept.as_mut() else {
            unreachable!("accept installed")
        };
        match accept.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.accept = None;
                match result {
                    Err(reason) => Poll::Ready(RouterEvent::Refused {
                        index: None,
                        reason,
                    }),
                    Ok(AcceptedRoute::Ready(route)) => Poll::Ready(RouterEvent::Ready(route)),
                    Ok(AcceptedRoute::Waiting(route)) => {
                        let index = route.enrollment_index();
                        if self.pending.len() == self.capacity {
                            drop(route);
                            Poll::Ready(RouterEvent::Refused {
                                index: Some(index),
                                reason: RouteError::PendingCapacity,
                            })
                        } else {
                            self.pending.push((index, Box::pin(route.resolve())));
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }
}

/// One completed discovery window matched against a bounded owner inventory.
/// Holds no camera sockets or secrets. The report borrow prevents mutating the
/// discovery claims while their indexes are in use.
pub struct Fleet<'a> {
    report: &'a Report,
    records: Vec<Record>,
    unknown: Vec<usize>,
}

impl<'a> Fleet<'a> {
    /// Classify every inventory entry and retain every discovery claim that
    /// has no matching inventory MAC. Duplicate inventory bindings refuse the
    /// entire plan before any setup can start.
    pub fn new(report: &'a Report, inventory: &[Enrollment]) -> Result<Self, Error> {
        if !report.valid_completed() {
            return Err(Error::IncompleteReport);
        }
        if inventory.len() > MAX_INVENTORY {
            return Err(Error::Configuration);
        }
        for (i, entry) in inventory.iter().enumerate() {
            if inventory[..i]
                .iter()
                .any(|old| old.mac == entry.mac || old.camera == entry.camera)
            {
                return Err(Error::Configuration);
            }
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(inventory.len())
            .map_err(|_| Error::Allocation)?;
        for entry in inventory {
            let state = match report.select_mac_claim(entry.mac) {
                Ok(candidate) => State::Ready { candidate },
                Err(SelectionError::NotObserved) => State::NotObserved,
                Err(SelectionError::Conflicted) => State::Conflicted,
                Err(SelectionError::IncompleteReport) => return Err(Error::IncompleteReport),
                Err(SelectionError::InvalidMac) => return Err(Error::Configuration),
            };
            records.push(Record {
                enrollment: *entry,
                state: Cell::new(state),
                operation: OnceCell::new(),
                route_ready: Cell::new(false),
                active: Rc::new(Cell::new(false)),
                setup_live: Cell::new(false),
                waiting: Cell::new(false),
                changed: Notify::new(),
            });
        }
        let mut unknown = Vec::new();
        unknown
            .try_reserve_exact(report.cameras.len())
            .map_err(|_| Error::Allocation)?;
        for (index, candidate) in report.cameras.iter().enumerate() {
            if !inventory
                .iter()
                .any(|entry| Some(entry.mac) == candidate.mac())
            {
                unknown.push(index);
            }
        }
        Ok(Self {
            report,
            records,
            unknown,
        })
    }

    /// Number of caller-supplied inventory entries, including missing entries.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether the owner inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Original inventory binding, indexed by owner inventory order.
    pub fn enrollment(&self, index: usize) -> Option<Enrollment> {
        self.records.get(index).map(|record| record.enrollment)
    }
    /// Current state of one inventory entry.
    pub fn state(&self, index: usize) -> Option<State> {
        self.records.get(index).map(|record| record.state.get())
    }
    /// Reserved identity of an entered attempt, including after cancellation.
    pub fn operation(&self, index: usize) -> Option<&OperationId> {
        self.records
            .get(index)
            .and_then(|record| record.operation.get())
    }
    /// Indexes of claims not matched to an inventory MAC, including claims
    /// without a usable MAC. These remain untrusted and are not setup targets.
    pub fn unknown_claims(&self) -> &[usize] {
        &self.unknown
    }
    /// First ready inventory entry in caller-supplied order, if any.
    pub fn next_ready(&self) -> Option<usize> {
        self.records
            .iter()
            .position(|record| matches!(record.state.get(), State::Ready { .. }))
    }
    /// Whether setup returned an outcome that permits an untrusted connection
    /// attempt. This does not prove adoption, identity, or effect settlement.
    pub fn route_ready(&self, index: usize) -> bool {
        self.records
            .get(index)
            .is_some_and(|record| record.route_ready.get())
    }

    /// Whether this fleet instance holds an early socket for this entry.
    pub fn route_pending(&self, index: usize) -> bool {
        self.records
            .get(index)
            .is_some_and(|record| record.waiting.get())
    }

    /// Accept and resolve one route. For early connections this waits for setup;
    /// callers that must keep accepting other cameras may use [`Self::accept_one`]
    /// and supervise its returned waiting owners separately.
    pub async fn accept_next<'scope, 'task, 'policy>(
        &self,
        listener: &controller_listener::Listener<'scope, 'task, 'policy>,
        max_poll: usize,
        wait: Duration,
    ) -> Result<controller_listener::Routed<'scope, 'task, 'policy>, RouteError> {
        match self.accept_one(listener, max_poll, wait).await? {
            AcceptedRoute::Ready(route) => Ok(route),
            AcceptedRoute::Waiting(route) => route.resolve().await,
        }
    }

    /// Accept one connection and return ownership as soon as it is classified.
    /// A pending result reserves one socket for its camera until resolved or
    /// dropped; the listener can immediately accept another camera. Source
    /// matching is not identity: callers must independently authenticate peers,
    /// supervise pending owners, and meter and gate plaintext above TLS.
    pub async fn accept_one<'fleet, 'scope, 'task, 'policy>(
        &'fleet self,
        listener: &'fleet controller_listener::Listener<'scope, 'task, 'policy>,
        max_poll: usize,
        wait: Duration,
    ) -> Result<AcceptedRoute<'fleet, 'scope, 'task, 'policy>, RouteError> {
        if wait.is_zero() || wait > Duration::from_secs(30) {
            return Err(RouteError::Listener(
                crate::unifi_direct::listener::Error::Configuration,
            ));
        }
        let cx = listener.runtime_context();
        let deadline = cx.now() + wait;
        let (io, gate) = listener
            .accept_next(max_poll, wait)
            .await
            .map_err(RouteError::Listener)?;
        let source = *gate.source().ip();
        let mut matches =
            self.records
                .iter()
                .enumerate()
                .filter(|(_, record)| match record.state.get() {
                    State::InFlight { candidate } => self
                        .report
                        .cameras
                        .get(candidate)
                        .is_some_and(|camera| *camera.source().ip() == source),
                    State::Finished { candidate } if record.route_ready.get() => self
                        .report
                        .cameras
                        .get(candidate)
                        .is_some_and(|camera| *camera.source().ip() == source),
                    _ => false,
                });
        let (index, record) = matches.next().ok_or(RouteError::UnknownPeer)?;
        if matches.next().is_some() {
            return Err(RouteError::AmbiguousPeer);
        }
        if record.active.get() {
            return Err(RouteError::AlreadyActive);
        }
        let resource = format!("camera:{}", record.enrollment.camera.to_text());
        if !listener.can_hold(&gate, &resource) {
            return Err(RouteError::Listener(
                crate::unifi_direct::listener::Error::Denied,
            ));
        }
        // Keep a later connection from overtaking the early socket after
        // setup publishes its result but before that waiter resumes.
        if record.waiting.get() {
            return Err(RouteError::AlreadyPending);
        }
        if matches!(record.state.get(), State::InFlight { .. }) {
            if !record.setup_live.get() {
                return Err(RouteError::SetupInterrupted);
            }
            if record.waiting.replace(true) {
                return Err(RouteError::AlreadyPending);
            }
            return Ok(AcceptedRoute::Waiting(PendingRoute {
                record,
                listener,
                io,
                gate,
                resource,
                index,
                deadline,
                lease: WaitingLease(&record.waiting),
            }));
        }
        listener
            .route_accepted(
                io,
                gate,
                index,
                record.enrollment.mac,
                resource,
                Rc::clone(&record.active),
            )
            .map(AcceptedRoute::Ready)
            .map_err(RouteError::Listener)
    }

    async fn drive<T>(
        &self,
        index: usize,
        operation: &OperationId,
        work: impl Future<Output = T>,
    ) -> Result<T, Error> {
        if self
            .records
            .iter()
            .any(|record| record.operation.get() == Some(operation))
        {
            return Err(Error::DuplicateOperation);
        }
        let record = self.records.get(index).ok_or(Error::NotReady)?;
        let State::Ready { candidate } = record.state.get() else {
            return Err(Error::NotReady);
        };
        record
            .operation
            .set(operation.clone())
            .map_err(|_| Error::NotReady)?;
        record.state.set(State::InFlight { candidate });
        record.setup_live.set(true);
        let mut lease = SetupLease {
            record,
            completed: false,
        };
        let result = work.await;
        record.state.set(State::Finished { candidate });
        record.setup_live.set(false);
        lease.completed = true;
        Ok(result)
    }

    /// Run one matched camera through the existing listener-bound setup owner.
    /// The returned setup outcome and the caller-owned trace retain every
    /// effect and uncertainty. The caller must resolve the credential handle,
    /// establish and bind the pinned TLS peer, hold a lease and supply a fresh
    /// operation identity. Equality of the supplied handles is not proof of
    /// those independent steps. Setup may coexist with another camera's
    /// listener accept. Dropping this future leaves `InFlight` and the trace
    /// available; it cannot be retried through this fleet object. These
    /// in-memory reservations are local to this single-threaded fleet owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn setup_one<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        index: usize,
        owner: &mut setup::Owner<'_, '_, '_>,
        listener: &controller_listener::Listener<'_, '_, '_>,
        expected_port: u16,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        certificate: ContentDigest,
        credential_handle: ContentDigest,
        credential: &[u8],
        fence: u64,
        destination: Ipv4Addr,
        operation: &OperationId,
        framing: handoff::Framing,
        wait: Duration,
        trace: &mut setup::Trace,
    ) -> Result<setup::Outcome, Error> {
        let record = self.records.get(index).ok_or(Error::NotReady)?;
        let State::Ready { candidate } = record.state.get() else {
            return Err(Error::NotReady);
        };
        let entry = record.enrollment;
        if certificate != entry.certificate || credential_handle != entry.credential {
            return Err(Error::Binding);
        }
        let cfg = setup::Config {
            report: self.report,
            index: candidate,
            camera: entry.camera,
            peer_admission: entry.peer_admission,
            generation: entry.generation,
            fence,
            destination,
            operation,
            credential,
            wait,
        };
        let result = self
            .drive(
                index,
                operation,
                owner.run_when_listening_tracked(
                    listener,
                    expected_port,
                    camera,
                    &cfg,
                    framing,
                    trace,
                ),
            )
            .await?;
        self.records[index].route_ready.set(match &result {
            Ok(setup::Outcome::AlreadyAssociated { .. }) => true,
            Ok(setup::Outcome::Observed {
                readback, response, ..
            }) => {
                matches!(
                    readback,
                    handoff::Readback::Requested | handoff::Readback::Previous
                ) && !matches!(
                    response,
                    crate::unifi_direct::camera_api::HandoffResponseObservation::Object {
                        success: Some(false),
                        ..
                    }
                )
            }
            _ => false,
        });
        self.records[index].changed.notify_waiters();
        result.map_err(Error::Setup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unifi_direct::discovery::{CameraCandidate, Stop};
    use std::{
        net::SocketAddrV4,
        task::{Context, Poll, Waker},
    };

    fn entry(n: u8) -> Enrollment {
        Enrollment::new(
            [0x10, 1, 2, 3, 4, n],
            ContentDigest::sha256(&[n, 1]),
            ContentDigest::sha256(&[n, 2]),
            ContentDigest::sha256(&[n, 3]),
            ContentDigest::sha256(&[n, 4]),
            1,
        )
        .unwrap()
    }

    fn candidate(ip: u8, mac: Option<[u8; 6]>) -> CameraCandidate {
        CameraCandidate {
            source: SocketAddrV4::new(Ipv4Addr::new(192, 168, 7, ip), 10001),
            platform: "UVC G4".into(),
            firmware: None,
            mac,
            source_advertised: true,
        }
    }

    fn report(cameras: Vec<CameraCandidate>) -> Report {
        Report {
            datagrams: cameras.len(),
            cameras,
            malformed: 0,
            out_of_scope: 0,
            stop: Stop::WindowElapsed,
        }
    }

    #[test]
    fn fleet_matches_all_inventory_and_retains_unknown_and_conflicted_claims() {
        let first = entry(1);
        let second = entry(2);
        let missing = entry(3);
        let report = report(vec![
            candidate(10, Some(first.mac)),
            candidate(11, Some(second.mac)),
            candidate(12, Some(second.mac)),
            candidate(13, Some(entry(4).mac)),
            candidate(14, None),
        ]);
        let fleet = Fleet::new(&report, &[first, second, missing]).unwrap();
        assert_eq!(fleet.len(), 3);
        assert_eq!(fleet.next_ready(), Some(0));
        assert_eq!(fleet.state(0), Some(State::Ready { candidate: 0 }));
        assert_eq!(fleet.state(1), Some(State::Conflicted));
        assert_eq!(fleet.state(2), Some(State::NotObserved));
        assert_eq!(fleet.unknown_claims(), &[3, 4]);
        assert!(!format!("{first:?}").contains("10.1.2"));
    }

    #[test]
    fn fleet_refuses_incomplete_reports_and_duplicate_owner_bindings() {
        let one = entry(1);
        let mut other = entry(2);
        let mut input = report(vec![candidate(10, Some(one.mac))]);
        assert!(matches!(
            Fleet::new(&input, &[one, one]),
            Err(Error::Configuration)
        ));
        other.camera = one.camera;
        assert!(matches!(
            Fleet::new(&input, &[one, other]),
            Err(Error::Configuration)
        ));
        input.stop = Stop::PacketLimit;
        assert!(matches!(
            Fleet::new(&input, &[one]),
            Err(Error::IncompleteReport)
        ));
        input.stop = Stop::WindowElapsed;
        input.datagrams = 0;
        assert!(matches!(
            Fleet::new(&input, &[one]),
            Err(Error::IncompleteReport)
        ));
        assert!(
            Enrollment::new(
                [1, 2, 3, 4, 5, 6],
                one.camera,
                one.peer_admission,
                one.certificate,
                one.credential,
                1
            )
            .is_err()
        );
    }

    #[test]
    fn dropped_attempt_stays_in_flight_and_other_camera_remains_ready() {
        let first = entry(1);
        let second = entry(2);
        let input = report(vec![
            candidate(10, Some(first.mac)),
            candidate(11, Some(second.mac)),
        ]);
        let fleet = Fleet::new(&input, &[first, second]).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let first_op = OperationId::parse("operation:fleet-one").unwrap();
        let second_op = OperationId::parse("operation:fleet-two").unwrap();
        let mut work = Box::pin(fleet.drive(0, &first_op, std::future::pending::<()>()));
        assert!(matches!(work.as_mut().poll(&mut context), Poll::Pending));
        let record = &fleet.records[0];
        let mut waiter = Box::pin(record.changed.wait_until(|| !record.setup_live.get()));
        assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.operation(0), Some(&first_op));
        assert_eq!(fleet.next_ready(), Some(1));
        let mut collision = Box::pin(fleet.drive(1, &first_op, std::future::ready(())));
        assert!(matches!(
            collision.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::DuplicateOperation))
        ));
        drop(collision);
        let mut retry = Box::pin(fleet.drive(0, &second_op, std::future::ready(())));
        assert!(matches!(
            retry.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NotReady))
        ));
        drop(retry);
        let mut next = Box::pin(fleet.drive(1, &second_op, std::future::ready(42)));
        assert!(matches!(
            next.as_mut().poll(&mut context),
            Poll::Ready(Ok(42))
        ));
        drop(next);
        // The first future still owns its in-flight reservation while a
        // different camera completes. Dropping it must not make it retryable.
        drop(work);
        assert!(matches!(
            waiter.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.state(1), Some(State::Finished { candidate: 1 }));
        assert_eq!(fleet.next_ready(), None);
    }
}
