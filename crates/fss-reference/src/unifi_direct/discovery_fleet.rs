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
    Cx,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Notify,
    time::timeout_at,
    types::Time,
};
use fss_core::{ContentDigest, DigestAlgorithm, OperationId};
use std::{
    cell::{Cell, OnceCell, RefCell},
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    net::Ipv4Addr,
    ops::Index,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

// A pre-effect outcome can be safe to retry without being useful or safe to
// retry automatically. In particular, do not repeat rejected credentials,
// denied authority, malformed responses or a missing video profile on a timer.
fn transient_setup_error(error: &setup::Error) -> bool {
    match error {
        setup::Error::Deadline | setup::Error::Camera(camera_http::Error::Deadline) => true,
        setup::Error::Camera(camera_http::Error::Io(kind)) => matches!(
            kind,
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::NotConnected
        ),
        _ => false,
    }
}

pub(super) const MAX_INVENTORY: usize = 128;
const MAX_SETUP_ATTEMPTS: usize = 16;

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}

// A discovery source is only a routing hint. It must never be treated as
// peer authentication or as a settlement of a prior setup effect.
fn source_claim(report: &Report, mac: [u8; 6]) -> Option<Ipv4Addr> {
    let index = report.select_mac_claim(mac).ok()?;
    report
        .cameras
        .get(index)
        .map(|camera| *camera.source().ip())
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
    /// This camera has exhausted its bounded retained operation history.
    AttemptCapacity,
    /// The previous attempt was not proven to have stopped before preparation.
    RetryNotSafe,
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

/// A refused refresh returns the exact supplied discovery window.
#[must_use = "retain or explicitly discard the refused discovery window"]
pub struct RefreshRefusal {
    /// Payload-free refusal category.
    pub reason: Error,
    /// Original report, which remains an unauthenticated observation.
    pub report: Report,
}
impl fmt::Debug for RefreshRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRefusal")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for RefreshRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi discovery refresh refused: {:?}", self.reason)
    }
}
impl std::error::Error for RefreshRefusal {}

struct Record {
    enrollment: Enrollment,
    report: RefCell<Rc<Report>>,
    state: Cell<State>,
    operations: [OnceCell<OperationId>; MAX_SETUP_ATTEMPTS],
    operation_count: Cell<usize>,
    retry_before_effect: Cell<bool>,
    retry_automatically: Cell<bool>,
    route_ready: Cell<bool>,
    route_source: Cell<Option<Ipv4Addr>>,
    active: Rc<Cell<bool>>,
    setup_live: Cell<bool>,
    waiting: Cell<bool>,
    changed: Notify,
}

impl Record {
    fn operations(&self) -> impl Iterator<Item = &OperationId> {
        self.operations[..self.operation_count.get()]
            .iter()
            .map(|slot| slot.get().expect("published setup operation"))
    }

    fn reserve_operation(&self, operation: &OperationId) -> Result<(), Error> {
        let count = self.operation_count.get();
        let slot = self.operations.get(count).ok_or(Error::AttemptCapacity)?;
        slot.set(operation.clone()).map_err(|_| Error::NotReady)?;
        self.operation_count.set(count + 1);
        Ok(())
    }
}

// All slots are allocated before the fleet is published. Once initialized, a
// record never moves or disappears, so existing setup and pending-route owners
// may keep borrowing it while another owner appends an authorized enrollment.
struct Records {
    slots: Vec<OnceCell<Record>>,
    len: Cell<usize>,
}

impl Records {
    fn new() -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(MAX_INVENTORY)
            .map_err(|_| Error::Allocation)?;
        slots.resize_with(MAX_INVENTORY, OnceCell::new);
        Ok(Self {
            slots,
            len: Cell::new(0),
        })
    }

    fn len(&self) -> usize {
        self.len.get()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn get(&self, index: usize) -> Option<&Record> {
        (index < self.len()).then(|| self.slots[index].get().expect("published record"))
    }
    fn iter(&self) -> impl ExactSizeIterator<Item = &Record> {
        self.slots[..self.len()]
            .iter()
            .map(|slot| slot.get().expect("published record"))
    }
    fn push(&self, record: Record) -> Result<usize, Error> {
        let index = self.len();
        let slot = self.slots.get(index).ok_or(Error::Configuration)?;
        slot.set(record).map_err(|_| Error::Configuration)?;
        self.len.set(index + 1);
        Ok(index)
    }
}

impl Index<usize> for Records {
    type Output = Record;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("valid fleet record index")
    }
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
    /// The latest completed discovery window no longer matches this socket.
    ClaimChanged,
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
        if record.route_source.get() != Some(*gate.source().ip()) {
            return Err(RouteError::ClaimChanged);
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

    /// The exact caller-supplied fleet retained by this router.
    pub fn fleet(&self) -> &'fleet Fleet<'report> {
        self.fleet
    }

    /// Check the exact fleet and task clock of a periodic scanner. This
    /// proves only local owner binding, not authorization or peer identity.
    pub fn matches_scanner(&self, scanner: &super::scan::Scanner<'_, '_, 'scope, 'task>) -> bool {
        Rc::ptr_eq(&self.fleet.identity, &scanner.fleet_identity())
            && self.listener.matches_clock(&scanner.clock())
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

/// One immutable discovery window and its corresponding unregistered indexes.
/// Retaining this snapshot keeps its indexes bound to the exact same report.
pub struct DiscoverySnapshot {
    report: Rc<Report>,
    unknown: Rc<[usize]>,
}
impl DiscoverySnapshot {
    /// Completed, unauthenticated discovery report.
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Indexes into this snapshot's report, not durable camera identities.
    pub fn unknown_claims(&self) -> &[usize] {
        &self.unknown
    }
}

/// Completed discovery windows matched against a bounded owner inventory.
/// Holds no camera sockets or secrets. Attempted entries keep their original
/// owned report while unattempted entries can follow newer completed windows.
pub struct Fleet<'a> {
    identity: Rc<()>,
    latest: RefCell<Rc<DiscoverySnapshot>>,
    initial_report: PhantomData<&'a Report>,
    records: Records,
    enrollment_changed: Notify,
}

impl<'a> Fleet<'a> {
    /// Classify every inventory entry and retain every discovery claim that
    /// has no matching inventory MAC. Duplicate inventory bindings refuse the
    /// entire plan before any setup can start.
    pub fn new(report: &'a Report, inventory: &[Enrollment]) -> Result<Self, Error> {
        if !report.valid_completed() {
            return Err(Error::IncompleteReport);
        }
        Self::build(report.clone(), inventory)
    }

    fn build(report: Report, inventory: &[Enrollment]) -> Result<Self, Error> {
        if !report.valid_completed() {
            return Err(Error::IncompleteReport);
        }
        if inventory.len() > MAX_INVENTORY {
            return Err(Error::Configuration);
        }
        let report = Rc::new(report);
        for (i, entry) in inventory.iter().enumerate() {
            if inventory[..i]
                .iter()
                .any(|old| old.mac == entry.mac || old.camera == entry.camera)
            {
                return Err(Error::Configuration);
            }
        }
        let records = Records::new()?;
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
                report: RefCell::new(Rc::clone(&report)),
                state: Cell::new(state),
                operations: std::array::from_fn(|_| OnceCell::new()),
                operation_count: Cell::new(0),
                retry_before_effect: Cell::new(false),
                retry_automatically: Cell::new(false),
                route_ready: Cell::new(false),
                route_source: Cell::new(None),
                active: Rc::new(Cell::new(false)),
                setup_live: Cell::new(false),
                waiting: Cell::new(false),
                changed: Notify::new(),
            })?;
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
            identity: Rc::new(()),
            latest: RefCell::new(Rc::new(DiscoverySnapshot {
                report,
                unknown: unknown.into(),
            })),
            initial_report: PhantomData,
            records,
            enrollment_changed: Notify::new(),
        })
    }

    pub(super) fn identity(&self) -> Rc<()> {
        Rc::clone(&self.identity)
    }

    /// Install a new completed window for entries without an entered setup.
    /// Attempted entries retain their original report and operation, including
    /// interrupted attempts. Finished entries that permit routing update their
    /// untrusted source hint from this window; absent or conflicting claims
    /// suspend new routes. Existing admitted sockets are not affected. A
    /// refusal changes nothing.
    /// The caller supplies and owns the bounded scan; this does not scan,
    /// authenticate a peer, or authorize an automatic retry.
    pub fn refresh(&self, report: Report) -> Result<(), RefreshRefusal> {
        if !report.valid_completed() {
            return Err(RefreshRefusal {
                reason: Error::IncompleteReport,
                report,
            });
        }
        let mut states = Vec::new();
        if states.try_reserve_exact(self.records.len()).is_err() {
            return Err(RefreshRefusal {
                reason: Error::Allocation,
                report,
            });
        }
        for record in self.records.iter() {
            let state = match record.state.get() {
                State::InFlight { .. } | State::Finished { .. } => None,
                _ => Some(match report.select_mac_claim(record.enrollment.mac) {
                    Ok(candidate) => State::Ready { candidate },
                    Err(SelectionError::NotObserved) => State::NotObserved,
                    Err(SelectionError::Conflicted) => State::Conflicted,
                    Err(SelectionError::IncompleteReport) => {
                        return Err(RefreshRefusal {
                            reason: Error::IncompleteReport,
                            report,
                        });
                    }
                    Err(SelectionError::InvalidMac) => {
                        return Err(RefreshRefusal {
                            reason: Error::Configuration,
                            report,
                        });
                    }
                }),
            };
            states.push(state);
        }
        let mut unknown = Vec::new();
        if unknown.try_reserve_exact(report.cameras.len()).is_err() {
            return Err(RefreshRefusal {
                reason: Error::Allocation,
                report,
            });
        }
        for (index, candidate) in report.cameras.iter().enumerate() {
            if !self
                .records
                .iter()
                .any(|record| Some(record.enrollment.mac) == candidate.mac())
            {
                unknown.push(index);
            }
        }
        let report = Rc::new(report);
        for (record, state) in self.records.iter().zip(states) {
            if let Some(state) = state {
                *record.report.borrow_mut() = Rc::clone(&report);
                record.state.set(state);
            } else if matches!(record.state.get(), State::Finished { .. })
                && record.route_ready.get()
            {
                record
                    .route_source
                    .set(source_claim(&report, record.enrollment.mac));
            }
        }
        *self.latest.borrow_mut() = Rc::new(DiscoverySnapshot {
            report,
            unknown: unknown.into(),
        });
        Ok(())
    }

    /// Add an explicitly supplied owner binding without rebuilding the fleet.
    /// An unknown discovery claim alone cannot create credentials or authority.
    /// Existing attempted entries and their reservations are left unchanged.
    /// Stable bounded slots allow scanner, router, and existing session owners
    /// to remain borrowed while a new binding is appended. This does not
    /// authenticate a discovery claim or grant authority to start setup.
    pub fn add_enrollment(&self, enrollment: Enrollment) -> Result<usize, Error> {
        if self.records.len() == MAX_INVENTORY
            || self.records.iter().any(|record| {
                record.enrollment.mac == enrollment.mac
                    || record.enrollment.camera == enrollment.camera
            })
        {
            return Err(Error::Configuration);
        }
        let report = Rc::clone(&self.latest.borrow().report);
        let state = match report.select_mac_claim(enrollment.mac) {
            Ok(candidate) => State::Ready { candidate },
            Err(SelectionError::NotObserved) => State::NotObserved,
            Err(SelectionError::Conflicted) => State::Conflicted,
            Err(SelectionError::IncompleteReport) => return Err(Error::IncompleteReport),
            Err(SelectionError::InvalidMac) => return Err(Error::Configuration),
        };
        let mut unknown = Vec::new();
        unknown
            .try_reserve_exact(report.cameras.len())
            .map_err(|_| Error::Allocation)?;
        for (index, candidate) in report.cameras.iter().enumerate() {
            if Some(enrollment.mac) != candidate.mac()
                && !self
                    .records
                    .iter()
                    .any(|record| Some(record.enrollment.mac) == candidate.mac())
            {
                unknown.push(index);
            }
        }
        let snapshot = Rc::new(DiscoverySnapshot {
            report: Rc::clone(&report),
            unknown: unknown.into(),
        });
        let index = self.records.push(Record {
            enrollment,
            report: RefCell::new(Rc::clone(&report)),
            state: Cell::new(state),
            operations: std::array::from_fn(|_| OnceCell::new()),
            operation_count: Cell::new(0),
            retry_before_effect: Cell::new(false),
            retry_automatically: Cell::new(false),
            route_ready: Cell::new(false),
            route_source: Cell::new(None),
            active: Rc::new(Cell::new(false)),
            setup_live: Cell::new(false),
            waiting: Cell::new(false),
            changed: Notify::new(),
        })?;
        *self.latest.borrow_mut() = snapshot;
        self.enrollment_changed.notify_waiters();
        Ok(index)
    }

    /// Wait until an owner has appended an enrollment after `observed_len`.
    /// This notification conveys no device identity or setup authority.
    pub async fn wait_for_enrollment_after(
        &self,
        cx: &Cx,
        observed_len: usize,
    ) -> std::io::Result<()> {
        if observed_len > MAX_INVENTORY {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let mut wait = std::pin::pin!(
            self.enrollment_changed
                .wait_until(|| self.len() > observed_len)
        );
        poll_fn(|context| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
            }
            match wait.as_mut().poll(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => Poll::Ready(
                    cx.checkpoint()
                        .map_err(|_| std::io::ErrorKind::Interrupted.into()),
                ),
            }
        })
        .await
    }

    /// A stable snapshot of the latest completed report and its claim indexes.
    pub fn latest_snapshot(&self) -> Rc<DiscoverySnapshot> {
        Rc::clone(&self.latest.borrow())
    }

    /// The latest completed report. Pair indexes with `latest_snapshot` when
    /// they must remain tied to the same window across an async yield.
    pub fn latest_report(&self) -> Rc<Report> {
        Rc::clone(&self.latest.borrow().report)
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
    /// Most recent reserved identity, including after cancellation. Earlier
    /// attempt identities remain reserved for the lifetime of this fleet.
    pub fn operation(&self, index: usize) -> Option<&OperationId> {
        self.records
            .get(index)
            .and_then(|record| record.operations().last())
    }

    // A schedule can only refer to the exact returned pre-effect failure.
    // The marker and operation are rechecked again when its timer expires.
    pub(super) fn retry_candidate(&self, index: usize) -> Option<(&OperationId, usize)> {
        let record = self.records.get(index)?;
        if !record.retry_before_effect.get()
            || !matches!(record.state.get(), State::Finished { .. })
        {
            return None;
        }
        Some((record.operations().last()?, record.operation_count.get()))
    }

    // An automatic timer needs both the exact pre-effect attempt and an
    // explicitly classified transient error. Manual rearm remains separate.
    pub(super) fn automatic_retry_candidate(&self, index: usize) -> Option<(&OperationId, usize)> {
        self.records.get(index)?.retry_automatically.get().then_some(())?;
        self.retry_candidate(index)
    }

    pub(super) fn rearm_matching(
        &self,
        index: usize,
        operation: &OperationId,
    ) -> Result<State, Error> {
        if self
            .retry_candidate(index)
            .is_none_or(|(current, _)| current != operation)
        {
            return Err(Error::RetryNotSafe);
        }
        self.rearm_before_effect(index)
    }

    /// Make a completed setup failure eligible for a fresh attempt only when
    /// that exact attempt returned before preparing a management effect.
    /// Interrupted work, successful outcomes and any possibly prepared effect
    /// remain fenced. The caller must arrange a bounded retry schedule, fresh
    /// transport, live authority and a new operation identity; login sessions
    /// from the earlier attempt may still exist. This method sends no I/O.
    pub fn rearm_before_effect(&self, index: usize) -> Result<State, Error> {
        let record = self.records.get(index).ok_or(Error::NotReady)?;
        if !matches!(record.state.get(), State::Finished { .. })
            || !record.retry_before_effect.get()
            || record.setup_live.get()
            || record.active.get()
            || record.waiting.get()
            || record.route_ready.get()
        {
            return Err(Error::RetryNotSafe);
        }
        if record.operation_count.get() == MAX_SETUP_ATTEMPTS {
            return Err(Error::AttemptCapacity);
        }
        let report = self.latest_report();
        let state = match report.select_mac_claim(record.enrollment.mac) {
            Ok(candidate) => State::Ready { candidate },
            Err(SelectionError::NotObserved) => State::NotObserved,
            Err(SelectionError::Conflicted) => State::Conflicted,
            Err(SelectionError::IncompleteReport) => return Err(Error::IncompleteReport),
            Err(SelectionError::InvalidMac) => return Err(Error::Configuration),
        };
        *record.report.borrow_mut() = report;
        record.state.set(state);
        record.retry_before_effect.set(false);
        record.retry_automatically.set(false);
        record.route_source.set(None);
        record.changed.notify_waiters();
        Ok(state)
    }
    /// Indexes of claims not matched to an inventory MAC, including claims
    /// without a usable MAC. These remain untrusted and are not setup targets.
    pub fn unknown_claims(&self) -> Rc<[usize]> {
        Rc::clone(&self.latest.borrow().unknown)
    }
    /// First ready inventory entry in caller-supplied order, if any.
    pub fn next_ready(&self) -> Option<usize> {
        self.records
            .iter()
            .position(|record| matches!(record.state.get(), State::Ready { .. }))
    }
    /// Select a ready camera by its preexisting certificate and credential
    /// handles, independently of inventory order. Shared handle pairs are
    /// ambiguous even if only one of their cameras is currently visible.
    /// Handles are claims; the transport and authority must still be checked.
    pub fn ready_for(
        &self,
        certificate: ContentDigest,
        credential: ContentDigest,
    ) -> Result<usize, Error> {
        let mut matches = self.records.iter().enumerate().filter(|(_, record)| {
            record.enrollment.certificate == certificate
                && record.enrollment.credential == credential
        });
        let (index, record) = matches.next().ok_or(Error::Binding)?;
        if matches.next().is_some() {
            return Err(Error::Binding);
        }
        if !matches!(record.state.get(), State::Ready { .. }) {
            return Err(Error::NotReady);
        }
        Ok(index)
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
                    State::InFlight { candidate } => record
                        .report
                        .borrow()
                        .cameras
                        .get(candidate)
                        .is_some_and(|camera| *camera.source().ip() == source),
                    State::Finished { .. } if record.route_ready.get() => {
                        record.route_source.get() == Some(source)
                    }
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
            .any(|record| record.operations().any(|old| old == operation))
        {
            return Err(Error::DuplicateOperation);
        }
        let record = self.records.get(index).ok_or(Error::NotReady)?;
        let State::Ready { candidate } = record.state.get() else {
            return Err(Error::NotReady);
        };
        record.reserve_operation(operation)?;
        record.retry_before_effect.set(false);
        record.retry_automatically.set(false);
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

    /// Select one ready camera using its unique supplied bindings, then run
    /// the existing listener-bound setup. No setup attempt is reserved when
    /// the bindings are missing, shared or not currently ready.
    #[allow(clippy::too_many_arguments)]
    pub async fn setup_available<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
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
    ) -> Result<(usize, setup::Outcome), Error> {
        let index = self.ready_for(certificate, credential_handle)?;
        let outcome = self
            .setup_one(
                index,
                owner,
                listener,
                expected_port,
                camera,
                certificate,
                credential_handle,
                credential,
                fence,
                destination,
                operation,
                framing,
                wait,
                trace,
            )
            .await?;
        Ok((index, outcome))
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
        let report = Rc::clone(&record.report.borrow());
        let cfg = setup::Config {
            report: &report,
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
        // Only this returned attempt can set the marker. Cancellation leaves
        // `InFlight`; a trace that entered preparation remains fenced even if
        // preparation subsequently failed or a permit was later dropped.
        let pre_effect_failure = result.is_err() && trace.operation().is_none();
        record.retry_before_effect.set(pre_effect_failure);
        record.retry_automatically.set(
            pre_effect_failure && result.as_ref().err().is_some_and(transient_setup_error),
        );
        let route_ready = match &result {
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
        } && result
            .as_ref()
            .is_ok_and(|outcome| trace.reported_video_matches(outcome));
        self.records[index].route_ready.set(route_ready);
        let latest = self.latest.borrow();
        self.records[index].route_source.set(if route_ready {
            source_claim(&latest.report, entry.mac)
        } else {
            None
        });
        drop(latest);
        self.records[index].changed.notify_waiters();
        result.map_err(Error::Setup)
    }
}

impl Fleet<'static> {
    /// Create a fleet by taking ownership of its first completed window. This
    /// lets a long-running owner release superseded windows once unreferenced.
    pub fn from_report(report: Report, inventory: &[Enrollment]) -> Result<Self, Error> {
        Self::build(report, inventory)
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
    fn automatic_retry_classifies_only_bounded_transient_setup_failures() {
        use crate::unifi_direct::camera_api;
        use std::io::ErrorKind;
        for error in [
            setup::Error::Deadline,
            setup::Error::Camera(camera_http::Error::Deadline),
            setup::Error::Camera(camera_http::Error::Io(ErrorKind::UnexpectedEof)),
            setup::Error::Camera(camera_http::Error::Io(ErrorKind::ConnectionReset)),
        ] {
            assert!(transient_setup_error(&error), "{error:?}");
        }
        for error in [
            setup::Error::Denied,
            setup::Error::VideoProfileUnavailable,
            setup::Error::Camera(camera_http::Error::Denied),
            setup::Error::Camera(camera_http::Error::Camera(camera_api::Error::HttpStatus)),
            setup::Error::Camera(camera_http::Error::Io(ErrorKind::Interrupted)),
            setup::Error::Camera(camera_http::Error::Protocol),
            setup::Error::Effect,
        ] {
            assert!(!transient_setup_error(&error), "{error:?}");
        }
    }

    #[test]
    fn enrollment_waiters_observe_append_and_ignore_refusals() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::task::Wake;
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
        let runtime_cx = Cx::current().unwrap();
        let observed = report(vec![candidate(10, Some(entry(1).mac))]);
        let fleet = Fleet::new(&observed, &[entry(1)]).unwrap();
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut context = Context::from_waker(&waker);
        let mut first = std::pin::pin!(fleet.wait_for_enrollment_after(&runtime_cx, 1));
        let mut second = std::pin::pin!(fleet.wait_for_enrollment_after(&runtime_cx, 1));
        let mut late = std::pin::pin!(fleet.wait_for_enrollment_after(&runtime_cx, 1));
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert!(second.as_mut().poll(&mut context).is_pending());
        assert_eq!(fleet.add_enrollment(entry(2)), Ok(1));
        assert_eq!(count.0.load(Ordering::Relaxed), 2);
        assert!(matches!(first.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
        assert!(matches!(late.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
        let mut refused = std::pin::pin!(fleet.wait_for_enrollment_after(&runtime_cx, 2));
        assert!(refused.as_mut().poll(&mut context).is_pending());
        assert_eq!(fleet.add_enrollment(entry(2)), Err(Error::Configuration));
        assert_eq!(count.0.load(Ordering::Relaxed), 2);
        assert!(refused.as_mut().poll(&mut context).is_pending());
        runtime_cx.set_cancel_requested(true);
        assert!(matches!(refused.as_mut().poll(&mut context), Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted));
        runtime_cx.set_cancel_requested(false);
        });
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
        assert_eq!(fleet.unknown_claims().as_ref(), &[3, 4]);
        assert!(!format!("{first:?}").contains("10.1.2"));
    }

    #[test]
    fn setup_selection_matches_unique_bindings_and_refuses_unavailable_or_shared() {
        let first = entry(1);
        let second = entry(2);
        let missing = entry(3);
        let observed = report(vec![
            candidate(10, Some(first.mac)),
            candidate(11, Some(second.mac)),
        ]);
        let fleet = Fleet::new(&observed, &[first, second, missing]).unwrap();
        assert_eq!(fleet.next_ready(), Some(0));
        assert_eq!(
            fleet.ready_for(second.certificate, second.credential),
            Ok(1)
        );
        assert_eq!(
            fleet.ready_for(missing.certificate, missing.credential),
            Err(Error::NotReady)
        );
        assert_eq!(
            fleet.ready_for(first.certificate, second.credential),
            Err(Error::Binding)
        );
        let shared = Enrollment::new(
            missing.mac,
            missing.camera,
            missing.peer_admission,
            first.certificate,
            first.credential,
            missing.generation,
        )
        .unwrap();
        let ambiguous = Fleet::new(&observed, &[first, second, shared]).unwrap();
        assert_eq!(
            ambiguous.ready_for(first.certificate, first.credential),
            Err(Error::Binding)
        );
        assert_eq!(ambiguous.state(0), Some(State::Ready { candidate: 0 }));
        assert!(ambiguous.operation(0).is_none());
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
    fn enrollment_preserves_live_setup_and_prior_snapshot() {
        let first = entry(1);
        let second = entry(2);
        let input = report(vec![
            candidate(10, Some(first.mac)),
            candidate(11, Some(second.mac)),
        ]);
        let fleet = Fleet::new(&input, &[first]).unwrap();
        let snapshot = fleet.latest_snapshot();
        assert_eq!(snapshot.unknown_claims(), &[1]);
        let operation = OperationId::parse("operation:existing-camera").unwrap();
        let mut work = Box::pin(fleet.drive(0, &operation, std::future::pending::<()>()));
        let mut context = Context::from_waker(Waker::noop());
        assert!(work.as_mut().poll(&mut context).is_pending());
        let existing = &fleet.records[0] as *const Record;

        assert_eq!(fleet.add_enrollment(second), Ok(1));
        assert_eq!(&fleet.records[0] as *const Record, existing);
        assert_eq!(fleet.operation(0), Some(&operation));
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 1 }));
        assert_eq!(snapshot.unknown_claims(), &[1]);
        assert!(fleet.latest_snapshot().unknown_claims().is_empty());
        assert_eq!(fleet.add_enrollment(second), Err(Error::Configuration));
        assert!(work.as_mut().poll(&mut context).is_pending());
        drop(work);
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.operation(0), Some(&operation));
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 1 }));
    }

    #[test]
    fn live_enrollment_capacity_refuses_without_changing_the_snapshot() {
        let fleet = Fleet::from_report(report(vec![]), &[]).unwrap();
        for n in 1..=MAX_INVENTORY as u8 {
            assert_eq!(fleet.add_enrollment(entry(n)), Ok(usize::from(n - 1)));
        }
        let snapshot = fleet.latest_snapshot();
        assert_eq!(fleet.add_enrollment(entry(129)), Err(Error::Configuration));
        assert_eq!(fleet.len(), MAX_INVENTORY);
        assert!(Rc::ptr_eq(&snapshot, &fleet.latest_snapshot()));
        assert_eq!(fleet.enrollment(0), Some(entry(1)));
        assert_eq!(fleet.enrollment(MAX_INVENTORY - 1), Some(entry(128)));
    }

    #[test]
    fn pre_effect_rearm_uses_latest_claim_and_retains_bounded_operation_history() {
        let one = entry(1);
        let fleet = Fleet::from_report(report(vec![candidate(10, Some(one.mac))]), &[one]).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let first = OperationId::parse("operation:pre-effect-first").unwrap();
        let mut attempt = Box::pin(fleet.drive(0, &first, std::future::ready(())));
        assert!(matches!(
            attempt.as_mut().poll(&mut context),
            Poll::Ready(Ok(()))
        ));
        drop(attempt);
        // Synthetic stand-in for the proof set only by a returned pre-effect
        // setup error; the integration fixture tests that boundary itself.
        fleet.records[0].retry_before_effect.set(true);
        assert!(fleet.automatic_retry_candidate(0).is_none());
        fleet.records[0].retry_automatically.set(true);
        assert_eq!(fleet.automatic_retry_candidate(0).map(|(op, _)| op), Some(&first));
        fleet.refresh(report(vec![])).unwrap();
        assert_eq!(fleet.rearm_before_effect(0), Ok(State::NotObserved));
        assert!(fleet.automatic_retry_candidate(0).is_none());
        assert_eq!(fleet.operation(0), Some(&first));
        fleet
            .refresh(report(vec![candidate(11, Some(one.mac))]))
            .unwrap();
        assert_eq!(fleet.state(0), Some(State::Ready { candidate: 0 }));
        let mut duplicate = Box::pin(fleet.drive(0, &first, std::future::ready(())));
        assert!(matches!(
            duplicate.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::DuplicateOperation))
        ));
        drop(duplicate);

        for n in 1..MAX_SETUP_ATTEMPTS {
            let operation = OperationId::parse(format!("operation:pre-effect-{n}")).unwrap();
            let mut attempt = Box::pin(fleet.drive(0, &operation, std::future::ready(())));
            assert!(matches!(
                attempt.as_mut().poll(&mut context),
                Poll::Ready(Ok(()))
            ));
            drop(attempt);
            fleet.records[0].retry_before_effect.set(true);
            assert_eq!(fleet.rearm_matching(0, &first), Err(Error::RetryNotSafe));
            assert_eq!(fleet.operation(0), Some(&operation));
            if n + 1 == MAX_SETUP_ATTEMPTS {
                assert_eq!(fleet.rearm_before_effect(0), Err(Error::AttemptCapacity));
            } else {
                assert_eq!(
                    fleet.rearm_before_effect(0),
                    Ok(State::Ready { candidate: 0 })
                );
            }
        }
        assert_eq!(fleet.records[0].operations().count(), MAX_SETUP_ATTEMPTS);
        assert!(fleet.records[0].operations().any(|old| old == &first));
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

    #[test]
    fn refresh_discovers_later_camera_without_reopening_interrupted_attempt() {
        let first = entry(1);
        let second = entry(2);
        let fleet = Fleet::from_report(
            report(vec![candidate(10, Some(first.mac))]),
            &[first, second],
        )
        .unwrap();
        let old_report = Rc::downgrade(&fleet.records[0].report.borrow());
        let first_op = OperationId::parse("operation:refresh-first").unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut work = Box::pin(fleet.drive(0, &first_op, std::future::pending::<()>()));
        assert!(matches!(work.as_mut().poll(&mut context), Poll::Pending));
        let earlier = fleet.latest_snapshot();
        fleet
            .refresh(report(vec![
                candidate(30, Some(entry(3).mac)),
                candidate(20, Some(second.mac)),
                candidate(11, Some(first.mac)),
            ]))
            .unwrap();
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.operation(0), Some(&first_op));
        assert_eq!(
            fleet.records[0].report.borrow().cameras[0].source().ip(),
            &Ipv4Addr::new(192, 168, 7, 10)
        );
        assert!(old_report.upgrade().is_some());
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 1 }));
        assert_eq!(fleet.unknown_claims().as_ref(), &[0]);
        assert_eq!(fleet.latest_report().cameras[1].mac(), Some(second.mac));
        assert!(earlier.unknown_claims().is_empty());
        assert_eq!(earlier.report().cameras[0].mac(), Some(first.mac));
        let mut reused = Box::pin(fleet.drive(1, &first_op, std::future::ready(())));
        assert!(matches!(
            reused.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::DuplicateOperation))
        ));
        drop(reused);
        drop(work);

        let before = fleet.latest_snapshot();
        let mut incomplete = report(vec![candidate(22, Some(second.mac))]);
        incomplete.stop = Stop::PacketLimit;
        let refusal = fleet.refresh(incomplete).unwrap_err();
        assert_eq!(refusal.reason, Error::IncompleteReport);
        assert_eq!(refusal.report.stop, Stop::PacketLimit);
        assert_eq!(
            refusal.report.cameras[0].source().ip(),
            &Ipv4Addr::new(192, 168, 7, 22)
        );
        assert!(Rc::ptr_eq(&before, &fleet.latest_snapshot()));
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 1 }));
        assert_eq!(fleet.unknown_claims().as_ref(), &[0]);

        fleet
            .refresh(report(vec![
                candidate(20, Some(second.mac)),
                candidate(21, Some(second.mac)),
            ]))
            .unwrap();
        assert_eq!(fleet.state(1), Some(State::Conflicted));
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        fleet
            .refresh(report(vec![candidate(22, Some(second.mac))]))
            .unwrap();
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 0 }));
        assert_eq!(
            fleet.records[0].report.borrow().cameras[0].source().ip(),
            &Ipv4Addr::new(192, 168, 7, 10)
        );
    }

    #[test]
    fn refresh_releases_superseded_unattempted_window() {
        let one = entry(1);
        let fleet = Fleet::from_report(report(vec![candidate(10, Some(one.mac))]), &[one]).unwrap();
        let old = Rc::downgrade(&fleet.latest.borrow().report);
        fleet
            .refresh(report(vec![candidate(11, Some(one.mac))]))
            .unwrap();
        assert!(old.upgrade().is_none());
        assert_eq!(fleet.state(0), Some(State::Ready { candidate: 0 }));
        assert_eq!(
            fleet.latest_report().cameras[0].source().ip(),
            &Ipv4Addr::new(192, 168, 7, 11)
        );
    }

    #[test]
    fn finished_route_follows_unconflicted_windows_without_rewriting_setup() {
        let one = entry(1);
        let fleet = Fleet::from_report(report(vec![candidate(10, Some(one.mac))]), &[one]).unwrap();
        let operation = OperationId::parse("operation:route-refresh").unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut setup = Box::pin(fleet.drive(0, &operation, std::future::ready(())));
        assert!(matches!(
            setup.as_mut().poll(&mut context),
            Poll::Ready(Ok(()))
        ));
        drop(setup);
        let record = &fleet.records[0];
        record.route_ready.set(true);
        record
            .route_source
            .set(source_claim(&record.report.borrow(), one.mac));
        let initial = Rc::clone(&record.report.borrow());

        fleet
            .refresh(report(vec![candidate(11, Some(one.mac))]))
            .unwrap();
        assert_eq!(
            record.route_source.get(),
            Some(Ipv4Addr::new(192, 168, 7, 11))
        );
        assert_eq!(fleet.state(0), Some(State::Finished { candidate: 0 }));
        assert_eq!(fleet.operation(0), Some(&operation));
        assert!(Rc::ptr_eq(&initial, &record.report.borrow()));

        let mut partial = report(vec![candidate(12, Some(one.mac))]);
        partial.stop = Stop::PacketLimit;
        assert_eq!(
            fleet.refresh(partial).unwrap_err().reason,
            Error::IncompleteReport
        );
        assert_eq!(
            record.route_source.get(),
            Some(Ipv4Addr::new(192, 168, 7, 11))
        );

        fleet.refresh(report(vec![])).unwrap();
        assert_eq!(record.route_source.get(), None);
        assert!(fleet.route_ready(0));
        fleet
            .refresh(report(vec![
                candidate(12, Some(one.mac)),
                candidate(13, Some(one.mac)),
            ]))
            .unwrap();
        assert_eq!(record.route_source.get(), None);
        fleet
            .refresh(report(vec![candidate(14, Some(one.mac))]))
            .unwrap();
        assert_eq!(
            record.route_source.get(),
            Some(Ipv4Addr::new(192, 168, 7, 14))
        );
        assert!(Rc::ptr_eq(&initial, &record.report.borrow()));
        assert_eq!(fleet.operation(0), Some(&operation));
    }

    #[test]
    fn add_enrollment_preserves_attempts_and_matches_latest_window() {
        let first = entry(1);
        let second = entry(2);
        let fleet = Fleet::from_report(
            report(vec![
                candidate(10, Some(first.mac)),
                candidate(20, Some(second.mac)),
                candidate(30, None),
            ]),
            &[first],
        )
        .unwrap();
        let operation = OperationId::parse("operation:dynamic-first").unwrap();
        let mut context = Context::from_waker(Waker::noop());
        {
            let mut work = Box::pin(fleet.drive(0, &operation, std::future::pending::<()>()));
            assert!(matches!(work.as_mut().poll(&mut context), Poll::Pending));
        }
        assert_eq!(fleet.unknown_claims().as_ref(), &[1, 2]);
        assert_eq!(fleet.add_enrollment(second), Ok(1));
        assert_eq!(fleet.state(0), Some(State::InFlight { candidate: 0 }));
        assert_eq!(fleet.operation(0), Some(&operation));
        assert_eq!(fleet.state(1), Some(State::Ready { candidate: 1 }));
        assert_eq!(fleet.unknown_claims().as_ref(), &[2]);
        assert_eq!(fleet.add_enrollment(second), Err(Error::Configuration));
        let mut duplicate_camera = entry(3);
        duplicate_camera.camera = first.camera;
        assert_eq!(
            fleet.add_enrollment(duplicate_camera),
            Err(Error::Configuration)
        );
        assert_eq!(fleet.len(), 2);
        assert_eq!(fleet.unknown_claims().as_ref(), &[2]);
    }
}
