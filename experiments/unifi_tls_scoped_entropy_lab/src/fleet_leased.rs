#![forbid(unsafe_code)]
//! Experimental fleet TLS transport using caller-owned pre-acquired leases.
use crate::owned::{
    Session, admitted,
    offload::{Acquisition, Lease},
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::BudgetVector;
use fss_reference::unifi_direct::{
    VideoChannel, camera_api::VideoProfile,
    controller_acceptor::{self, Acceptor, Transport},
    controller_listener::Routed,
    discovery::{
        fleet::{Enrollment, Fleet, State},
        pump::{self, CameraWork, CameraWorkSet, Driver, Progress, Pump, RetryDisposition, WorkRefusal},
        retry,
    },
    metered::MeteredClock,
    owner::PeerAdmission,
};
use fss_runtime::{
    effect::{EffectCoordinator, EffectCoordinatorBinding, EffectSettlementRefusal},
    execution::TaskCx,
};
use rustls::ServerConfig;
use std::{
    cell::{Cell, OnceCell, RefCell},
    future::{Future, poll_fn},
    io,
    pin::{Pin, pin},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};

const MAX_RESOURCES: usize = 128;

/// Stable, bounded resource names for an explicitly supplied fleet inventory.
/// A discovery claim by itself does not populate these slots or authorize setup.
pub struct FleetResources {
    names: Vec<OnceCell<String>>,
    len: Cell<usize>,
    attached: Cell<bool>,
}
impl FleetResources {
    /// Reserve stable slots before starting any transport or handshake.
    pub fn new(initial: &[String]) -> io::Result<Self> {
        if initial.len() > MAX_RESOURCES
            || initial
                .iter()
                .any(|name| name.is_empty() || name.len() > 1024)
            || initial
                .iter()
                .enumerate()
                .any(|(index, name)| initial[..index].contains(name))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut names = Vec::new();
        names
            .try_reserve_exact(MAX_RESOURCES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        names.resize_with(MAX_RESOURCES, OnceCell::new);
        for (index, name) in initial.iter().enumerate() {
            names[index]
                .set(name.clone())
                .map_err(|_| io::ErrorKind::InvalidInput)?;
        }
        Ok(Self {
            names,
            len: Cell::new(initial.len()),
            attached: Cell::new(false),
        })
    }
    /// Number of resource names published so far.
    pub fn len(&self) -> usize {
        self.len.get()
    }
    /// Whether no resource names have been published.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn get(&self, index: usize) -> Option<&str> {
        if index < self.len() {
            self.names[index].get().map(String::as_str)
        } else {
            None
        }
    }
    fn position(&self, name: &str) -> Option<usize> {
        (0..self.len()).find(|&index| self.get(index) == Some(name))
    }
}

struct ResourceBinding<'scope>(&'scope FleetResources);
impl Drop for ResourceBinding<'_> {
    fn drop(&mut self) {
        self.0.attached.set(false);
    }
}

struct Slots<'scope, 'task> {
    leases: Vec<Option<Lease<'scope, 'task>>>,
    waiter: Option<Waker>,
    handshake_waiters: Vec<Option<Registration>>,
}

struct Registration {
    token: Rc<()>,
    waker: Waker,
}

/// One bounded registration owned by one routed handshake.
struct WaitSlot<'scope, 'task> {
    slots: Rc<RefCell<Slots<'scope, 'task>>>,
    index: usize,
    token: Rc<()>,
}
impl<'scope, 'task> WaitSlot<'scope, 'task> {
    fn poll_lease(
        &self,
        cx: &mut Context<'_>,
        valid: impl FnOnce(&Lease<'scope, 'task>) -> bool,
    ) -> Poll<io::Result<Lease<'scope, 'task>>> {
        let waker = cx.waker().clone();
        let Ok(mut slots) = self.slots.try_borrow_mut() else {
            return Poll::Ready(Err(io::ErrorKind::WouldBlock.into()));
        };
        if let Some(existing) = &slots.handshake_waiters[self.index] {
            if !Rc::ptr_eq(&existing.token, &self.token) && Rc::strong_count(&existing.token) > 1 {
                return Poll::Ready(Err(io::ErrorKind::WouldBlock.into()));
            }
        }
        if let Some(lease) = slots.leases[self.index].as_ref() {
            if !valid(lease) {
                return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
            }
            let lease = slots.leases[self.index].take().expect("lease was present");
            let previous = slots.handshake_waiters[self.index].take();
            let supply = slots.waiter.take();
            drop(slots);
            drop(previous);
            if let Some(supply) = supply {
                supply.wake();
            }
            return Poll::Ready(Ok(lease));
        }
        let previous = slots.handshake_waiters[self.index].replace(Registration {
            token: self.token.clone(),
            waker,
        });
        drop(slots);
        drop(previous);
        Poll::Pending
    }
}
impl Drop for WaitSlot<'_, '_> {
    fn drop(&mut self) {
        let previous = self.slots.try_borrow_mut().ok().and_then(|mut slots| {
            if slots.handshake_waiters[self.index]
                .as_ref()
                .is_some_and(|entry| Rc::ptr_eq(&entry.token, &self.token))
            {
                slots.handshake_waiters[self.index].take()
            } else {
                None
            }
        });
        drop(previous);
    }
}

/// Finite one-shot leases, supplied and replenished by the caller.
/// No worker is started or detached by this transport.
#[derive(Clone)]
pub struct FleetLeased<'scope, 'task> {
    config: Arc<ServerConfig>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resources: &'scope FleetResources,
    _binding: Rc<ResourceBinding<'scope>>,
    identity: Rc<()>,
    slots: Rc<RefCell<Slots<'scope, 'task>>>,
    supply_claim: Rc<Cell<bool>>,
}
impl<'scope, 'task> FleetLeased<'scope, 'task> {
    /// Create empty slots for the caller's authorized resource inventory.
    pub fn new(
        config: ServerConfig,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resources: &'scope FleetResources,
    ) -> io::Result<Self> {
        if config.scoped_random.is_some()
            || config.scoped_kx.is_some()
            || config.send_tls13_tickets != 0
            || !clock.matches(task, cx)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(MAX_RESOURCES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        slots.resize_with(MAX_RESOURCES, || None);
        let mut handshake_waiters = Vec::new();
        handshake_waiters
            .try_reserve_exact(MAX_RESOURCES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        handshake_waiters.resize_with(MAX_RESOURCES, || None);
        if resources.attached.replace(true) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(Self {
            config: Arc::new(config),
            task,
            cx,
            clock,
            resources,
            _binding: Rc::new(ResourceBinding(resources)),
            identity: Rc::new(()),
            slots: Rc::new(RefCell::new(Slots {
                leases: slots,
                waiter: None,
                handshake_waiters,
            })),
            supply_claim: Rc::new(Cell::new(false)),
        })
    }
    /// Append resource names for previously enrolled cameras without moving
    /// existing slots. Refuses a mismatched prefix before publishing anything.
    /// This does not authenticate discovery claims or initiate camera setup.
    pub fn synchronize_fleet(&self, fleet: &Fleet<'_>) -> io::Result<usize> {
        let current = self.resources.len();
        let target = fleet.len();
        if target < current || target > MAX_RESOURCES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(target - current)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for index in 0..target {
            let camera = fleet
                .enrollment(index)
                .ok_or(io::ErrorKind::InvalidInput)?
                .camera();
            let name = format!("camera:{}", camera.to_text());
            if index < current {
                if self.resources.get(index) != Some(name.as_str()) {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
            } else {
                staged.push(name);
            }
        }
        if staged.is_empty() {
            return Ok(0);
        }
        if self.resources.names[current..target]
            .iter()
            .any(|slot| slot.get().is_some())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let Ok(mut slots) = self.slots.try_borrow_mut() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        for (offset, name) in staged.into_iter().enumerate() {
            self.resources.names[current + offset]
                .set(name)
                .expect("prechecked empty slot");
        }
        self.resources.len.set(target);
        let wake = slots.waiter.take();
        drop(slots);
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(target - current)
    }
    /// Install one matching lease without replacing an existing owner.
    /// A rejected lease is returned to its caller for explicit disposition.
    pub fn install(&self, lease: Lease<'scope, 'task>) -> Result<(), Lease<'scope, 'task>> {
        let Some(index) = self.resources.position(lease.resource()) else {
            return Err(lease);
        };
        if !lease.matches(
            self.task,
            self.cx,
            &self.clock,
            self.resources.get(index).expect("published resource"),
        ) {
            return Err(lease);
        }
        let Ok(mut slots) = self.slots.try_borrow_mut() else {
            return Err(lease);
        };
        if slots.leases[index].is_some() {
            return Err(lease);
        }
        slots.leases[index] = Some(lease);
        let wake = slots.waiter.take();
        let handshake = slots.handshake_waiters[index].take();
        drop(slots);
        if let Some(wake) = wake {
            wake.wake();
        }
        if let Some(handshake) = handshake {
            handshake.waker.wake();
        }
        Ok(())
    }
}
impl<'scope, 'task, 'policy> Transport<'scope, 'task, 'policy> for FleetLeased<'scope, 'task>
where
    'task: 'scope,
    'policy: 'scope,
{
    type Stream = Session<'scope, 'task, Routed<'scope, 'task, 'policy>>;
    type Handshake = Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + 'scope>>;
    fn handshake(&self, cx: &'scope Cx, route: Routed<'scope, 'task, 'policy>) -> Self::Handshake {
        let selected = if !std::ptr::eq(self.cx, cx)
            || !route.matches_context(cx)
            || !self.clock.same_mapping(&route.clock())
        {
            Err(io::ErrorKind::PermissionDenied)
        } else if let Some(index) = self.resources.position(route.resource()) {
            Ok(index)
        } else {
            Err(io::ErrorKind::PermissionDenied)
        };
        let transport = self.clone();
        Box::pin(async move {
            let index = selected.map_err(io::Error::from)?;
            let registration = WaitSlot {
                slots: transport.slots.clone(),
                index,
                token: Rc::new(()),
            };
            let lease = poll_fn(|context| {
                if let Err(error) = admitted(
                    transport.task,
                    cx,
                    transport.clock,
                    route.resource(),
                    &BudgetVector::ZERO,
                )
                .and_then(|_| route.gate().check())
                {
                    return Poll::Ready(Err(error));
                }
                registration.poll_lease(context, |lease| {
                    lease.matches(transport.task, cx, &transport.clock, route.resource())
                })
            })
            .await?;
            drop(registration);
            Session::accept_with_lease((*transport.config).clone(), route, lease).await
        })
    }
}

/// Observable progress from the bounded lease replenishment owner.
#[must_use]
pub enum SupplyEvent<'scope, 'task> {
    /// One per-resource worker was admitted.
    Started(usize),
    /// A completed lease was installed for the resource index.
    Installed(usize),
    /// A worker failed; caller must explicitly rearm this resource.
    Failed { index: usize, kind: io::ErrorKind },
    /// A reentrant local slot borrow prevented this poll; the owner may retry later.
    Busy,
    /// Another caller filled the slot first; ownership returns to the caller.
    Rejected {
        index: usize,
        lease: Lease<'scope, 'task>,
    },
    /// A cancelled worker reached actual release during shutdown.
    Drained(usize),
    /// No acquisition worker remains; the owner may now be dropped.
    Stopped,
}

/// One fleet event or one completed caller-owned camera operation.
#[must_use = "handle the fleet event or retain the camera operation outcome"]
pub enum Supervised<'scope, 'task, E, W> {
    /// Discovery, routing, or TLS lease supply progress.
    Fleet(Progress<E, Option<SupplyEvent<'scope, 'task>>>),
    /// An exact camera operation completed and is returned to the caller.
    Camera { index: usize, output: W },
}

/// Why an explicit setup rearm was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RearmRefusal {
    /// No enrollment exists at this index.
    UnknownEnrollment,
    /// No prior setup admission or factory attempt exists at this index.
    NotAttempted,
    /// A previously admitted future is still retained by this owner.
    InFlight,
    /// The fleet has not made this enrollment ready for a new attempt.
    NotReady,
    /// Shutdown has stopped further admissions.
    Stopped,
}

/// Why a camera plan could not be attached to this automatic setup owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanRegistrationRefusal {
    /// Factory and automatic owner do not reference the same fleet.
    FleetMismatch,
    /// Shutdown has stopped further admission.
    Stopped,
    /// An operation is still retained by the setup owner.
    InFlight,
    /// A prior attempt may need reconciliation or came from another factory.
    NeedsReconciliation,
    /// A prior missing-plan selection is no longer ready for setup.
    NotReady,
}

#[derive(Debug)]
pub(crate) struct MissingPlan {
    identity: Arc<()>,
    index: usize,
}
impl std::fmt::Display for MissingPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no owner-supplied camera plan")
    }
}
impl std::error::Error for MissingPlan {}

pub(crate) fn missing_plan(identity: Arc<()>, index: usize) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, MissingPlan { identity, index })
}

/// Bounded, caller-owned camera work and per-enrollment admission latches.
/// A completed or refused attempt is not silently retried in this owner. The
/// caller may explicitly rearm after reconciling any possible external effects.
#[must_use = "retire pending camera work and reconcile its effect traces"]
pub struct AutomaticWork<'fleet, 'report, 'work, W> {
    fleet: &'fleet Fleet<'report>,
    work: CameraWorkSet<'work, W>,
    attempted: [bool; MAX_RESOURCES],
    in_flight: [bool; MAX_RESOURCES],
    missing_factory: [Option<Arc<()>>; MAX_RESOURCES],
    transport: Option<Rc<()>>,
    capacity: usize,
    cursor: usize,
    stopped: bool,
}
impl<'fleet, 'report, 'work, W> AutomaticWork<'fleet, 'report, 'work, W> {
    /// Bind to one fleet and preallocate a finite number of in-flight works.
    pub fn new(fleet: &'fleet Fleet<'report>, capacity: usize) -> Result<Self, WorkRefusal> {
        Ok(Self {
            fleet,
            work: CameraWorkSet::new(capacity)?,
            attempted: [false; MAX_RESOURCES],
            in_flight: [false; MAX_RESOURCES],
            missing_factory: std::array::from_fn(|_| None),
            transport: None,
            capacity,
            cursor: 0,
            stopped: false,
        })
    }
    /// Stop admitting new work; already admitted work remains owned.
    pub fn request_stop(&mut self) {
        self.stopped = true;
    }
    /// Number of camera operations still retained.
    pub fn pending_len(&self) -> usize {
        self.work.len()
    }
    /// Reset only this owner's selection latch for an attempted enrollment.
    /// The fleet must already be ready: a completed fleet operation requires
    /// its own safe rearm first. The caller must reconcile any possible effect
    /// and authorize a new operation. This method cannot verify reconciliation,
    /// grant authority, or coordinate separate work owners. It refuses an
    /// in-flight operation and never resumes a stopped owner.
    pub fn rearm(&mut self, index: usize) -> Result<(), RearmRefusal> {
        if index >= MAX_RESOURCES || self.fleet.enrollment(index).is_none() {
            return Err(RearmRefusal::UnknownEnrollment);
        }
        if self.stopped {
            return Err(RearmRefusal::Stopped);
        }
        if self.in_flight[index] {
            return Err(RearmRefusal::InFlight);
        }
        if !self.attempted[index] {
            return Err(RearmRefusal::NotAttempted);
        }
        if !matches!(self.fleet.state(index), Some(State::Ready { .. })) {
            return Err(RearmRefusal::NotReady);
        }
        self.attempted[index] = false;
        self.missing_factory[index] = None;
        Ok(())
    }
    /// Validate registration without altering the selection latch.
    pub(crate) fn check_plan_registration(
        &self,
        fleet: &Fleet<'_>,
        index: usize,
        identity: &Arc<()>,
    ) -> Result<bool, PlanRegistrationRefusal> {
        if !std::ptr::eq(self.fleet, fleet) || index >= MAX_RESOURCES {
            return Err(PlanRegistrationRefusal::FleetMismatch);
        }
        if self.stopped {
            return Err(PlanRegistrationRefusal::Stopped);
        }
        if self.in_flight[index] {
            return Err(PlanRegistrationRefusal::InFlight);
        }
        if !self.attempted[index] {
            return Ok(false);
        }
        if !self.missing_factory[index]
            .as_ref()
            .is_some_and(|saved| Arc::ptr_eq(saved, identity))
        {
            return Err(PlanRegistrationRefusal::NeedsReconciliation);
        }
        if !matches!(self.fleet.state(index), Some(State::Ready { .. })) {
            return Err(PlanRegistrationRefusal::NotReady);
        }
        Ok(true)
    }
    /// Commit a previously validated synchronous registration.
    pub(crate) fn commit_plan_registration(&mut self, index: usize, rearm: bool) {
        if rearm {
            self.attempted[index] = false;
            self.missing_factory[index] = None;
        }
    }
    /// Return every outstanding future for explicit cancellation or retirement.
    pub fn into_pending(self) -> Vec<(usize, CameraWork<'work, W>)> {
        self.work.into_pending()
    }
}

/// Refusal to retain a stream future for this fleet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRefusal {
    /// No enrollment exists at the supplied index.
    UnknownEnrollment,
    /// A prior automatic stream for this enrollment still needs disposition.
    PreviousUnresolved,
    /// The underlying bounded work set refused the exact future.
    Work(WorkRefusal),
}

/// Why a routed session could not be admitted to its stream owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedStreamRefusal {
    /// The setup and stream owners do not share the same fleet.
    FleetMismatch,
    /// No enrollment exists at this index.
    UnknownEnrollment,
    /// The session's untrusted MAC claim differs from the enrollment.
    ClaimMismatch,
    /// Setup has not released the route or remains in flight.
    SetupNotReady,
    /// Setup admission has been stopped for shutdown.
    Stopped,
    /// The session has already progressed beyond the startup boundary.
    SessionNotFresh,
    /// This enrollment already has a stream.
    Duplicate,
    /// The previous automatically admitted stream still needs disposition.
    PreviousUnresolved,
    /// This owner's bounded generation counter is exhausted.
    GenerationExhausted,
    /// The bounded stream work set is full.
    Capacity,
    /// The work set refused a freshly constructed future.
    Work(WorkRefusal),
}

/// A refusal preserves the exact session or the newly created future.
#[must_use = "retain or explicitly retire the refused session or future"]
pub enum RoutedStreamAdmission<'scope, 'task, 'policy, 'work, IO, S> {
    /// The factory was not called; the caller retains the session.
    Session {
        /// Why the unconsumed session was refused.
        reason: RoutedStreamRefusal,
        /// The original upgraded session.
        session:
            fss_reference::unifi_direct::controller_acceptor::Session<'scope, 'task, 'policy, IO>,
    },
    /// The factory was called, but the exact resulting future was refused.
    Work {
        /// Why the future was refused.
        reason: RoutedStreamRefusal,
        /// The unpolled future and its owned session.
        work: CameraWork<'work, S>,
        /// Binding supplied with that work, retained for reconciliation.
        effects: EffectCoordinatorBinding,
    },
}

/// Owner-bound identity of one completed automatically admitted stream.
/// This is a reconciliation handle, not proof that effects are settled.
#[derive(Clone, Debug)]
#[must_use = "retain this completion until its effects are reconciled"]
pub struct StreamCompletion {
    owner: Rc<()>,
    index: usize,
    generation: u64,
}
impl StreamCompletion {
    /// Enrollment associated with this exact completed stream.
    pub fn index(&self) -> usize { self.index }
    /// Monotone generation within this particular stream owner.
    pub fn generation(&self) -> u64 { self.generation }
}

/// Why a completed stream's admission fence was not released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamCompletionRefusal {
    /// The completion belongs to a different owner.
    WrongOwner,
    /// The completion was already released or is no longer current.
    Stale,
    /// The supplied coordinator does not match the stream's original binding.
    WrongCoordinator,
    /// The coordinator's persisted state requires cold recovery.
    PersistencePoisoned,
    /// At least one retained operation has not reached a safe terminal state.
    UnsettledEffects,
}

/// An unpolled stream future bound to its effect coordinator. The factory
/// must send every stream effect through that exact coordinator; the binding
/// cannot enforce that contract or establish independent custody.
pub struct TrackedStreamWork<'work, S> {
    /// Future that owns the routed session and stream work.
    pub work: CameraWork<'work, S>,
    /// Identity of the effect coordinator used by the future.
    pub effects: EffectCoordinatorBinding,
}

impl<'work, S: 'work> TrackedStreamWork<'work, (S, EffectCoordinator)> {
    /// Retain an effect coordinator in the unpolled stream future and return
    /// it with the output. The closure is first invoked when work is polled.
    /// It must return the same coordinator and route its effects through it;
    /// the release check refuses a different returned coordinator. Dropping
    /// the work can still discard this process-local owner and is not recovery.
    pub fn with_owned_effects<F, Fut>(effects: EffectCoordinator, make: F) -> Self
    where
        F: FnOnce(EffectCoordinator) -> Fut + 'work,
        Fut: Future<Output = (S, EffectCoordinator)> + 'work,
    {
        let binding = effects.binding();
        Self {
            work: Box::pin(async move { make(effects).await }),
            effects: binding,
        }
    }
}

/// Fleet-bound stream futures with an explicit occupied-index inventory.
/// The caller still binds each future's session, authority and effect trace.
#[must_use = "retire pending stream work and reconcile its effect traces"]
pub struct ActiveStreams<'fleet, 'report, 'work, S> {
    fleet: &'fleet Fleet<'report>,
    work: CameraWorkSet<'work, S>,
    occupied: [bool; MAX_RESOURCES],
    capacity: usize,
    identity: Rc<()>,
    sequence: [u64; MAX_RESOURCES],
    running_automatic: [Option<u64>; MAX_RESOURCES],
    awaiting_disposition: [Option<u64>; MAX_RESOURCES],
    running_effects: [Option<EffectCoordinatorBinding>; MAX_RESOURCES],
    awaiting_effects: [Option<EffectCoordinatorBinding>; MAX_RESOURCES],
    emitted_completion: Option<StreamCompletion>,
}
impl<'fleet, 'report, 'work, S> ActiveStreams<'fleet, 'report, 'work, S> {
    /// Bind to the fleet and reserve finite work capacity.
    pub fn new(fleet: &'fleet Fleet<'report>, capacity: usize) -> Result<Self, WorkRefusal> {
        Ok(Self {
            fleet,
            work: CameraWorkSet::new(capacity)?,
            occupied: [false; MAX_RESOURCES],
            capacity,
            identity: Rc::new(()),
            sequence: [0; MAX_RESOURCES],
            running_automatic: [None; MAX_RESOURCES],
            awaiting_disposition: [None; MAX_RESOURCES],
            running_effects: std::array::from_fn(|_| None),
            awaiting_effects: std::array::from_fn(|_| None),
            emitted_completion: None,
        })
    }
    /// Retain a stream future or return it unchanged on refusal.
    pub fn insert(
        &mut self,
        index: usize,
        work: CameraWork<'work, S>,
    ) -> Result<(), (StreamRefusal, CameraWork<'work, S>)> {
        if index >= MAX_RESOURCES || self.fleet.enrollment(index).is_none() {
            return Err((StreamRefusal::UnknownEnrollment, work));
        }
        if self.awaiting_disposition[index].is_some() {
            return Err((StreamRefusal::PreviousUnresolved, work));
        }
        match self.work.insert(index, work) {
            Ok(()) => {
                self.occupied[index] = true;
                Ok(())
            }
            Err((reason, work)) => Err((StreamRefusal::Work(reason), work)),
        }
    }
    /// Bind one accepted session to a bounded stream factory after setup.
    /// The caller must pass the exact index and session from one acceptor
    /// event. MAC and route claims are not physical identity or authority;
    /// the factory must separately bind session, effects and admission. The
    /// factory constructs a future and must not perform camera I/O itself.
    pub fn admit_routed_session<'scope, 'task, 'policy, IO, W, F>(
        &mut self,
        automatic: &AutomaticWork<'fleet, 'report, '_, W>,
        index: usize,
        session:
            fss_reference::unifi_direct::controller_acceptor::Session<'scope, 'task, 'policy, IO>,
        factory: F,
    ) -> Result<(), RoutedStreamAdmission<'scope, 'task, 'policy, 'work, IO, S>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(
            Enrollment,
            fss_reference::unifi_direct::controller_acceptor::Session<'scope, 'task, 'policy, IO>,
        ) -> TrackedStreamWork<'work, S>,
    {
        let refusal = if !std::ptr::eq(self.fleet, automatic.fleet) {
            Some(RoutedStreamRefusal::FleetMismatch)
        } else if index >= MAX_RESOURCES || self.fleet.enrollment(index).is_none() {
            Some(RoutedStreamRefusal::UnknownEnrollment)
        } else if self
            .fleet
            .enrollment(index)
            .is_some_and(|enrollment| enrollment.mac() != session.claimed_mac())
        {
            Some(RoutedStreamRefusal::ClaimMismatch)
        } else if automatic.stopped {
            Some(RoutedStreamRefusal::Stopped)
        } else if automatic.in_flight[index] || !self.fleet.route_ready(index) {
            Some(RoutedStreamRefusal::SetupNotReady)
        } else if session.phase() != fss_reference::unifi_direct::Phase::AwaitHello {
            Some(RoutedStreamRefusal::SessionNotFresh)
        } else if self.occupied[index] {
            Some(RoutedStreamRefusal::Duplicate)
        } else if self.awaiting_disposition[index].is_some() {
            Some(RoutedStreamRefusal::PreviousUnresolved)
        } else if self.sequence[index] == u64::MAX {
            Some(RoutedStreamRefusal::GenerationExhausted)
        } else if self.work.len() >= self.capacity {
            Some(RoutedStreamRefusal::Capacity)
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err(RoutedStreamAdmission::Session { reason, session });
        }
        let enrollment = self.fleet.enrollment(index).expect("checked enrollment");
        let TrackedStreamWork { work, effects } = factory(enrollment, session);
        match self.insert(index, work) {
            Ok(()) => {
                let generation = self.sequence[index] + 1;
                self.sequence[index] = generation;
                self.running_automatic[index] = Some(generation);
                self.running_effects[index] = Some(effects);
                Ok(())
            }
            Err((reason, work)) => Err(RoutedStreamAdmission::Work {
                reason: match reason {
                    StreamRefusal::UnknownEnrollment => RoutedStreamRefusal::UnknownEnrollment,
                    StreamRefusal::PreviousUnresolved => RoutedStreamRefusal::PreviousUnresolved,
                    StreamRefusal::Work(reason) => RoutedStreamRefusal::Work(reason),
                },
                work,
                effects,
            }),
        }
    }
    /// Retrieve the exact outstanding completion for this owner and camera.
    pub fn pending_completion(&self, index: usize) -> Option<StreamCompletion> {
        Some(StreamCompletion {
            owner: Rc::clone(&self.identity),
            index,
            generation: self.awaiting_disposition.get(index).copied().flatten()?,
        })
    }
    /// Release only this exact completion after the caller has reconciled all
    /// effects and retained work from that stream. Checks the bound live
    /// coordinator's entire journal and refuses ambiguous persistence. This
    /// does not prove all stream effects used that coordinator or that its
    /// storage and reconciliation evidence are independently trustworthy.
    pub fn release_after_reconciliation(&mut self, completion: &StreamCompletion, effects: &EffectCoordinator) -> Result<(), StreamCompletionRefusal> {
        if !Rc::ptr_eq(&self.identity, &completion.owner) {
            return Err(StreamCompletionRefusal::WrongOwner);
        }
        let Some(slot) = self.awaiting_disposition.get_mut(completion.index) else {
            return Err(StreamCompletionRefusal::Stale);
        };
        if *slot != Some(completion.generation) {
            return Err(StreamCompletionRefusal::Stale);
        }
        let binding = self.awaiting_effects.get(completion.index)
            .and_then(Option::as_ref).ok_or(StreamCompletionRefusal::Stale)?;
        effects.check_all_terminal(binding).map_err(|reason| match reason {
            EffectSettlementRefusal::WrongCoordinator => StreamCompletionRefusal::WrongCoordinator,
            EffectSettlementRefusal::PersistencePoisoned => StreamCompletionRefusal::PersistencePoisoned,
            EffectSettlementRefusal::Unsettled => StreamCompletionRefusal::UnsettledEffects,
        })?;
        *slot = None;
        self.awaiting_effects[completion.index] = None;
        Ok(())
    }
    /// Whether all retained stream futures have completed.
    pub fn is_empty(&self) -> bool {
        self.work.is_empty()
    }
    /// Number of retained stream futures.
    pub fn len(&self) -> usize {
        self.work.len()
    }
    // Both live streams and retained completions exclude a new setup attempt.
    fn setup_exclusions(&self) -> [bool; MAX_RESOURCES] {
        std::array::from_fn(|index| {
            self.occupied[index] || self.awaiting_disposition[index].is_some()
        })
    }
    /// Return remaining futures for explicit retirement only when there are
    /// no running or undisposed automatic streams; otherwise return this exact owner.
    /// Dropping an owner remains an interruption, not reconciliation.
    pub fn into_pending(self) -> Result<Vec<(usize, CameraWork<'work, S>)>, Self> {
        if self.awaiting_disposition.iter().any(Option::is_some)
            || self.running_automatic.iter().any(Option::is_some) {
            return Err(self);
        }
        Ok(self.work.into_pending())
    }
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<(usize, S)> {
        match self.work.poll_next(cx) {
            Poll::Ready((index, output)) => {
                self.occupied[index] = false;
                self.emitted_completion = None;
                if let Some(generation) = self.running_automatic[index].take() {
                    self.awaiting_disposition[index] = Some(generation);
                    self.awaiting_effects[index] = self.running_effects[index].take();
                    self.emitted_completion = Some(StreamCompletion {
                        owner: Rc::clone(&self.identity), index, generation,
                    });
                }
                Poll::Ready((index, output))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A setup admission or progress from the caller-owned automatic work loop.
#[must_use = "handle admission failures, returned work, and fleet events"]
pub enum AutomaticEvent<'scope, 'task, 'work, E, W> {
    /// One ready enrollment's factory-provided future was retained.
    Started { index: usize },
    /// Factory refused this enrollment; it will not be silently retried.
    FactoryFailed { index: usize, kind: io::ErrorKind },
    /// Work-set refusal, returning the exact not-yet-polled future.
    Rejected {
        index: usize,
        reason: WorkRefusal,
        work: CameraWork<'work, W>,
    },
    /// Fleet progress or an exact completed camera operation.
    Progress(Supervised<'scope, 'task, E, W>),
}

/// One automatic setup/fleet event or one caller-owned active stream result.
#[must_use = "handle the event and reconcile any returned camera effects"]
pub enum FleetStreamEvent<'scope, 'task, 'work, E, W, S> {
    /// Existing setup selection or fleet progress.
    Automatic(AutomaticEvent<'scope, 'task, 'work, E, W>),
    /// A retained stream operation completed for this enrollment.
    Stream { index: usize, output: S },
}

/// An exact setup operation and its caller-owned result.
pub struct RetryCompletion<W> {
    /// The operation passed to the tracked setup.
    pub operation: fss_core::OperationId,
    /// Original setup outcome and any associated caller-owned obligations.
    pub output: W,
}

/// Own an initially empty retry queue and its association with setup outcomes.
/// The queue stays private so a timer cannot be consumed by another owner.
#[must_use = "retain or explicitly retire pending retry timers"]
pub struct RetryCoordinator<'fleet, 'report, 'scope, 'task> {
    queue: retry::Queue<'fleet, 'report, 'scope, 'task>,
    scheduled: [bool; MAX_RESOURCES],
}
impl<'fleet, 'report, 'scope, 'task> RetryCoordinator<'fleet, 'report, 'scope, 'task> {
    /// Take an empty queue or return it unchanged.
    pub fn new(
        queue: retry::Queue<'fleet, 'report, 'scope, 'task>,
    ) -> Result<Self, retry::Queue<'fleet, 'report, 'scope, 'task>> {
        if !queue.is_empty() {
            return Err(queue);
        }
        Ok(Self {
            queue,
            scheduled: [false; MAX_RESOURCES],
        })
    }
    /// Number of retained retry timers.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
    /// Whether there are no retained retry timers.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    /// Explicitly schedule an exact pre-effect failure after an owner decision.
    /// This does not grant authority for a subsequent camera operation.
    pub fn schedule_explicit_for(
        &mut self,
        index: usize,
        operation: &fss_core::OperationId,
    ) -> Result<(), retry::Error> {
        let slot = self.scheduled.get_mut(index).ok_or(retry::Error::NotEligible)?;
        self.queue.schedule_for(index, operation)?;
        *slot = true;
        Ok(())
    }
}

/// How a completed timer affected this supervisor's selection latch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrySelection {
    /// Its exact queue-owned attempt became eligible for a later selection.
    Released,
    /// Shutdown prevented selection; no new setup will be admitted.
    Stopped,
    /// The timer was stale, refused or no longer matched this owner.
    NotReleased,
}

/// A fleet event with any automatic timer admission result, or a retry event.
#[must_use = "retain every setup outcome and handle every retry event"]
pub enum RetryingFleetEvent<'scope, 'task, 'work, E, W, S> {
    /// Fleet event; `retry` is present only for a completed setup.
    Fleet {
        event: FleetStreamEvent<'scope, 'task, 'work, E, RetryCompletion<W>, S>,
        retry: Option<RetryDisposition>,
    },
    /// A retry timer returned; selection release does not authorize an effect.
    Retry {
        event: retry::Event,
        selection: RetrySelection,
    },
}

/// Protected transport owned by a routed fleet controller session.
pub type RoutedTransport<'scope, 'task, 'policy> =
    Session<'scope, 'task, Routed<'scope, 'task, 'policy>>;

/// Events from the combined setup, retry, route and stream admission loop.
#[must_use = "handle progress and retain any refused session or work"]
pub enum AutoRoutedFleetEvent<'scope, 'task, 'policy, 'setup, 'stream, W, S> {
    /// Existing fleet, setup, retry or stream outcome.
    Progress(RetryingFleetEvent<'scope, 'task, 'setup,
        controller_acceptor::Event<'scope, 'task, 'policy, RoutedTransport<'scope, 'task, 'policy>>,
        W, S>),
    /// An accepted session was converted into a retained, unpolled stream future.
    StreamStarted { index: usize },
    /// An automatically admitted stream finished; reconcile before rearming.
    StreamFinished {
        /// Enrollment whose stream finished.
        index: usize,
        /// Original caller-owned output and any effects it retains.
        output: S,
        /// Owner-bound identity for this completion.
        completion: StreamCompletion,
    },
    /// Admission was refused; the original session or future remains caller-owned.
    StreamRefused {
        /// Enrollment selected by the router.
        index: usize,
        /// The refused session or work.
        refusal: RoutedStreamAdmission<'scope, 'task, 'policy, 'stream,
            RoutedTransport<'scope, 'task, 'policy>, S>,
    },
}

/// Refusal while driving the coordinated retry loop.
#[derive(Debug)]
pub enum RetryLoopError {
    /// The queue is not bound to this pump's fleet, context and clock.
    Binding,
    /// The existing fleet or stream loop refused progress.
    Fleet(io::Error),
    /// The retry queue refused progress.
    Retry(retry::Error),
}

/// One supervisor for a bounded, append-only caller-supplied resource inventory.
///
/// Poll `next` alongside the fleet driver. Call `request_stop` and continue
/// polling until `Stopped`; dropping the owner cannot synchronously drain an
/// already-running system call. Failure is latched until explicit rearm.
#[must_use = "request stop and drain all workers before dropping the supply"]
pub struct LeaseSupply<'scope, 'task> {
    transport: FleetLeased<'scope, 'task>,
    pending: Vec<Option<Acquisition<'scope, 'task>>>,
    failed: Vec<bool>,
    max_inflight: usize,
    entropy_bytes: usize,
    cursor: usize,
    prefer_camera: bool,
    prefer_stream: bool,
    prefer_retry: bool,
    stopping: bool,
    finished: bool,
}
impl<'scope, 'task> LeaseSupply<'scope, 'task> {
    /// Claim the transport's sole supply owner and preallocate finite slots.
    pub fn new(
        transport: FleetLeased<'scope, 'task>,
        max_inflight: usize,
        entropy_bytes: usize,
    ) -> io::Result<Self> {
        if !(1..=MAX_RESOURCES).contains(&max_inflight) || !(64..=4096).contains(&entropy_bytes) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(MAX_RESOURCES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        pending.resize_with(MAX_RESOURCES, || None);
        let mut failed = Vec::new();
        failed
            .try_reserve_exact(MAX_RESOURCES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        failed.resize(MAX_RESOURCES, false);
        if transport.supply_claim.replace(true) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(Self {
            transport,
            pending,
            failed,
            max_inflight,
            entropy_bytes,
            cursor: 0,
            prefer_camera: true,
            prefer_stream: true,
            prefer_retry: true,
            stopping: false,
            finished: false,
        })
    }
    /// Retry one latched failure only after an explicit owner decision.
    pub fn rearm(&mut self, index: usize) -> io::Result<()> {
        if self.stopping
            || index >= self.transport.resources.len()
            || !self.failed[index]
            || self.pending[index].is_some()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.failed[index] = false;
        Ok(())
    }
    /// Cancel pending acquisitions, retaining them until `Stopped`.
    pub fn request_stop(&mut self) {
        self.stopping = true;
        for owner in self.pending.iter_mut().flatten() {
            owner.abort();
        }
    }
    /// Wait for one bounded event; dropping this wait retains every owner.
    pub async fn next(&mut self) -> Option<SupplyEvent<'scope, 'task>> {
        poll_fn(|cx| self.poll_next(cx)).await
    }
    /// Drive discovery, routing, and this supply in the same caller-owned loop.
    /// Synchronize owner-supplied enrollments from the pump's exact fleet and
    /// wake on later additions. This does not create enrollments or credentials.
    /// Refuses a pump whose acceptor does not retain this exact transport.
    /// Dropping the borrowing wait retains both owners and all admitted work.
    pub async fn next_with_pump<'pump, 'fleet, 'report, 'policy, A>(
        &mut self,
        pump: &mut Pump<
            'pump,
            'fleet,
            'report,
            'scope,
            'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>,
        >,
    ) -> io::Result<
        Progress<
            <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
            Option<SupplyEvent<'scope, 'task>>,
        >,
    >
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
{
        if !Rc::ptr_eq(&self.transport.slots, &pump.driver().transport().slots) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fleet = pump.driver().fleet();
        let runtime_cx = self.transport.cx;
        loop {
            if self.stopping {
                let mut wait = pin!(self.next());
                return Ok(pump.next_with(wait.as_mut()).await);
            }
            self.transport.synchronize_fleet(fleet)?;
            let observed = fleet.len();
            enum Selected<T> {
                Changed(io::Result<()>),
                Progress(T),
            }
            let selected = {
                let mut changed = pin!(fleet.wait_for_enrollment_after(runtime_cx, observed));
                let mut wait = pin!(self.next());
                poll_fn(|context| {
                    if let Poll::Ready(result) = changed.as_mut().poll(context) {
                        return Poll::Ready(Selected::Changed(result));
                    }
                    pump.poll_with(context, wait.as_mut())
                        .map(Selected::Progress)
                })
                .await
            };
            match selected {
                Selected::Changed(Ok(())) => (),
                Selected::Changed(Err(error)) => return Err(error),
                Selected::Progress(progress) => return Ok(progress),
            }
        }
    }

    /// Drive retained camera work fairly alongside discovery, routing and the
    /// lease supply. Camera operations and their effect traces remain caller
    /// owned; this method does not construct or authorize a setup. Dropping a
    /// borrowing wait preserves both the work set and the fleet owners.
    pub async fn next_with_camera_work<'pump, 'fleet, 'report, 'policy, 'work, A, W>(
        &mut self,
        pump: &mut Pump<
            'pump,
            'fleet,
            'report,
            'scope,
            'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>,
        >,
        work: &mut CameraWorkSet<'work, W>,
    ) -> io::Result<
        Supervised<
            'scope,
            'task,
            <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
            W,
        >,
    >
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
{
        if !Rc::ptr_eq(&self.transport.slots, &pump.driver().transport().slots) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let prefer_camera = self.prefer_camera;
        let selected = {
            let mut fleet = pin!(self.next_with_pump(pump));
            poll_fn(|context| {
                if prefer_camera {
                    if let Poll::Ready((index, output)) = work.poll_next(context) {
                        return Poll::Ready(Ok(Supervised::Camera { index, output }));
                    }
                }
                if let Poll::Ready(result) = fleet.as_mut().poll(context) {
                    return Poll::Ready(result.map(Supervised::Fleet));
                }
                if !prefer_camera {
                    if let Poll::Ready((index, output)) = work.poll_next(context) {
                        return Poll::Ready(Ok(Supervised::Camera { index, output }));
                    }
                }
                Poll::Pending
            })
            .await?
        };
        self.prefer_camera = matches!(selected, Supervised::Fleet(_));
        Ok(selected)
    }

    /// Select an unattempted ready owner enrollment and ask the caller's
    /// factory for its already-authorized work. The factory must not perform
    /// effects synchronously; all I/O and effects belong inside the returned
    /// owned future. Factory refusal and completed work are never silently
    /// retried by this owner. Dropping the borrowing wait retains admitted work.
    pub async fn next_with_automatic_setup<'pump, 'fleet, 'report, 'policy, 'work, A, W, F>(
        &mut self,
        pump: &mut Pump<
            'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>,
        >,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work, W>,
        factory: &mut F,
    ) -> io::Result<
        AutomaticEvent<'scope, 'task, 'work,
            <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
            W>,
    >
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
        F: FnMut(usize, Enrollment) -> io::Result<CameraWork<'work, W>>,
{
        self.next_with_automatic_setup_excluding(pump, automatic, factory, &[false; MAX_RESOURCES])
            .await
    }

    async fn next_with_automatic_setup_excluding<'pump, 'fleet, 'report, 'policy, 'work, A, W, F>(
        &mut self,
        pump: &mut Pump<'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>>,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work, W>,
        factory: &mut F,
        excluded: &[bool; MAX_RESOURCES],
    ) -> io::Result<AutomaticEvent<'scope, 'task, 'work,
        <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
        W>>
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
        F: FnMut(usize, Enrollment) -> io::Result<CameraWork<'work, W>>,
{
        if !Rc::ptr_eq(&self.transport.slots, &pump.driver().transport().slots)
            || !std::ptr::eq(automatic.fleet, pump.driver().fleet())
            || automatic
                .transport
                .as_ref()
                .is_some_and(|bound| !Rc::ptr_eq(bound, &self.transport.identity))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.transport
            .cx
            .checkpoint()
            .map_err(|_| io::ErrorKind::Interrupted)?;
        let fleet = automatic.fleet;
        if !self.stopping && !automatic.stopped {
            self.transport.synchronize_fleet(fleet)?;
        }
        if automatic.transport.is_none() {
            automatic.transport = Some(self.transport.identity.clone());
        }
        let len = fleet.len();
        if !self.stopping && !automatic.stopped && automatic.work.len() < automatic.capacity {
            for offset in 0..len {
                let index = (automatic.cursor + offset) % len;
                if excluded[index]
                    || automatic.attempted[index]
                    || !matches!(fleet.state(index), Some(State::Ready { .. }))
                {
                    continue;
                }
                let enrollment = fleet.enrollment(index).ok_or(io::ErrorKind::InvalidData)?;
                automatic.attempted[index] = true;
                automatic.missing_factory[index] = None;
                automatic.cursor = (index + 1) % len;
                return Ok(match factory(index, enrollment) {
                    Err(error) => {
                        if let Some(missing) = error
                            .get_ref()
                            .and_then(|value| value.downcast_ref::<MissingPlan>())
                            .filter(|missing| {
                                missing.index == index && error.kind() == io::ErrorKind::NotFound
                            })
                        {
                            automatic.missing_factory[index] = Some(missing.identity.clone());
                        }
                        AutomaticEvent::FactoryFailed {
                            index,
                            kind: error.kind(),
                        }
                    }
                    Ok(work) => match automatic.work.insert(index, work) {
                        Ok(()) => {
                            automatic.in_flight[index] = true;
                            AutomaticEvent::Started { index }
                        }
                        Err((reason, work)) => AutomaticEvent::Rejected {
                            index,
                            reason,
                            work,
                        },
                    },
                });
            }
        }
        let result = self
            .next_with_camera_work(pump, &mut automatic.work)
            .await?;
        if let Supervised::Camera { index, .. } = &result {
            automatic.in_flight[*index] = false;
        }
        Ok(AutomaticEvent::Progress(result))
    }

    /// Drive caller-owned active streams together with automatic setup,
    /// discovery, routing and entropy supply. Validate the pump and fleet
    /// bindings before polling either work set. Both sets and all traces
    /// remain caller-owned across a dropped wait; stop admission and explicitly
    /// retire or drain their pending futures at shutdown. The caller must bind
    /// each stream's session, authority and effect trace to the camera; the
    /// work set does not authenticate that association. This method skips
    /// setup for occupied or unresolved stream indices and refuses overlaps before
    /// polling either work set. This protection covers only the supplied pair;
    /// separate owners or the standalone setup method can still overlap. A
    /// completed future does not establish effect reconciliation. Polling only
    /// provides fairness between yields: a blocking callback, journal operation, or
    /// decoder inside one future can still stall the entire loop.
    pub async fn next_with_setup_and_streams<'pump, 'fleet, 'report, 'policy, 'work, 'stream, A, W, S, F>(
        &mut self,
        pump: &mut Pump<'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>>,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work, W>,
        streams: &mut ActiveStreams<'fleet, 'report, 'stream, S>,
        factory: &mut F,
    ) -> io::Result<FleetStreamEvent<'scope, 'task, 'work,
        <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
        W, S>>
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
        F: FnMut(usize, Enrollment) -> io::Result<CameraWork<'work, W>>,
{
        if !Rc::ptr_eq(&self.transport.slots, &pump.driver().transport().slots)
            || !std::ptr::eq(automatic.fleet, pump.driver().fleet())
            || !std::ptr::eq(streams.fleet, pump.driver().fleet())
            || automatic
                .transport
                .as_ref()
                .is_some_and(|bound| !Rc::ptr_eq(bound, &self.transport.identity))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let excluded = streams.setup_exclusions();
        if automatic
            .in_flight
            .iter()
            .zip(excluded.iter())
            .any(|(a, b)| *a && *b)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.transport
            .cx
            .checkpoint()
            .map_err(|_| io::ErrorKind::Interrupted)?;
        let prefer_stream = self.prefer_stream;
        let selected = {
            let mut other =
                pin!(self.next_with_automatic_setup_excluding(pump, automatic, factory, &excluded));
            poll_fn(|context| {
                if prefer_stream {
                    if let Poll::Ready((index, output)) = streams.poll_next(context) {
                        return Poll::Ready(Ok(FleetStreamEvent::Stream { index, output }));
                    }
                }
                if let Poll::Ready(result) = other.as_mut().poll(context) {
                    return Poll::Ready(result.map(FleetStreamEvent::Automatic));
                }
                if !prefer_stream {
                    if let Poll::Ready((index, output)) = streams.poll_next(context) {
                        return Poll::Ready(Ok(FleetStreamEvent::Stream { index, output }));
                    }
                }
                Poll::Pending
            })
            .await?
        };
        self.prefer_stream = matches!(selected, FleetStreamEvent::Automatic(_));
        Ok(selected)
    }

    /// Drive automatic setup, retry timers, active streams, discovery and
    /// lease supply together. Only an exact pre-effect fleet failure can be
    /// scheduled by the queue. Every setup output and timer disposition is
    /// returned; effect traces and credentials remain with the caller. A
    /// borrowing wait may be dropped without discarding retained work.
    /// Stopping setup or the supply stops polling timers; it does not discard
    /// them. Polls must still be cooperative and independent owners can overlap.
    pub async fn next_with_retries_and_streams<'pump, 'fleet, 'report, 'policy, 'work, 'stream, A, W, S, F>(
        &mut self,
        pump: &mut Pump<'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>>,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work, RetryCompletion<W>>,
        streams: &mut ActiveStreams<'fleet, 'report, 'stream, S>,
        retries: &mut RetryCoordinator<'fleet, 'report, 'scope, 'task>,
        factory: &mut F,
    ) -> Result<RetryingFleetEvent<'scope, 'task, 'work,
        <Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>> as Driver<'scope, 'task>>::Event,
        W, S>, RetryLoopError>
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
        F: FnMut(usize, Enrollment) -> io::Result<CameraWork<'work, RetryCompletion<W>>>,
{
        if !pump.accepts_retries(&retries.queue) {
            return Err(RetryLoopError::Binding);
        }
        if !Rc::ptr_eq(&self.transport.slots, &pump.driver().transport().slots)
            || !std::ptr::eq(automatic.fleet, pump.driver().fleet())
            || !std::ptr::eq(streams.fleet, pump.driver().fleet())
            || automatic
                .transport
                .as_ref()
                .is_some_and(|bound| !Rc::ptr_eq(bound, &self.transport.identity))
        {
            return Err(RetryLoopError::Fleet(io::ErrorKind::InvalidInput.into()));
        }
        let excluded = streams.setup_exclusions();
        if automatic
            .in_flight
            .iter()
            .zip(excluded.iter())
            .any(|(a, b)| *a && *b)
        {
            return Err(RetryLoopError::Fleet(io::ErrorKind::AlreadyExists.into()));
        }
        self.transport
            .cx
            .checkpoint()
            .map_err(|_| RetryLoopError::Fleet(io::ErrorKind::Interrupted.into()))?;
        enum Selected<T> {
            Fleet(io::Result<T>),
            Retry(Result<retry::Event, retry::Error>),
        }
        let prefer_retry = self.prefer_retry;
        let poll_retries = !retries.queue.is_empty() && !self.stopping && !automatic.stopped;
        let selected = {
            let mut fleet =
                pin!(self.next_with_setup_and_streams(pump, automatic, streams, factory));
            if !poll_retries {
                Selected::Fleet(fleet.await)
            } else {
                let mut retry = pin!(retries.queue.next());
                poll_fn(|cx| {
                    if prefer_retry {
                        if let Poll::Ready(result) = retry.as_mut().poll(cx) {
                            return Poll::Ready(Selected::Retry(result));
                        }
                    }
                    if let Poll::Ready(result) = fleet.as_mut().poll(cx) {
                        return Poll::Ready(Selected::Fleet(result));
                    }
                    if !prefer_retry {
                        if let Poll::Ready(result) = retry.as_mut().poll(cx) {
                            return Poll::Ready(Selected::Retry(result));
                        }
                    }
                    Poll::Pending
                })
                .await
            }
        };
        match selected {
            Selected::Fleet(result) => {
                let event = result.map_err(RetryLoopError::Fleet)?;
                self.prefer_retry = true;
                let retry = if let FleetStreamEvent::Automatic(AutomaticEvent::Progress(
                    Supervised::Camera { index, output },
                )) = &event
                {
                    Some(
                        match retries.queue.schedule_automatic_for(*index, &output.operation) {
                            Ok(()) => {
                                retries.scheduled[*index] = true;
                                RetryDisposition::Scheduled
                            }
                            Err(retry::Error::NotEligible) => RetryDisposition::NotEligible,
                            Err(retry::Error::Duplicate) => RetryDisposition::AlreadyScheduled,
                            Err(error) => RetryDisposition::Refused(error),
                        },
                    )
                } else {
                    None
                };
                Ok(RetryingFleetEvent::Fleet { event, retry })
            }
            Selected::Retry(result) => {
                let event = result.map_err(RetryLoopError::Retry)?;
                self.prefer_retry = false;
                let index = match event {
                    retry::Event::Rearmed { index, .. }
                    | retry::Event::Stale { index }
                    | retry::Event::Refused { index, .. } => index,
                };
                let owned = index < MAX_RESOURCES
                    && std::mem::replace(&mut retries.scheduled[index], false);
                let selection = if self.stopping || automatic.stopped {
                    RetrySelection::Stopped
                } else if owned
                    && matches!(event, retry::Event::Rearmed { state, .. } if automatic.fleet.state(index) == Some(state))
                    && automatic.attempted[index]
                    && !automatic.in_flight[index]
                {
                    automatic.attempted[index] = false;
                    automatic.missing_factory[index] = None;
                    RetrySelection::Released
                } else {
                    RetrySelection::NotReleased
                };
                Ok(RetryingFleetEvent::Retry { event, selection })
            }
        }
    }
    /// Drive setup, retries, routes and streams, admitting each accepted route
    /// to a caller-supplied factory without a separate event-routing step.
    /// The factory receives the optional setup-time camera-reported profile;
    /// an absent selection requires an explicit caller policy. That claim may
    /// be stale and is not proof of media properties. The factory must only
    /// construct a future and must independently bind
    /// its session, credentials, media policy and effect authority. A refusal
    /// returns the original session or unpolled future; shutdown never starts
    /// a new stream. Dropping this wait retains existing owners, but dropping
    /// the owners still requires the caller to retire or drain their work.
    pub async fn next_with_automatic_streams<'pump, 'fleet, 'report, 'policy, 'work, 'stream, A, W, S, F, G>(
        &mut self,
        pump: &mut Pump<'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>>,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work, RetryCompletion<W>>,
        streams: &mut ActiveStreams<'fleet, 'report, 'stream, S>,
        retries: &mut RetryCoordinator<'fleet, 'report, 'scope, 'task>,
        setup_factory: &mut F,
        stream_factory: &mut G,
    ) -> Result<AutoRoutedFleetEvent<'scope, 'task, 'policy, 'work, 'stream, W, S>, RetryLoopError>
    where
        'fleet: 'pump,
        'report: 'fleet,
        'scope: 'fleet,
        'task: 'scope,
        'policy: 'scope,
        A: PeerAdmission + 'fleet,
        F: FnMut(usize, Enrollment) -> io::Result<CameraWork<'work, RetryCompletion<W>>>,
        G: FnMut(usize, Enrollment, Option<(VideoChannel, VideoProfile)>,
            controller_acceptor::Session<'scope, 'task, 'policy, RoutedTransport<'scope, 'task, 'policy>>)
            -> TrackedStreamWork<'stream, S>,
    {
        let event = self.next_with_retries_and_streams(
            pump, automatic, streams, retries, setup_factory,
        ).await?;
        match event {
            RetryingFleetEvent::Fleet {
                event: FleetStreamEvent::Stream { index, output }, retry: None,
            } => match streams.emitted_completion.take() {
                Some(completion) => Ok(AutoRoutedFleetEvent::StreamFinished { index, output, completion }),
                None => Ok(AutoRoutedFleetEvent::Progress(RetryingFleetEvent::Fleet {
                    event: FleetStreamEvent::Stream { index, output }, retry: None,
                })),
            },
            RetryingFleetEvent::Fleet {
                event: FleetStreamEvent::Automatic(AutomaticEvent::Progress(
                    Supervised::Fleet(Progress::Event(pump::Event::Route(
                        controller_acceptor::Event::Session { index, session }
                    )))
                )),
                retry: None,
            } => {
                if self.stopping {
                    return Ok(AutoRoutedFleetEvent::StreamRefused {
                        index,
                        refusal: RoutedStreamAdmission::Session {
                            reason: RoutedStreamRefusal::Stopped,
                            session,
                        },
                    });
                }
                let reported_video = streams.fleet.reported_video(index);
                match streams.admit_routed_session(automatic, index, session,
                    |enrollment, session| stream_factory(index, enrollment, reported_video, session)) {
                    Ok(()) => Ok(AutoRoutedFleetEvent::StreamStarted { index }),
                    Err(refusal) => Ok(AutoRoutedFleetEvent::StreamRefused { index, refusal }),
                }
            }
            other => Ok(AutoRoutedFleetEvent::Progress(other)),
        }
    }

    /// Drive an enrolled camera factory, retry queue, routed stream factory,
    /// discovery and entropy supply under the same caller-owned supervisor.
    /// A mismatched camera factory is refused before any owner is polled.
    /// The caller must retain and reconcile returned attempt and stream state;
    /// this does not enroll unknown devices or prove physical identity.
    pub async fn next_with_camera_factory_and_automatic_streams<
        'pump, 'fleet, 'report, 'policy, 'work, 'owner, 'stream, A, S, G,
    >(
        &mut self,
        pump: &mut Pump<'pump, 'fleet, 'report, 'scope, 'task,
            Acceptor<'fleet, 'report, 'scope, 'task, 'policy, A, FleetLeased<'scope, 'task>>>,
        automatic: &mut AutomaticWork<'fleet, 'report, 'work,
            RetryCompletion<Result<fss_reference::unifi_direct::setup::Outcome, crate::camera_setup::Error>>>,
        streams: &mut ActiveStreams<'fleet, 'report, 'stream, S>,
        retries: &mut RetryCoordinator<'fleet, 'report, 'scope, 'task>,
        factory: &mut crate::camera_factory::Factory<'fleet, 'work, 'owner, 'report, 'scope, 'task, 'policy>,
        stream_factory: &mut G,
    ) -> Result<AutoRoutedFleetEvent<'scope, 'task, 'policy, 'work, 'stream,
        Result<fss_reference::unifi_direct::setup::Outcome, crate::camera_setup::Error>, S>, RetryLoopError>
    where
        'fleet: 'pump,
        'report: 'fleet + 'work,
        'scope: 'fleet + 'work,
        'task: 'scope,
        'policy: 'scope,
        'owner: 'work,
        A: PeerAdmission + 'fleet,
        G: FnMut(usize, Enrollment, Option<(VideoChannel, VideoProfile)>,
            controller_acceptor::Session<'scope, 'task, 'policy, RoutedTransport<'scope, 'task, 'policy>>)
            -> TrackedStreamWork<'stream, S>,
    {
        if !factory.matches_fleet(pump.driver().fleet()) {
            return Err(RetryLoopError::Binding);
        }
        let mut setup = |index, enrollment| factory.take(index, enrollment);
        self.next_with_automatic_streams(pump, automatic, streams, retries, &mut setup, stream_factory).await
    }

    /// Drive workers and replenish empty slots without detached tasks.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<SupplyEvent<'scope, 'task>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        let incoming = cx.waker().clone();
        let previous = match self.transport.slots.try_borrow_mut() {
            Ok(mut slots) => slots.waiter.replace(incoming),
            Err(_) => {
                return Poll::Ready(Some(SupplyEvent::Busy));
            }
        };
        drop(previous);
        let len = self.transport.resources.len();
        for offset in 0..len {
            let index = (self.cursor + offset) % len;
            let completion = if let Some(owner) = self.pending[index].as_mut() {
                let mut wait = pin!(owner.join());
                match wait.as_mut().poll(cx) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                }
            } else {
                None
            };
            if let Some(result) = completion {
                self.pending[index].take();
                self.cursor = (index + 1) % len;
                if self.stopping {
                    drop(result);
                    return Poll::Ready(Some(SupplyEvent::Drained(index)));
                }
                return Poll::Ready(Some(match result {
                    Ok(lease) => match self.transport.install(lease) {
                        Ok(()) => SupplyEvent::Installed(index),
                        Err(lease) => {
                            self.failed[index] = true;
                            SupplyEvent::Rejected { index, lease }
                        }
                    },
                    Err(error) => {
                        self.failed[index] = true;
                        SupplyEvent::Failed {
                            index,
                            kind: error.kind(),
                        }
                    }
                }));
            }
        }
        if self.stopping {
            if self.pending.iter().all(Option::is_none) {
                self.finished = true;
                return Poll::Ready(Some(SupplyEvent::Stopped));
            }
            return Poll::Pending;
        }
        let inflight = self.pending.iter().filter(|owner| owner.is_some()).count();
        if inflight < self.max_inflight {
            for offset in 0..len {
                let index = (self.cursor + offset) % len;
                if self.pending[index].is_some() || self.failed[index] {
                    continue;
                }
                let occupied = match self.transport.slots.try_borrow() {
                    Ok(slots) => slots.leases[index].is_some(),
                    Err(_) => return Poll::Ready(Some(SupplyEvent::Busy)),
                };
                if occupied {
                    continue;
                }
                let resources = self.transport.resources;
                match Acquisition::begin(
                    self.transport.task,
                    self.transport.cx,
                    self.transport.clock,
                    resources.get(index).expect("published resource"),
                    self.entropy_bytes,
                ) {
                    Ok(owner) => {
                        self.pending[index] = Some(owner);
                        self.cursor = (index + 1) % len;
                        return Poll::Ready(Some(SupplyEvent::Started(index)));
                    }
                    Err(error) => {
                        self.failed[index] = true;
                        return Poll::Ready(Some(SupplyEvent::Failed {
                            index,
                            kind: error.kind(),
                        }));
                    }
                }
            }
        }
        Poll::Pending
    }
}
impl Drop for LeaseSupply<'_, '_> {
    fn drop(&mut self) {
        for owner in self.pending.iter_mut().flatten() {
            owner.abort();
        }
        self.transport.supply_claim.set(false);
        let wake = self
            .transport
            .slots
            .try_borrow_mut()
            .ok()
            .and_then(|mut slots| slots.waiter.take());
        drop(wake);
    }
}

#[cfg(test)]
mod waiting_tests {
    use super::*;

    #[test]
    fn owned_effect_work_is_lazy_and_returns_the_bound_coordinator() {
        let called = Rc::new(Cell::new(false));
        let called_in_work = called.clone();
        let tracked = TrackedStreamWork::with_owned_effects(
            EffectCoordinator::new(),
            move |effects| async move {
                called_in_work.set(true);
                (42, effects)
            },
        );
        assert!(!called.get());
        let TrackedStreamWork { mut work, effects: binding } = tracked;
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready((value, effects)) = work.as_mut().poll(&mut cx) else {
            panic!("immediate work unexpectedly pending");
        };
        assert!(called.get());
        assert_eq!(value, 42);
        assert_eq!(effects.check_all_terminal(&binding), Ok(()));
        assert_eq!(EffectCoordinator::new().check_all_terminal(&binding), Err(EffectSettlementRefusal::WrongCoordinator));
    }

    #[test]
    fn stream_completion_release_is_owner_bound_and_rejects_stale_handles() {
        use fss_reference::unifi_direct::discovery::{Report, Stop};
        let fleet = Fleet::from_report(Report {
            cameras: vec![], datagrams: 0, malformed: 0, out_of_scope: 0,
            stop: Stop::WindowElapsed,
        }, &[]).unwrap();
        let mut first = ActiveStreams::<()>::new(&fleet, 1).unwrap();
        let mut second = ActiveStreams::<()>::new(&fleet, 1).unwrap();
        let effects = EffectCoordinator::new();
        first.awaiting_disposition[0] = Some(1);
        first.awaiting_effects[0] = Some(effects.binding());
        first.occupied[1] = true;
        assert!(first.setup_exclusions()[0]);
        assert!(first.setup_exclusions()[1]);
        assert!(!first.setup_exclusions()[2]);
        let old = first.pending_completion(0).unwrap();
        assert_eq!(second.release_after_reconciliation(&old, &effects), Err(StreamCompletionRefusal::WrongOwner));
        first.awaiting_disposition[0] = Some(2);
        assert_eq!(first.release_after_reconciliation(&old, &effects), Err(StreamCompletionRefusal::Stale));
        let current = first.pending_completion(0).unwrap();
        assert_eq!(first.release_after_reconciliation(&current, &EffectCoordinator::new()), Err(StreamCompletionRefusal::WrongCoordinator));
        assert_eq!(first.release_after_reconciliation(&current, &effects), Ok(()));
        assert!(!first.setup_exclusions()[0]);
        assert!(first.setup_exclusions()[1]);
        assert!(first.pending_completion(0).is_none());
        assert_eq!(first.release_after_reconciliation(&current, &effects), Err(StreamCompletionRefusal::Stale));
    }

    #[test]
    fn failed_automatic_work_remains_fenced_until_no_effect_is_resolved() {
        use fss_reference::unifi_direct::discovery::{Report, Stop};
        let fleet = Fleet::from_report(Report {
            cameras: vec![], datagrams: 0, malformed: 0, out_of_scope: 0,
            stop: Stop::WindowElapsed,
        }, &[]).unwrap();
        let mut streams = ActiveStreams::<Result<(), &'static str>>::new(&fleet, 1).unwrap();
        let effects = EffectCoordinator::new();
        assert!(streams.work.insert(0, Box::pin(async { Err("synthetic failure without effects") })).is_ok());
        streams.occupied[0] = true;
        streams.running_automatic[0] = Some(1);
        streams.running_effects[0] = Some(effects.binding());
        streams.sequence[0] = 1;
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(streams.poll_next(&mut cx), Poll::Ready((0, Err(_)))));
        let completion = streams.pending_completion(0).unwrap();
        let mut streams = match streams.into_pending() { Err(owner) => owner, Ok(_) => panic!("completion was lost") };
        // The synthetic future above has no I/O or effect to reconcile.
        assert_eq!(streams.release_after_reconciliation(&completion, &effects), Ok(()));
        assert_eq!(streams.release_after_reconciliation(&completion, &effects), Err(StreamCompletionRefusal::Stale));
        assert!(streams.into_pending().ok().is_some_and(|pending| pending.is_empty()));
    }

    #[test]
    fn resource_inventory_is_bounded_and_rejects_duplicates() {
        let empty = FleetResources::new(&[]).expect("empty fleet inventory");
        assert!(empty.is_empty());
        let names: Vec<_> = (0..MAX_RESOURCES)
            .map(|index| format!("camera:{index}"))
            .collect();
        let full = FleetResources::new(&names).expect("bounded fleet inventory");
        assert_eq!(full.len(), MAX_RESOURCES);
        let mut too_many = names.clone();
        too_many.push("camera:overflow".to_owned());
        assert!(
            matches!(FleetResources::new(&too_many), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(
            matches!(FleetResources::new(&["duplicate".into(), "duplicate".into()]), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }

    fn slot() -> Rc<RefCell<Slots<'static, 'static>>> {
        Rc::new(RefCell::new(Slots {
            leases: vec![None],
            waiter: None,
            handshake_waiters: vec![None],
        }))
    }

    fn waiting(slots: &Rc<RefCell<Slots<'static, 'static>>>) -> WaitSlot<'static, 'static> {
        WaitSlot {
            slots: slots.clone(),
            index: 0,
            token: Rc::new(()),
        }
    }

    #[test]
    fn cancelled_wait_releases_slot_and_refuses_a_live_competitor() {
        let slots = slot();
        let first = waiting(&slots);
        let second = waiting(&slots);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.poll_lease(&mut cx, |_| true).is_pending());
        assert!(
            matches!(second.poll_lease(&mut cx, |_| true), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::WouldBlock)
        );
        drop(first);
        assert!(second.poll_lease(&mut cx, |_| true).is_pending());
        drop(second);
        assert!(slots.borrow().handshake_waiters[0].is_none());
    }

    #[test]
    fn cancelled_wait_with_reentrant_borrow_does_not_block_successor() {
        let slots = slot();
        let first = waiting(&slots);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.poll_lease(&mut cx, |_| true).is_pending());
        let held = slots.borrow_mut();
        drop(first);
        drop(held);
        let next = waiting(&slots);
        assert!(next.poll_lease(&mut cx, |_| true).is_pending());
        drop(next);
        assert!(slots.borrow().handshake_waiters[0].is_none());
    }
}
