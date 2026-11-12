#![forbid(unsafe_code)]
//! Caller-driven coordination of periodic discovery and controller routing.
//!
//! The pump retains one scan future and the router's bounded socket owners
//! across events. It creates no task and supplies no setup or peer authority.
//! The caller must poll it, handle each outcome, authenticate routed peers,
//! and supervise sessions. A discovery claim is not device identity.

use super::{fleet, retry, scan};
use crate::unifi_direct::setup;
use fss_core::OperationId;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

type ScanFuture<'a> = Pin<Box<dyn Future<Output = Result<scan::Outcome, scan::Error>> + 'a>>;

/// One caller-owned camera operation. Dropping it can interrupt an effect;
/// the caller is responsible for draining its owner and reconciling its trace.
pub type CameraWork<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Why a camera operation could not enter the bounded work set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkRefusal {
    /// The requested work-set size is outside the admitted bound.
    InvalidCapacity,
    /// Space for the bounded work set could not be reserved.
    Allocation,
    /// Another operation for this enrollment is still in flight.
    Duplicate,
    /// The configured number of in-flight operations is already present.
    Capacity,
}

/// Bounded, caller-driven polling of independent camera operations.
///
/// A camera's future must own or borrow its own session and effect authority;
/// this set does not authenticate devices or create tasks. Dropping `next`
/// preserves every pending future. Dropping the set interrupts those futures;
/// use `into_pending` to return them to the caller for explicit retirement.
pub struct CameraWorkSet<'a, T> {
    pending: Vec<(usize, CameraWork<'a, T>)>,
    capacity: usize,
    cursor: usize,
}

impl<'a, T> CameraWorkSet<'a, T> {
    /// Allocate a finite number of slots. Invalid or failed allocation refuses
    /// before any camera operation is accepted.
    pub fn new(capacity: usize) -> Result<Self, WorkRefusal> {
        if !(1..=128).contains(&capacity) {
            return Err(WorkRefusal::InvalidCapacity);
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| WorkRefusal::Allocation)?;
        Ok(Self {
            pending,
            capacity,
            cursor: 0,
        })
    }

    /// Retain an operation or return that exact future unchanged on refusal.
    pub fn insert(
        &mut self,
        index: usize,
        work: CameraWork<'a, T>,
    ) -> Result<(), (WorkRefusal, CameraWork<'a, T>)> {
        if self.pending.iter().any(|(existing, _)| *existing == index) {
            return Err((WorkRefusal::Duplicate, work));
        }
        if self.pending.len() == self.capacity {
            return Err((WorkRefusal::Capacity, work));
        }
        self.pending.push((index, work));
        Ok(())
    }

    /// Number of still-owned operations.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no operations are owned.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Return all pending futures for explicit cancellation or retirement.
    pub fn into_pending(self) -> Vec<(usize, CameraWork<'a, T>)> {
        self.pending
    }

    /// Poll every pending operation fairly until one completes. An empty set
    /// stays pending; the caller must insert work before awaiting it.
    pub async fn next(&mut self) -> (usize, T) {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Poll at most the configured number of operations in rotating order.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<(usize, T)> {
        let len = self.pending.len();
        for offset in 0..len {
            let index = (self.cursor + offset) % len;
            if let Poll::Ready(output) = self.pending[index].1.as_mut().poll(cx) {
                // Preserve round-robin order when a completed camera is
                // immediately resubmitted; swap_remove could starve peers.
                let (camera, completed) = self.pending.remove(index);
                drop(completed);
                self.cursor = if self.pending.is_empty() {
                    0
                } else {
                    index % self.pending.len()
                };
                return Poll::Ready((camera, output));
            }
        }
        if len > 0 {
            self.cursor = (self.cursor + 1) % len;
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod work_set_tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
        sync::Arc,
        task::{Wake, Waker},
    };

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    struct Parked(Rc<Cell<usize>>);
    impl Future for Parked {
        type Output = usize;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
            Poll::Pending
        }
    }
    impl Drop for Parked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    struct TracePoll(usize, Rc<RefCell<Vec<usize>>>);
    impl Future for TracePoll {
        type Output = usize;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
            self.1.borrow_mut().push(self.0);
            Poll::Pending
        }
    }

    #[test]
    fn rotates_the_first_polled_camera() {
        let order = Rc::new(RefCell::new(Vec::new()));
        let mut set = CameraWorkSet::new(3).expect("bounded capacity");
        for index in 0..3 {
            assert!(
                set.insert(index, Box::pin(TracePoll(index, order.clone())))
                    .is_ok()
            );
        }
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(set.poll_next(&mut cx).is_pending());
        assert!(set.poll_next(&mut cx).is_pending());
        assert_eq!(&*order.borrow(), &[0, 1, 2, 1, 2, 0]);
    }

    #[test]
    fn completed_camera_resubmission_does_not_starve_ready_peers() {
        let mut set = CameraWorkSet::new(3).expect("bounded capacity");
        for index in 0..3 {
            assert!(
                set.insert(index, Box::pin(std::future::ready(index)))
                    .is_ok()
            );
        }
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        for expected in [0, 1, 2, 0, 1, 2] {
            assert_eq!(set.poll_next(&mut cx), Poll::Ready((expected, expected)));
            assert!(
                set.insert(expected, Box::pin(std::future::ready(expected)))
                    .is_ok()
            );
        }
    }

    #[test]
    fn preserves_owners_on_refusal_and_dropped_wait() {
        let drops = Rc::new(Cell::new(0));
        let mut set = CameraWorkSet::new(2).expect("bounded capacity");
        assert!(set.insert(1, Box::pin(Parked(drops.clone()))).is_ok());
        let duplicate = set.insert(1, Box::pin(Parked(drops.clone())));
        let (reason, duplicate) = match duplicate {
            Err(value) => value,
            Ok(()) => panic!("duplicate admitted"),
        };
        assert_eq!(reason, WorkRefusal::Duplicate);
        assert_eq!(drops.get(), 0);
        drop(duplicate);
        assert!(set.insert(2, Box::pin(std::future::ready(7))).is_ok());
        let overflow = set.insert(3, Box::pin(Parked(drops.clone())));
        let (reason, overflow) = match overflow {
            Err(value) => value,
            Ok(()) => panic!("overflow admitted"),
        };
        assert_eq!(reason, WorkRefusal::Capacity);
        assert_eq!(drops.get(), 1);
        drop(overflow);
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert_eq!(set.poll_next(&mut cx), Poll::Ready((2, 7)));
        let mut wait = Box::pin(set.next());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(wait);
        assert_eq!(drops.get(), 2);
        let retained = set.into_pending();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, 1);
        drop(retained);
        assert_eq!(drops.get(), 3);
    }
}

/// A bounded caller-owned connection driver that shares this scanner's fleet
/// and task clock. Implementations must truthfully validate that binding and
/// retain pending work across polls; this trait grants no network authority.
pub trait Driver<'scope, 'task> {
    /// One caller-owned event emitted by this driver.
    type Event;
    /// Check the scanner's exact fleet, task, runtime and clock mapping.
    fn matches_scanner(&self, scanner: &scan::Scanner<'_, '_, 'scope, 'task>) -> bool;
    /// Poll one event, preserving in-flight work when pending.
    fn poll_driver(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event>;
}

impl<'fleet, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, 'policy: 'fleet> Driver<'scope, 'task>
    for fleet::Router<'fleet, 'report, 'scope, 'task, 'policy>
{
    type Event = fleet::RouterEvent<'scope, 'task, 'policy>;
    fn matches_scanner(&self, scanner: &scan::Scanner<'_, '_, 'scope, 'task>) -> bool {
        fleet::Router::matches_scanner(self, scanner)
    }
    fn poll_driver(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event> {
        self.poll_next(cx)
    }
}

/// One discovery result or one connection-driver result.
#[must_use = "handle discovery outcomes and routed sockets"]
pub enum Event<T> {
    /// A completed, incomplete, or refused observation; an error stops new scans.
    Discovery(Result<scan::Outcome, scan::Error>),
    /// A connection or bounded refusal, retaining its ordinary routing semantics.
    Route(T),
}

/// Either a pump event or completion of one caller-owned operation.
#[must_use = "handle the pump event or completed operation"]
pub enum Progress<T, W> {
    /// Discovery or connection-driver event.
    Event(Event<T>),
    /// The separately pinned operation completed; do not poll it again.
    Work(W),
}

/// The exact operation and result returned by one caller-owned setup future.
#[must_use = "retain the setup outcome and reconcile any committed effect"]
pub struct SetupCompletion {
    /// Operation identity supplied to that setup, not an authorization.
    pub operation: OperationId,
    /// Original result, including any caller-owned committed permit.
    pub outcome: Result<setup::Outcome, fleet::Error>,
}

/// Whether an exact completed failure was admitted to the retry queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    /// A timer was created for a proven pre-effect or cancelled failure.
    Scheduled,
    /// The result did not identify an eligible failure.
    NotEligible,
    /// This camera already had a timer; its existing timer remains owned.
    AlreadyScheduled,
    /// The timer could not be admitted; the completion remains caller-owned.
    Refused(retry::Error),
}

/// A discovery, route, retry or completed camera setup from the shared loop.
#[must_use = "handle every event and retain setup outcomes"]
pub enum Coordinated<T> {
    /// Existing discovery or connection event.
    Event(Event<T>),
    /// A timer completed; rearming does not itself launch a setup.
    Retry(retry::Event),
    /// Setup completed; its original result and scheduling disposition remain owned.
    Setup {
        /// Owner inventory index of this work item.
        index: usize,
        /// Original setup result and operation identity.
        completion: SetupCompletion,
        /// The automatic timer admission result.
        retry: RetryDisposition,
    },
}

/// Bounded composition of an existing scanner and router, both caller-owned.
///
/// Dropping a `next` future leaves in-flight work here. Requesting scan stop
/// prevents new windows and lets an existing window finish; continue polling
/// until `scan_drained` before dropping this pump for an orderly stop. Dropping
/// the pump during a probe interrupts the scanner, and dropping the router
/// closes its retained sockets. No detached task or automatic restart exists.
pub struct Pump<'pump, 'fleet, 'report, 'scope, 'task, D: Driver<'scope, 'task>> {
    scanner: &'pump scan::Scanner<'fleet, 'report, 'scope, 'task>,
    driver: &'pump mut D,
    scan: Option<ScanFuture<'pump>>,
    start_scans: bool,
    prefer_scan: bool,
    prefer_work: bool,
    prefer_setup: bool,
}

impl<'pump, 'fleet: 'pump, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, D: Driver<'scope, 'task>>
    Pump<'pump, 'fleet, 'report, 'scope, 'task, D>
{
    /// Compose owners only when fleet, task, runtime and clock mapping match.
    pub fn new(
        scanner: &'pump scan::Scanner<'fleet, 'report, 'scope, 'task>,
        driver: &'pump mut D,
    ) -> Result<Self, scan::Error> {
        if !driver.matches_scanner(scanner) {
            return Err(scan::Error::Configuration);
        }
        if scanner.phase() != scan::Phase::Idle {
            return Err(scan::Error::Busy);
        }
        Ok(Self {
            scanner,
            driver,
            scan: None,
            start_scans: true,
            prefer_scan: true,
            prefer_work: true,
            prefer_setup: true,
        })
    }

    /// Inspect the driver without moving or cancelling its in-flight work.
    pub fn driver(&self) -> &D {
        self.driver
    }

    /// Check that a retry queue uses this pump's exact fleet, runtime and clock.
    /// This makes no retry eligible and does not poll either owner.
    pub fn accepts_retries(&self, retries: &retry::Queue<'_, '_, 'scope, 'task>) -> bool {
        retries.matches_scanner(self.scanner)
    }

    /// Do not start another scan; an already started scan remains owned.
    pub fn request_scan_stop(&mut self) {
        self.start_scans = false;
    }

    /// Whether the requested stop has drained the current scan.
    pub fn scan_drained(&self) -> bool {
        !self.start_scans && self.scan.is_none()
    }

    /// Resume after an orderly stop or a handled error, provided the scanner
    /// is idle. Interrupted probes first require its explicit acknowledgement.
    pub fn resume_scanning(&mut self) -> Result<(), scan::Error> {
        if self.scan.is_some() || self.start_scans {
            return Err(scan::Error::Busy);
        }
        match self.scanner.phase() {
            scan::Phase::Idle => {
                self.start_scans = true;
                Ok(())
            }
            scan::Phase::Interrupted => Err(scan::Error::Interrupted),
            _ => Err(scan::Error::Busy),
        }
    }

    /// Wait for one event. Dropping this future retains the in-flight owners.
    pub async fn next(&mut self) -> Event<D::Event> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Drive one externally owned operation alongside this pump. Dropping the
    /// returned future preserves both owners; after `Work`, retire the completed
    /// operation instead of polling it again. The caller must handle all events
    /// and retain any operation-specific cancellation or effect trace.
    pub async fn next_with<F: Future>(
        &mut self,
        mut work: Pin<&mut F>,
    ) -> Progress<D::Event, F::Output> {
        poll_fn(|cx| self.poll_with(cx, work.as_mut())).await
    }

    /// Drive a retry timer alongside discovery and routing. A discovery or
    /// route event drops only the timer wait, not the queue's retained entry.
    /// Rearming does not itself start setup or grant camera authority.
    pub async fn next_with_retries(
        &mut self,
        retries: &mut retry::Queue<'_, '_, 'scope, 'task>,
    ) -> Result<Progress<D::Event, retry::Event>, retry::Error> {
        if !retries.matches_scanner(self.scanner) {
            return Err(retry::Error::Configuration);
        }
        let mut wait = std::pin::pin!(retries.next());
        match self.next_with(wait.as_mut()).await {
            Progress::Event(event) => Ok(Progress::Event(event)),
            Progress::Work(result) => result.map(Progress::Work),
        }
    }

    /// Drive setup work, retry timers, discovery and routing without detached
    /// tasks. A returned eligible setup failure is scheduled automatically
    /// only when its exact operation still matches the queue's fleet marker.
    /// Every original completion is returned even if timer admission fails.
    /// The caller still owns credentials, transport creation and starting the
    /// next setup when a timer rearms an eligible camera.
    pub async fn next_coordinated(
        &mut self,
        work: &mut CameraWorkSet<'_, SetupCompletion>,
        retries: &mut retry::Queue<'_, '_, 'scope, 'task>,
    ) -> Result<Coordinated<D::Event>, retry::Error> {
        if !retries.matches_scanner(self.scanner) {
            return Err(retry::Error::Configuration);
        }
        enum Selected<T> {
            Event(Event<T>),
            Retry(retry::Event),
            Setup(usize, SetupCompletion),
        }
        let prefer_setup = self.prefer_setup;
        let selected = {
            let mut setup = std::pin::pin!(work.next());
            if retries.is_empty() {
                match self.next_with(setup.as_mut()).await {
                    Progress::Event(event) => Selected::Event(event),
                    Progress::Work((index, completion)) => Selected::Setup(index, completion),
                }
            } else {
                let mut pump = std::pin::pin!(self.next_with_retries(retries));
                poll_fn(|cx| {
                    if prefer_setup {
                        if let Poll::Ready((index, result)) = setup.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Selected::Setup(index, result)));
                        }
                    }
                    if let Poll::Ready(result) = pump.as_mut().poll(cx) {
                        return Poll::Ready(result.map(|progress| match progress {
                            Progress::Event(event) => Selected::Event(event),
                            Progress::Work(event) => Selected::Retry(event),
                        }));
                    }
                    if !prefer_setup {
                        if let Poll::Ready((index, result)) = setup.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Selected::Setup(index, result)));
                        }
                    }
                    Poll::Pending
                })
                .await?
            }
        };
        self.prefer_setup = !matches!(&selected, Selected::Setup(..));
        Ok(match selected {
            Selected::Event(event) => Coordinated::Event(event),
            Selected::Retry(event) => Coordinated::Retry(event),
            Selected::Setup(index, completion) => {
                let disposition = if matches!(&completion.outcome, Err(fleet::Error::Setup(_))) {
                    match retries.schedule_automatic_for(index, &completion.operation) {
                        Ok(()) => RetryDisposition::Scheduled,
                        Err(retry::Error::NotEligible) => RetryDisposition::NotEligible,
                        Err(retry::Error::Duplicate) => RetryDisposition::AlreadyScheduled,
                        Err(reason) => RetryDisposition::Refused(reason),
                    }
                } else {
                    RetryDisposition::NotEligible
                };
                Coordinated::Setup {
                    index,
                    completion,
                    retry: disposition,
                }
            }
        })
    }

    /// Poll the operation and pump with alternating first preference after
    /// each returned result, without spawning a task or dropping either owner.
    pub fn poll_with<F: Future>(
        &mut self,
        cx: &mut Context<'_>,
        mut work: Pin<&mut F>,
    ) -> Poll<Progress<D::Event, F::Output>> {
        if self.prefer_work {
            if let Poll::Ready(value) = work.as_mut().poll(cx) {
                self.prefer_work = false;
                return Poll::Ready(Progress::Work(value));
            }
            if let Poll::Ready(event) = self.poll_next(cx) {
                self.prefer_work = true;
                return Poll::Ready(Progress::Event(event));
            }
        } else {
            if let Poll::Ready(event) = self.poll_next(cx) {
                self.prefer_work = true;
                return Poll::Ready(Progress::Event(event));
            }
            if let Poll::Ready(value) = work.as_mut().poll(cx) {
                self.prefer_work = false;
                return Poll::Ready(Progress::Work(value));
            }
        }
        Poll::Pending
    }

    fn poll_scan(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        if self.scan.is_none() && self.start_scans {
            self.scan = Some(Box::pin(self.scanner.next()));
        }
        if let Some(scan) = self.scan.as_mut() {
            if let Poll::Ready(result) = scan.as_mut().poll(cx) {
                self.scan = None;
                if result.is_err() {
                    self.start_scans = false;
                }
                self.prefer_scan = false;
                return Poll::Ready(Event::Discovery(result));
            }
        }
        Poll::Pending
    }

    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        match self.driver.poll_driver(cx) {
            Poll::Ready(event) => {
                self.prefer_scan = true;
                Poll::Ready(Event::Route(event))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll both owners with alternating first preference after each event.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        if self.prefer_scan {
            if let Poll::Ready(event) = self.poll_scan(cx) {
                return Poll::Ready(event);
            }
            self.poll_route(cx)
        } else {
            if let Poll::Ready(event) = self.poll_route(cx) {
                return Poll::Ready(event);
            }
            self.poll_scan(cx)
        }
    }
}
