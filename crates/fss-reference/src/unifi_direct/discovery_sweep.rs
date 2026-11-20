#![forbid(unsafe_code)]
//! Caller-driven, task-owned multi-page UniFi discovery cycles.
//!
//! The caller supplies the scoped query plan and supervises each step. This
//! owner does not spawn a task, establish host coverage or device identity,
//! provision a camera, or grant setup authority.

use super::{Config, Report, Stop, SweepPage, fleet};
use crate::unifi_direct::metered::MeteredClock;
use asupersync::{
    Cx,
    time::{sleep_until, timeout},
    types::Time,
};
use fss_core::{ContentDigest, DigestAlgorithm, TimestampNs};
use fss_runtime::execution::TaskCx;
use std::{
    cell::{Cell, RefCell},
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    rc::Rc,
    time::Duration,
};

const CANCEL_POLL: Duration = Duration::from_millis(100);
const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[cfg(test)]
mod host_plan_tests {
    use super::host_plans;
    use std::{collections::BTreeSet, net::Ipv4Addr};

    #[test]
    fn covers_each_other_host_once_across_all_supported_scopes() {
        for prefix in 20..=30 {
            let mask = u32::MAX << (32 - prefix);
            let base = u32::from(Ipv4Addr::new(10, 32, 0, 0)) & mask;
            let last = base | !mask;
            for own in [base + 1, last - 1] {
                for limited in [false, true] {
                    let pages = host_plans(Ipv4Addr::from(own), prefix, 12345, limited).unwrap();
                    assert!(pages.len() <= 17);
                    let mut hosts = BTreeSet::new();
                    for page in pages {
                        assert!((1..=4).contains(&page.len()));
                        for window in page {
                            assert!(window.len() <= 64);
                            assert_eq!(*window[0].ip(), Ipv4Addr::from(last));
                            assert!(window.iter().all(|target| target.port() == 12345));
                            if limited { assert_eq!(*window[1].ip(), Ipv4Addr::BROADCAST); }
                            for target in window.iter().skip(1 + usize::from(limited)) {
                                let address = u32::from(*target.ip());
                                assert!(address > base && address < last && address != own);
                                assert!(hosts.insert(address));
                            }
                        }
                    }
                    assert_eq!(hosts.len(), usize::try_from(last - base - 2).unwrap());
                }
            }
        }
        assert!(host_plans(Ipv4Addr::new(10, 0, 0, 1), 19, 10001, false).is_err());
        assert!(host_plans(Ipv4Addr::new(10, 0, 0, 0), 24, 10001, false).is_err());
        assert!(host_plans(Ipv4Addr::new(10, 0, 0, 1), 24, 0, false).is_err());
    }
}

/// Construct bounded windows covering each usable address other than the
/// selected interface address. A planned target is not proof of delivery,
/// device absence, identity, or authority to configure a discovered device.
/// The caller must independently validate the interface and network scope.
pub fn host_plans(
    bind: Ipv4Addr,
    prefix: u8,
    port: u16,
    limited_broadcast: bool,
) -> Result<Vec<Vec<Vec<SocketAddrV4>>>, Error> {
    if !(20..=30).contains(&prefix) || port == 0 {
        return Err(Error::Configuration);
    }
    let mask = u32::MAX << (32 - prefix);
    let base = u32::from(bind) & mask;
    let host_mask = !mask;
    let own_host = u32::from(bind) & host_mask;
    if own_host == 0 || own_host == host_mask {
        return Err(Error::Configuration);
    }
    let count = usize::try_from(host_mask - 2).map_err(|_| Error::Configuration)?;
    let capacity = super::MAX_TARGETS - 1 - usize::from(limited_broadcast);
    let per_page = capacity * super::MAX_COMBINED_WINDOWS;
    let page_count = count.div_ceil(per_page);
    if page_count == 0 || page_count > super::MAX_SWEEP_PAGES {
        return Err(Error::Configuration);
    }
    let mut pages = Vec::new();
    pages.try_reserve_exact(page_count).map_err(|_| Error::Allocation)?;
    for start in (0..count).step_by(per_page) {
        let end = (start + per_page).min(count);
        let mut page = Vec::new();
        page.try_reserve_exact((end - start).div_ceil(capacity)).map_err(|_| Error::Allocation)?;
        for first in (start..end).step_by(capacity) {
            let mut targets = Vec::new();
            targets.try_reserve_exact(super::MAX_TARGETS).map_err(|_| Error::Allocation)?;
            targets.push(SocketAddrV4::new(Ipv4Addr::from(base | host_mask), port));
            if limited_broadcast {
                targets.push(SocketAddrV4::new(Ipv4Addr::BROADCAST, port));
            }
            for index in first..(first + capacity).min(end) {
                let index = u32::try_from(index).map_err(|_| Error::Configuration)?;
                let host = base + 1 + index + u32::from(index >= own_host - 1);
                targets.push(SocketAddrV4::new(Ipv4Addr::from(host), port));
            }
            page.push(targets);
        }
        pages.push(page);
    }
    Ok(pages)
}

/// State of the caller-owned sweep operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// A new step can start.
    Idle,
    /// Waiting until the next cycle is due.
    Waiting,
    /// A window is in flight.
    Probing,
    /// A window or completion was interrupted and requires reconciliation.
    Interrupted,
}

/// A bounded sweep refusal; original completed windows remain with the runner.
#[derive(Debug)]
pub enum Error {
    /// Scope, plans, task, timer, or interval were invalid.
    Configuration,
    /// A bounded allocation could not be made.
    Allocation,
    /// Another step is active.
    Busy,
    /// A different fleet, or a change between bootstrap and refresh, was supplied mid-cycle.
    WrongFleet,
    /// An earlier window or completion requires reconciliation.
    Interrupted,
    /// Runtime or canonical task authority stopped progress.
    Authority,
    /// Discovery failed; a query may have been sent.
    Discovery(super::Error),
    /// A page could not be combined from its completed windows.
    Combination(super::CombineError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi sweep stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact results of a completed cycle. Caller-supplied page scope and labels
/// remain claims, not proof of network coverage or device authentication.
#[must_use = "retain or explicitly account for the completed observations"]
pub struct Batch {
    scope: ContentDigest,
    pages: Vec<Report>,
    windows: Vec<Report>,
}
impl Batch {
    /// Original window reports in plan order.
    pub fn windows(&self) -> &[Report] {
        &self.windows
    }
    /// Combined page reports in page order.
    pub fn page_reports(&self) -> &[Report] {
        &self.pages
    }
    /// Views usable with `Fleet::from_sweep` or `Fleet::refresh_sweep`.
    pub fn pages(&self) -> Result<Vec<SweepPage<'_>>, Error> {
        page_views(self.scope, &self.pages)
    }
}

fn page_views(scope: ContentDigest, reports: &[Report]) -> Result<Vec<SweepPage<'_>>, Error> {
    let count = u8::try_from(reports.len()).map_err(|_| Error::Configuration)?;
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(reports.len())
        .map_err(|_| Error::Allocation)?;
    for (index, report) in reports.iter().enumerate() {
        pages.push(SweepPage {
            scope,
            index: index as u8,
            count,
            report,
        });
    }
    Ok(pages)
}

/// Result of one driven window. A refresh is attempted only after all windows
/// complete, and a refused refresh returns the exact combined report in its
/// error while the batch still owns all original window and page reports.
#[must_use = "inspect and retain the observation or refresh outcome"]
pub enum Step {
    /// One window completed; more windows remain.
    Progress {
        /// Zero-based page that completed.
        page: usize,
        /// Zero-based window that completed within the page.
        window: usize,
    },
    /// A partial window stopped the cycle without refreshing the fleet.
    Incomplete {
        /// Zero-based page.
        page: usize,
        /// Zero-based window within that page.
        window: usize,
        /// Exact partial report; earlier windows remain in the runner.
        report: Report,
    },
    /// Every window completed. `None` means no fleet was supplied.
    Finished {
        /// Original windows and derived page reports.
        batch: Batch,
        /// Optional actual fleet refresh result and resulting snapshot.
        refresh: Option<Result<Rc<fleet::DiscoverySnapshot>, fleet::SweepRefreshError>>,
    },
}

struct Lease<'a>(&'a Cell<Phase>);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        match self.0.get() {
            Phase::Waiting => self.0.set(Phase::Idle),
            Phase::Probing => self.0.set(Phase::Interrupted),
            Phase::Idle | Phase::Interrupted => (),
        }
    }
}

enum CycleFleet {
    None,
    Bound(Rc<()>),
}

/// A bounded sweep schedule. No background work is spawned.
#[must_use = "retain or retire all completed and interrupted observations"]
pub struct Runner<'scope, 'task> {
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    scope: ContentDigest,
    plans: Vec<Vec<Config>>,
    interval: Duration,
    next_due: Cell<Option<Time>>,
    phase: Cell<Phase>,
    page: Cell<usize>,
    window: Cell<usize>,
    completed: RefCell<Vec<Report>>,
    cycle_fleet: RefCell<Option<CycleFleet>>,
    total_windows: usize,
}

/// The exact retained state when the caller stops driving a runner.
#[must_use = "account for completed observations and any interrupted window"]
pub struct Retirement {
    /// Caller-supplied scope claim.
    pub scope: ContentDigest,
    /// Original query plans.
    pub plans: Vec<Vec<Config>>,
    /// Naturally completed windows in plan order.
    pub completed: Vec<Report>,
    /// Next page, or the interrupted page.
    pub page: usize,
    /// Next window, or the interrupted window.
    pub window: usize,
    /// Local phase when retired; interruption does not prove a query outcome.
    pub phase: Phase,
    /// `None` before the first query, otherwise whether this cycle targets a fleet.
    pub fleet_bound: Option<bool>,
}

impl<'scope, 'task> Runner<'scope, 'task> {
    pub(super) fn clock(&self) -> MeteredClock<'scope, 'task> {
        self.clock
    }

    /// Whether this runner uses the exact supplied runtime context.
    pub fn matches_context(&self, cx: &Cx) -> bool {
        std::ptr::eq(self.cx, cx)
    }

    /// Check local scope and any already-started cycle binding before a
    /// coordinator starts routing against the supplied fleet.
    pub(super) fn accepts_fleet(&self, fleet: &fleet::Fleet<'_>) -> bool {
        if fleet.sweep_scope() != Some(self.scope) {
            return false;
        }
        match &*self.cycle_fleet.borrow() {
            None => true,
            Some(CycleFleet::None) => false,
            Some(CycleFleet::Bound(identity)) => Rc::ptr_eq(identity, &fleet.identity()),
        }
    }

    /// Bind one explicit task and a bounded list of ordered page windows.
    /// Every window must share the same interface, subnet mask and resource;
    /// labels and the supplied scope do not prove target coverage or freshness.
    pub fn new(
        cx: &'scope Cx,
        owner: &'scope TaskCx<'task>,
        clock: MeteredClock<'scope, 'task>,
        scope: ContentDigest,
        plans: Vec<Vec<Config>>,
        interval: Duration,
    ) -> Result<Self, Error> {
        if plans.is_empty()
            || plans.len() > super::MAX_SWEEP_PAGES
            || plans
                .iter()
                .any(|page| page.is_empty() || page.len() > super::MAX_COMBINED_WINDOWS)
            || interval.is_zero()
            || interval > MAX_INTERVAL
            || !cx.has_timer()
            || !clock.matches(owner, cx)
            || scope.algorithm() != DigestAlgorithm::Sha256
            || scope.is_laboratory()
            || scope.bytes() == [0; 32]
        {
            return Err(Error::Configuration);
        }
        let first = &plans[0][0];
        if plans.iter().flatten().any(|plan| {
            plan.bind != first.bind || plan.mask != first.mask || plan.resource != first.resource
        }) {
            return Err(Error::Configuration);
        }
        cx.checkpoint().map_err(|_| Error::Authority)?;
        let total_windows = plans.iter().map(Vec::len).sum();
        let mut completed = Vec::new();
        completed
            .try_reserve_exact(total_windows)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            owner,
            cx,
            clock,
            scope,
            plans,
            interval,
            next_due: Cell::new(None),
            phase: Cell::new(Phase::Idle),
            page: Cell::new(0),
            window: Cell::new(0),
            completed: RefCell::new(completed),
            cycle_fleet: RefCell::new(None),
            total_windows,
        })
    }

    /// Current local state; an interrupted operation has an uncertain outcome.
    pub fn phase(&self) -> Phase {
        self.phase.get()
    }

    fn admitted_time(&self) -> Result<TimestampNs, Error> {
        self.cx.checkpoint().map_err(|_| Error::Authority)?;
        if self
            .owner
            .is_cancel_requested()
            .map_err(|_| Error::Authority)?
        {
            return Err(Error::Authority);
        }
        let now = self.clock.now().map_err(|_| Error::Authority)?;
        if self
            .owner
            .context()
            .deadline
            .is_some_and(|deadline| now.0 >= deadline.0)
        {
            return Err(Error::Authority);
        }
        Ok(now)
    }

    /// Stop driving and return all retained completed windows and plans.
    pub fn retire(self) -> Retirement {
        let fleet_bound = self
            .cycle_fleet
            .into_inner()
            .map(|binding| matches!(binding, CycleFleet::Bound(_)));
        Retirement {
            scope: self.scope,
            plans: self.plans,
            completed: self.completed.into_inner(),
            page: self.page.into_inner(),
            window: self.window.into_inner(),
            phase: self.phase.into_inner(),
            fleet_bound,
        }
    }

    /// Execute one planned window. Supplying a fleet requests refresh only
    /// after the final window; initial discovery can omit it and use the batch
    /// to construct a fleet. Each step in a cycle must supply the same fleet,
    /// or all omit it. A dropped in-flight future fences the runner.
    pub async fn next(&self, fleet: Option<&fleet::Fleet<'_>>) -> Result<Step, Error> {
        match self.phase.get() {
            Phase::Idle => (),
            Phase::Interrupted => return Err(Error::Interrupted),
            Phase::Waiting | Phase::Probing => return Err(Error::Busy),
        }
        self.phase.set(Phase::Waiting);
        let _lease = Lease(&self.phase);
        self.admitted_time()?;
        if self.page.get() == 0 && self.window.get() == 0 {
            if let Some(due) = self.next_due.get() {
                while self.cx.now() < due {
                    self.admitted_time()?;
                    sleep_until((self.cx.now() + CANCEL_POLL).min(due)).await;
                }
            }
        }
        let now = self.admitted_time()?;
        let page = self.page.get();
        let window = self.window.get();
        let config = self
            .plans
            .get(page)
            .and_then(|plans| plans.get(window))
            .ok_or(Error::Configuration)?;
        {
            let supplied = fleet.map(|fleet| fleet.identity());
            let mut bound = self.cycle_fleet.borrow_mut();
            match (&*bound, supplied) {
                (None, None) => *bound = Some(CycleFleet::None),
                (None, Some(identity)) => *bound = Some(CycleFleet::Bound(identity)),
                (Some(CycleFleet::None), None) => (),
                (Some(CycleFleet::Bound(previous)), Some(identity))
                    if Rc::ptr_eq(previous, &identity) =>
                {
                    ()
                }
                _ => return Err(Error::WrongFleet),
            }
        }
        self.phase.set(Phase::Probing);
        let mut probe = std::pin::pin!(super::discover(self.owner, self.cx, now, config));
        let result = loop {
            if self.cx.checkpoint().is_err() {
                return Err(Error::Authority);
            }
            match timeout(self.cx.now(), CANCEL_POLL, probe.as_mut()).await {
                Ok(result) => break result,
                Err(_) => continue,
            }
        };
        let report = result.map_err(Error::Discovery)?;
        if report.stop != Stop::WindowElapsed {
            self.phase.set(Phase::Interrupted);
            return Ok(Step::Incomplete {
                page,
                window,
                report,
            });
        }
        self.completed.borrow_mut().push(report);
        if window + 1 < self.plans[page].len() {
            self.window.set(window + 1);
            self.phase.set(Phase::Idle);
            return Ok(Step::Progress { page, window });
        }
        if page + 1 < self.plans.len() {
            self.page.set(page + 1);
            self.window.set(0);
            self.phase.set(Phase::Idle);
            return Ok(Step::Progress { page, window });
        }
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(self.plans.len())
            .map_err(|_| Error::Allocation)?;
        {
            let completed = self.completed.borrow();
            let mut offset = 0usize;
            for plan in &self.plans {
                let end = offset + plan.len();
                let mut refs = Vec::new();
                refs.try_reserve_exact(plan.len())
                    .map_err(|_| Error::Allocation)?;
                refs.extend(completed[offset..end].iter());
                pages.push(Report::combine_completed(&refs).map_err(Error::Combination)?);
                offset = end;
            }
        }
        let mut next_windows = Vec::new();
        next_windows
            .try_reserve_exact(self.total_windows)
            .map_err(|_| Error::Allocation)?;
        let views = page_views(self.scope, &pages)?;
        // A completed final receive is not permission to update after task
        // authority closes. The retained windows remain recoverable on refusal.
        self.admitted_time()?;
        let refresh = fleet.map(|fleet| {
            fleet
                .refresh_sweep(&views)
                .map(|()| fleet.latest_snapshot())
        });
        drop(views);
        let windows = std::mem::replace(&mut *self.completed.borrow_mut(), next_windows);
        let nanos = u64::try_from(self.interval.as_nanos()).unwrap_or(u64::MAX);
        self.next_due.set(Some(Time::from_nanos(
            self.cx.now().as_nanos().saturating_add(nanos),
        )));
        self.page.set(0);
        self.window.set(0);
        *self.cycle_fleet.borrow_mut() = None;
        self.phase.set(Phase::Idle);
        Ok(Step::Finished {
            batch: Batch {
                scope: self.scope,
                pages,
                windows,
            },
            refresh,
        })
    }
}
