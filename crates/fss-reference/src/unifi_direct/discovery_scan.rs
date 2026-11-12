#![forbid(unsafe_code)]
//! Caller-driven periodic discovery for an existing UniFi fleet.
//!
//! This owner spawns no background task and never provisions a camera. A
//! caller must keep polling it, supervise returned outcomes, and independently
//! authenticate and authorize any setup. An interrupted UDP observation does
//! not prove whether a query was sent or whether a camera exists.

use super::{Config, Report, Stop, fleet};
use crate::unifi_direct::metered::MeteredClock;
use asupersync::{
    Cx,
    time::{sleep_until, timeout},
    types::Time,
};
use fss_runtime::execution::TaskCx;
use std::{cell::Cell, fmt, rc::Rc, time::Duration};

const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
// The pinned runtime's timer uses ambient cancellation, which may not be the
// explicit task Cx supplied to this owner. Bound how long we go without
// checking that exact Cx even when its cancellation does not wake the timer.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Observable local progress; no variant proves a camera received a query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No next-window future is active.
    Idle,
    /// Waiting for the configured interval before beginning a query.
    Waiting,
    /// A bounded discovery operation is being driven.
    Probing,
    /// A probing future was dropped; the outcome is not known.
    Interrupted,
}

/// An observation result. No result authenticates a camera or proves absence.
#[must_use = "inspect the discovery result and retain incomplete reports"]
pub enum Outcome {
    /// A completed window was installed and is retained as an exact snapshot.
    Updated(Rc<fleet::DiscoverySnapshot>),
    /// A partial window was retained without replacing the current fleet view.
    Incomplete(Report),
}

/// A payload-free scanner failure, except for an explicitly returned report.
#[derive(Debug)]
pub enum Error {
    /// Interval, timer, or task-clock binding is invalid.
    Configuration,
    /// The parked scanner belongs to a different fleet instance.
    WrongFleet,
    /// Another next-window future is already owned by this scanner.
    Busy,
    /// A dropped probing future requires explicit acknowledgement.
    Interrupted,
    /// Runtime cancellation or the canonical task deadline stopped progress.
    Authority,
    /// The task-bound clock could not be read.
    Clock,
    /// The underlying bounded network discovery failed.
    Discovery(super::Error),
    /// A completed report was refused and remains caller-owned.
    Refresh(fleet::RefreshRefusal),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi periodic discovery stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

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

/// One explicitly scoped fleet scanner. The interval starts after each
/// completed attempt, preventing catch-up bursts after a slow scan.
#[must_use = "supervise each observation and any interrupted attempt"]
pub struct Scanner<'fleet, 'report, 'scope, 'task> {
    fleet: &'fleet fleet::Fleet<'report>,
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    config: Config,
    interval: Duration,
    next_due: Cell<Option<Time>>,
    phase: Cell<Phase>,
}

/// A scanner schedule detached from its fleet while inventory is updated.
/// This token is local to its original fleet, task and runtime; it carries no
/// credential or setup authority. Interrupted observations stay interrupted.
#[must_use = "resume or explicitly discard the scanner schedule"]
pub struct Parked<'scope, 'task> {
    identity: Rc<()>,
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    config: Config,
    interval: Duration,
    next_due: Option<Time>,
    phase: Phase,
}

impl<'scope, 'task> Parked<'scope, 'task> {
    /// Reattach to the same fleet without resetting the next due time.
    /// A refusal returns the unchanged token for reconciliation or retry.
    pub fn resume<'fleet, 'report>(
        self,
        fleet: &'fleet fleet::Fleet<'report>,
    ) -> Result<Scanner<'fleet, 'report, 'scope, 'task>, (Error, Self)> {
        if !Rc::ptr_eq(&self.identity, &fleet.identity()) {
            return Err((Error::WrongFleet, self));
        }
        if !self.clock.matches(self.owner, self.cx) || !self.cx.has_timer() {
            return Err((Error::Configuration, self));
        }
        if self.cx.checkpoint().is_err() {
            return Err((Error::Authority, self));
        }
        Ok(Scanner {
            fleet,
            owner: self.owner,
            cx: self.cx,
            clock: self.clock,
            config: self.config,
            interval: self.interval,
            next_due: Cell::new(self.next_due),
            phase: Cell::new(self.phase),
        })
    }
}

impl<'fleet, 'report, 'scope, 'task> Scanner<'fleet, 'report, 'scope, 'task> {
    pub(super) fn fleet_identity(&self) -> Rc<()> {
        self.fleet.identity()
    }

    pub(super) fn clock(&self) -> MeteredClock<'scope, 'task> {
        self.clock
    }

    /// Whether this scanner uses the exact supplied runtime context.
    pub fn matches_context(&self, cx: &Cx) -> bool {
        std::ptr::eq(self.cx, cx)
    }

    /// Release the fleet borrow while retaining the schedule and any
    /// interrupted observation. A live `next` future prevents this move.
    pub fn park(self) -> Parked<'scope, 'task> {
        Parked {
            identity: self.fleet.identity(),
            owner: self.owner,
            cx: self.cx,
            clock: self.clock,
            config: self.config,
            interval: self.interval,
            next_due: self.next_due.into_inner(),
            phase: self.phase.into_inner(),
        }
    }
    /// Bind one existing task, clock, fleet, and already scoped network query.
    /// The first window is immediate; subsequent attempts are interval-spaced.
    pub fn new(
        cx: &'scope Cx,
        owner: &'scope TaskCx<'task>,
        clock: MeteredClock<'scope, 'task>,
        fleet: &'fleet fleet::Fleet<'report>,
        config: Config,
        interval: Duration,
    ) -> Result<Self, Error> {
        if interval.is_zero()
            || interval > MAX_INTERVAL
            || !cx.has_timer()
            || !clock.matches(owner, cx)
        {
            return Err(Error::Configuration);
        }
        cx.checkpoint().map_err(|_| Error::Authority)?;
        Ok(Self {
            fleet,
            owner,
            cx,
            clock,
            config,
            interval,
            next_due: Cell::new(None),
            phase: Cell::new(Phase::Idle),
        })
    }

    /// Local phase, including an interrupted future that has already dropped.
    pub fn phase(&self) -> Phase {
        self.phase.get()
    }

    fn later(&self) -> Time {
        let nanos = u64::try_from(self.interval.as_nanos()).unwrap_or(u64::MAX);
        Time::from_nanos(self.cx.now().as_nanos().saturating_add(nanos))
    }

    /// Acknowledge an interrupted observation and rearm after one interval.
    /// This does not determine whether any previous datagram was transmitted.
    pub fn acknowledge_interruption(&self) -> Result<(), Error> {
        if self.phase.get() != Phase::Interrupted {
            return Err(Error::Configuration);
        }
        self.clock.now().map_err(|_| Error::Authority)?;
        self.next_due.set(Some(self.later()));
        self.phase.set(Phase::Idle);
        Ok(())
    }

    /// Drive the next scoped observation without spawning a task. If this
    /// future is dropped while waiting, its due time is preserved; if dropped
    /// while probing, the scanner becomes interrupted until acknowledged.
    pub async fn next(&self) -> Result<Outcome, Error> {
        match self.phase.get() {
            Phase::Idle => (),
            Phase::Interrupted => return Err(Error::Interrupted),
            Phase::Waiting | Phase::Probing => return Err(Error::Busy),
        }
        self.phase.set(Phase::Waiting);
        let _lease = Lease(&self.phase);
        self.cx.checkpoint().map_err(|_| Error::Authority)?;
        if let Some(due) = self.next_due.get() {
            let canonical = self.clock.now().map_err(|_| Error::Clock)?;
            let deadline = match self.owner.context().deadline {
                Some(deadline) => {
                    let remaining = deadline
                        .0
                        .checked_sub(canonical.0)
                        .filter(|&n| n > 0)
                        .ok_or(Error::Authority)?;
                    let remaining = u64::try_from(remaining).unwrap_or(u64::MAX);
                    let task_deadline =
                        Time::from_nanos(self.cx.now().as_nanos().saturating_add(remaining));
                    due.min(task_deadline)
                }
                None => due,
            };
            while self.cx.now() < deadline {
                self.cx.checkpoint().map_err(|_| Error::Authority)?;
                let next = (self.cx.now() + CANCEL_POLL).min(deadline);
                sleep_until(next).await;
            }
        }
        self.cx.checkpoint().map_err(|_| Error::Authority)?;
        let now = self.clock.now().map_err(|_| Error::Clock)?;
        if self
            .owner
            .context()
            .deadline
            .is_some_and(|deadline| now.0 >= deadline.0)
        {
            return Err(Error::Authority);
        }
        self.phase.set(Phase::Probing);
        let mut probe = std::pin::pin!(super::discover(self.owner, self.cx, now, &self.config));
        let result = loop {
            if self.cx.checkpoint().is_err() {
                self.phase.set(Phase::Interrupted);
                return Err(Error::Authority);
            }
            match timeout(self.cx.now(), CANCEL_POLL, probe.as_mut()).await {
                Ok(result) => break result,
                Err(_) => continue,
            }
        };
        self.next_due.set(Some(self.later()));
        self.phase.set(Phase::Idle);
        let report = result.map_err(Error::Discovery)?;
        if report.stop != Stop::WindowElapsed {
            return Ok(Outcome::Incomplete(report));
        }
        self.fleet.refresh(report).map_err(Error::Refresh)?;
        Ok(Outcome::Updated(self.fleet.latest_snapshot()))
    }
}
