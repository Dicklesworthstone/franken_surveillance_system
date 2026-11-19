#![forbid(unsafe_code)]
//! Caller-driven composition of paged discovery, routing, and setup retries.
//!
//! This loop owns no task, credentials, enrollment, or camera effect. The
//! caller drives it and handles every observation and setup completion.

use super::{fleet, pump, retry, sweep};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

type SweepFuture<'a> = Pin<Box<dyn Future<Output = Result<sweep::Step, sweep::Error>> + 'a>>;

/// A caller-owned routing driver bound to the exact sweep, task and fleet.
pub trait Driver<'scope, 'task> {
    /// One retained routing event.
    type Event;
    /// Check local owner bindings; this does not authenticate a peer.
    fn matches_sweep(
        &self,
        runner: &sweep::Runner<'scope, 'task>,
        fleet: &fleet::Fleet<'_>,
    ) -> bool;
    /// Poll without discarding in-flight routes.
    fn poll_driver(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event>;
}

impl<'fleet, 'report: 'fleet, 'scope: 'fleet, 'task: 'fleet, 'policy: 'fleet> Driver<'scope, 'task>
    for fleet::Router<'fleet, 'report, 'scope, 'task, 'policy>
{
    type Event = fleet::RouterEvent<'scope, 'task, 'policy>;
    fn matches_sweep(
        &self,
        runner: &sweep::Runner<'scope, 'task>,
        fleet: &fleet::Fleet<'_>,
    ) -> bool {
        fleet::Router::matches_sweep(self, runner, fleet)
    }
    fn poll_driver(&mut self, cx: &mut Context<'_>) -> Poll<Self::Event> {
        self.poll_next(cx)
    }
}

/// A discovery step or a routed connection.
#[must_use = "handle the observation or routed connection"]
pub enum Event<T> {
    /// A completed window, completed sweep, partial window, or refusal.
    Discovery(Result<sweep::Step, sweep::Error>),
    /// The routing driver's original event.
    Route(T),
}

/// An event or one separately owned operation's completion.
#[must_use = "handle the event or operation completion"]
pub enum Progress<T, W> {
    /// A discovery or routing event.
    Event(Event<T>),
    /// The exact completion of the supplied future.
    Work(W),
}

/// One result from the coordinated sweep, routing, retry and setup loop.
#[must_use = "handle the event and retain setup outcomes"]
pub enum Coordinated<T> {
    /// A discovery or routing event.
    Event(Event<T>),
    /// A retry timer completed without starting a camera operation.
    Retry(retry::Event),
    /// The exact setup completion and its retry admission outcome.
    Setup {
        /// Owner inventory index.
        index: usize,
        /// Original completion, including any effect permit.
        completion: pump::SetupCompletion,
        /// Whether the failure was admitted to the retry queue.
        retry: pump::RetryDisposition,
    },
}

/// Compose one sweep with an existing router. Stopping drains an active window
/// but does not discard an unfinished cycle. Dropping this owner with a window
/// in flight interrupts that window; callers must account for its outcome.
pub struct Pump<'pump, 'report, 'scope, 'task, D: Driver<'scope, 'task>> {
    runner: &'pump sweep::Runner<'scope, 'task>,
    fleet: &'pump fleet::Fleet<'report>,
    driver: &'pump mut D,
    sweep: Option<SweepFuture<'pump>>,
    start_windows: bool,
    prefer_sweep: bool,
    prefer_work: bool,
    prefer_setup: bool,
}

impl<'pump, 'report: 'pump, 'scope: 'pump, 'task: 'pump, D: Driver<'scope, 'task>>
    Pump<'pump, 'report, 'scope, 'task, D>
{
    /// Inspect the driver without interrupting its retained connections.
    pub fn driver(&self) -> &D {
        self.driver
    }

    /// Refuse mismatched owners, scopes, or an already active window.
    pub fn new(
        runner: &'pump sweep::Runner<'scope, 'task>,
        fleet: &'pump fleet::Fleet<'report>,
        driver: &'pump mut D,
    ) -> Result<Self, sweep::Error> {
        if !runner.accepts_fleet(fleet) || !driver.matches_sweep(runner, fleet) {
            return Err(sweep::Error::Configuration);
        }
        if runner.phase() != sweep::Phase::Idle {
            return Err(sweep::Error::Busy);
        }
        Ok(Self {
            runner,
            fleet,
            driver,
            sweep: None,
            start_windows: true,
            prefer_sweep: true,
            prefer_work: true,
            prefer_setup: true,
        })
    }

    /// Do not start a further window; a window already owned is drained.
    pub fn request_sweep_stop(&mut self) {
        self.start_windows = false;
    }

    /// Whether the requested stop has drained its in-flight window.
    pub fn sweep_drained(&self) -> bool {
        !self.start_windows && self.sweep.is_none()
    }

    /// Resume a retained, idle cycle after an orderly stop.
    pub fn resume_sweeping(&mut self) -> Result<(), sweep::Error> {
        if self.start_windows || self.sweep.is_some() {
            return Err(sweep::Error::Busy);
        }
        if !self.runner.accepts_fleet(self.fleet) {
            return Err(sweep::Error::WrongFleet);
        }
        match self.runner.phase() {
            sweep::Phase::Idle => {
                self.start_windows = true;
                Ok(())
            }
            sweep::Phase::Interrupted => Err(sweep::Error::Interrupted),
            _ => Err(sweep::Error::Busy),
        }
    }

    /// Check the exact task, clock and fleet of a retry queue.
    pub fn accepts_retries(&self, retries: &retry::Queue<'_, '_, 'scope, 'task>) -> bool {
        retries.matches_sweep(self.runner, self.fleet)
    }

    fn poll_sweep(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        if self.sweep.is_none() && self.start_windows {
            self.sweep = Some(Box::pin(self.runner.next(Some(self.fleet))));
        }
        if let Some(active) = self.sweep.as_mut() {
            if let Poll::Ready(result) = active.as_mut().poll(cx) {
                self.sweep = None;
                if matches!(
                    &result,
                    Err(_)
                        | Ok(sweep::Step::Incomplete { .. })
                        | Ok(sweep::Step::Finished {
                            refresh: Some(Err(_)),
                            ..
                        })
                ) {
                    self.start_windows = false;
                }
                self.prefer_sweep = false;
                return Poll::Ready(Event::Discovery(result));
            }
        }
        Poll::Pending
    }

    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        match self.driver.poll_driver(cx) {
            Poll::Ready(event) => {
                self.prefer_sweep = true;
                Poll::Ready(Event::Route(event))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll both owners with alternating first preference after each event.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Event<D::Event>> {
        if self.prefer_sweep {
            if let Poll::Ready(event) = self.poll_sweep(cx) {
                return Poll::Ready(event);
            }
            self.poll_route(cx)
        } else {
            if let Poll::Ready(event) = self.poll_route(cx) {
                return Poll::Ready(event);
            }
            self.poll_sweep(cx)
        }
    }

    /// Drive until one sweep or route event is available.
    pub async fn next(&mut self) -> Event<D::Event> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Poll an external owned operation alongside the sweep and router.
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

    /// Drive an externally owned future alongside discovery and routing.
    pub async fn next_with<F: Future>(
        &mut self,
        mut work: Pin<&mut F>,
    ) -> Progress<D::Event, F::Output> {
        poll_fn(|cx| self.poll_with(cx, work.as_mut())).await
    }

    /// Drive a retry timer without losing it when another event wins.
    pub async fn next_with_retries(
        &mut self,
        retries: &mut retry::Queue<'_, '_, 'scope, 'task>,
    ) -> Result<Progress<D::Event, retry::Event>, retry::Error> {
        if !self.accepts_retries(retries) {
            return Err(retry::Error::Configuration);
        }
        let mut wait = std::pin::pin!(retries.next());
        match self.next_with(wait.as_mut()).await {
            Progress::Event(event) => Ok(Progress::Event(event)),
            Progress::Work(result) => result.map(Progress::Work),
        }
    }

    /// Drive setup completions, retries, paged discovery and routing together.
    /// The caller still starts setup work and supplies authentication and authority.
    pub async fn next_coordinated(
        &mut self,
        work: &mut pump::CameraWorkSet<'_, pump::SetupCompletion>,
        retries: &mut retry::Queue<'_, '_, 'scope, 'task>,
    ) -> Result<Coordinated<D::Event>, retry::Error> {
        if !self.accepts_retries(retries) {
            return Err(retry::Error::Configuration);
        }
        enum Selected<T> {
            Event(Event<T>),
            Retry(retry::Event),
            Setup(usize, pump::SetupCompletion),
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
                let mut active = std::pin::pin!(self.next_with_retries(retries));
                poll_fn(|cx| {
                    if prefer_setup {
                        if let Poll::Ready((index, value)) = setup.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Selected::Setup(index, value)));
                        }
                    }
                    if let Poll::Ready(result) = active.as_mut().poll(cx) {
                        return Poll::Ready(result.map(|progress| match progress {
                            Progress::Event(event) => Selected::Event(event),
                            Progress::Work(event) => Selected::Retry(event),
                        }));
                    }
                    if !prefer_setup {
                        if let Poll::Ready((index, value)) = setup.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Selected::Setup(index, value)));
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
                let retry = if matches!(&completion.outcome, Err(fleet::Error::Setup(_))) {
                    match retries.schedule_automatic_for(index, &completion.operation) {
                        Ok(()) => pump::RetryDisposition::Scheduled,
                        Err(retry::Error::NotEligible) => pump::RetryDisposition::NotEligible,
                        Err(retry::Error::Duplicate) => pump::RetryDisposition::AlreadyScheduled,
                        Err(reason) => pump::RetryDisposition::Refused(reason),
                    }
                } else {
                    pump::RetryDisposition::NotEligible
                };
                Coordinated::Setup {
                    index,
                    completion,
                    retry,
                }
            }
        })
    }
}
