#![forbid(unsafe_code)]
//! Task-bound, bounded rearming of setup failures known to precede an effect.
//!
//! Rearming makes an enrolled camera eligible for a new owner-authorized
//! setup; it does not acquire credentials, create a transport or send a write.

use super::{fleet, scan};
use crate::unifi_direct::metered::MeteredClock;
use asupersync::{Cx, time::sleep_until, types::Time};
use fss_core::OperationId;
use fss_runtime::execution::TaskCx;
use std::{rc::Rc, time::Duration};

const MIN_DELAY: Duration = Duration::from_millis(10);
const MAX_DELAY: Duration = Duration::from_secs(60 * 60);
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Finite exponential retry delay and maximum number of retries per camera.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    initial: Duration,
    maximum: Duration,
    max_retries: usize,
}
impl Policy {
    /// A delay is always positive; at most 15 retries follow the first attempt.
    pub fn new(initial: Duration, maximum: Duration, max_retries: usize) -> Result<Self, Error> {
        if initial < MIN_DELAY
            || maximum < initial
            || maximum > MAX_DELAY
            || !(1..=15).contains(&max_retries)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            initial,
            maximum,
            max_retries,
        })
    }
    fn delay(self, attempts: usize) -> Duration {
        let factor = 1u32
            .checked_shl((attempts - 1).min(31) as u32)
            .unwrap_or(u32::MAX);
        self.initial
            .checked_mul(factor)
            .unwrap_or(self.maximum)
            .min(self.maximum)
    }
}

/// A payload-free scheduling refusal; no camera effect is dispatched here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The task/clock binding or bounded policy is invalid.
    Configuration,
    /// The task was cancelled, expired, or its clock could not be read.
    Authority,
    /// No proven pre-effect failure matches the requested entry.
    NotEligible,
    /// This exact camera already has a pending retry.
    Duplicate,
    /// Another operation's timer is retained for this camera.
    StalePending,
    /// The finite retry limit has been reached.
    Limit,
    /// The queue has no pending timers.
    Empty,
    /// Bounded queue storage could not be reserved.
    Allocation,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UniFi retry scheduling refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One completed timer and its effect-free fleet transition.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// A current pre-effect failure was rearmed against the latest scan.
    Rearmed { index: usize, state: fleet::State },
    /// The original failed operation is no longer the current retry candidate.
    Stale { index: usize },
    /// Fleet capacity or another explicit precondition refused rearming.
    Refused { index: usize, reason: fleet::Error },
}

struct Entry {
    index: usize,
    operation: OperationId,
    due: u64,
}

/// Retained retry timers; dropping a wait future does not discard them.
/// Dropping this queue explicitly abandons only timers, not effect obligations.
pub struct Queue<'fleet, 'report, 'scope, 'task> {
    fleet: &'fleet fleet::Fleet<'report>,
    owner: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    policy: Policy,
    pending: Vec<Entry>,
}
impl<'fleet, 'report, 'scope, 'task> Queue<'fleet, 'report, 'scope, 'task> {
    /// Bind the queue to the same task and clock as discovery and routing.
    pub fn new(
        fleet: &'fleet fleet::Fleet<'report>,
        owner: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        policy: Policy,
    ) -> Result<Self, Error> {
        if !cx.has_timer() || !clock.matches(owner, cx) {
            return Err(Error::Configuration);
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(fleet::MAX_INVENTORY)
            .map_err(|_| Error::Allocation)?;
        let queue = Self {
            fleet,
            owner,
            cx,
            clock,
            policy,
            pending,
        };
        queue.check()?;
        Ok(queue)
    }

    fn check(&self) -> Result<(), Error> {
        let now = self.clock.now().map_err(|_| Error::Authority)?;
        if self
            .owner
            .context()
            .deadline
            .is_some_and(|deadline| now.0 >= deadline.0)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub(super) fn matches_scanner(&self, scanner: &scan::Scanner<'_, '_, 'scope, 'task>) -> bool {
        Rc::ptr_eq(&self.fleet.identity(), &scanner.fleet_identity())
            && self.clock.same_mapping(&scanner.clock())
            && scanner.matches_context(self.cx)
    }

    /// Number of still-owned timers.
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    /// Whether there are no scheduled retries.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Schedule the exact latest completed pre-effect failure. The operation
    /// is checked again on expiry so a stale timer cannot rearm a later attempt.
    pub fn schedule(&mut self, index: usize) -> Result<(), Error> {
        self.check()?;
        if self.pending.iter().any(|entry| entry.index == index) {
            return Err(Error::Duplicate);
        }
        let (operation, attempts) = self
            .fleet
            .retry_candidate(index)
            .ok_or(Error::NotEligible)?;
        if attempts > self.policy.max_retries {
            return Err(Error::Limit);
        }
        let ns = u64::try_from(self.policy.delay(attempts).as_nanos())
            .map_err(|_| Error::Configuration)?;
        let due = self
            .cx
            .now()
            .as_nanos()
            .checked_add(ns)
            .ok_or(Error::Configuration)?;
        self.pending.push(Entry {
            index,
            operation: operation.clone(),
            due,
        });
        Ok(())
    }

    /// Schedule only if the current pre-effect failure belongs to this exact
    /// completed operation. A different or stale completion is not eligible.
    pub fn schedule_for(&mut self, index: usize, operation: &OperationId) -> Result<(), Error> {
        if self
            .fleet
            .retry_candidate(index)
            .is_none_or(|(current, _)| current != operation)
        {
            return Err(Error::NotEligible);
        }
        if self
            .pending
            .iter()
            .any(|entry| entry.index == index && &entry.operation != operation)
        {
            return Err(Error::StalePending);
        }
        self.schedule(index)
    }

    /// Wait for and revalidate one retry. A pending route delays rearming;
    /// cancellation leaves all pending entries with this queue's owner.
    pub async fn next(&mut self) -> Result<Event, Error> {
        loop {
            self.check()?;
            let index = self
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| (e.due, e.index))
                .map(|(index, _)| index)
                .ok_or(Error::Empty)?;
            let now = self.cx.now().as_nanos();
            let due = self.pending[index].due;
            if now < due {
                let quantum = u64::try_from(CANCEL_POLL.as_nanos()).expect("bounded quantum");
                sleep_until(Time::from_nanos(due.min(now.saturating_add(quantum)))).await;
                continue;
            }
            let entry = &self.pending[index];
            if self
                .fleet
                .retry_candidate(entry.index)
                .is_none_or(|(op, _)| op != &entry.operation)
            {
                let entry = self.pending.remove(index);
                return Ok(Event::Stale { index: entry.index });
            }
            match self.fleet.rearm_matching(entry.index, &entry.operation) {
                Ok(state) => {
                    let entry = self.pending.remove(index);
                    return Ok(Event::Rearmed {
                        index: entry.index,
                        state,
                    });
                }
                Err(fleet::Error::RetryNotSafe) => {
                    let delay = u64::try_from(self.policy.initial.as_nanos())
                        .map_err(|_| Error::Configuration)?;
                    self.pending[index].due = now.checked_add(delay).ok_or(Error::Configuration)?;
                }
                Err(reason) => {
                    let entry = self.pending.remove(index);
                    return Ok(Event::Refused {
                        index: entry.index,
                        reason,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_configuration_refuses_unbounded_retries() {
        let policy = Policy::new(Duration::from_millis(20), Duration::from_millis(75), 3).unwrap();
        assert_eq!(policy.delay(1), Duration::from_millis(20));
        assert_eq!(policy.delay(2), Duration::from_millis(40));
        assert_eq!(policy.delay(3), Duration::from_millis(75));
        assert!(matches!(
            Policy::new(Duration::ZERO, Duration::from_secs(1), 1),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Policy::new(Duration::from_millis(10), Duration::from_secs(1), 16),
            Err(Error::Configuration)
        ));
    }
}
