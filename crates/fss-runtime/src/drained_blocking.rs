#![forbid(unsafe_code)]
//! Region-owned drain for a bounded Asupersync 0.5 blocking-pool handoff.
//!
//! Unlike the ordinary cancellation-dominant blocking wrapper, this owner
//! waits for the submitted closure to return or be destroyed before reporting
//! its work outcome. Cancellation before pool claim returns the unstarted
//! closure. A running closure receives its child `Cx` and must cooperate.
//! Callers must join or explicitly transfer the owner before finalization.

use std::{
    future::poll_fn,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use asupersync::{
    Cx,
    runtime::{JoinError, SpawnError, TaskHandle},
};

struct Signal {
    done: AtomicBool,
    cancellation_observed: AtomicBool,
    waiters: Mutex<[Option<Waker>; 2]>,
}
impl Signal {
    fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            cancellation_observed: AtomicBool::new(false),
            waiters: Mutex::new([None, None]),
        }
    }
    fn finish(&self) {
        self.done.store(true, Ordering::Release);
        let wake = self
            .waiters
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .each_mut()
            .map(Option::take);
        for wake in wake.into_iter().flatten() {
            wake.wake();
        }
    }
    fn poll(&self, cx: &mut Context<'_>, lane: usize) -> Poll<()> {
        if self.done.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        // Waker clone/drop can invoke caller-provided code. Keep both outside
        // the lock so a reentrant waker cannot deadlock completion.
        let incoming = cx.waker().clone();
        let mut waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.done.load(Ordering::Acquire) {
            drop(waiters);
            drop(incoming);
            return Poll::Ready(());
        }
        let old = waiters[lane].replace(incoming);
        drop(waiters);
        drop(old);
        Poll::Pending
    }
}

// This token moves into the pool closure. It also fires if a queued closure is
// cancelled and dropped without being invoked, or if task admission fails.
struct Finish(Arc<Signal>);
impl Drop for Finish {
    fn drop(&mut self) {
        self.0.finish();
    }
}

struct Slot<F, R> {
    work: Option<F>,
    result: Option<std::thread::Result<R>>,
}

/// Why an operation was not admitted to a runtime-owned blocking pool.
#[derive(Debug)]
pub enum StartFailure {
    /// The caller context has no admissible pool.
    NoPool,
    /// Cancellation was already visible.
    Cancelled,
    /// The runtime refused a new region-owned coordinator task.
    Spawn(SpawnError),
}

/// A refusal preserves the submitted closure when it never left this caller.
#[must_use]
pub struct StartRefusal<F> {
    /// Payload-free refusal reason.
    pub reason: StartFailure,
    /// Original unstarted closure, if recoverable.
    pub work: Option<F>,
}

/// Exact closure outcome after the worker boundary has drained.
#[must_use]
pub enum WorkOutcome<F, R> {
    /// The pool never invoked the original closure.
    NotStarted(F),
    /// The closure returned this exact value.
    Finished(R),
    /// The closure panicked; external effects may be indeterminate.
    Panicked,
    /// Internal state was inconsistent; external effects may be indeterminate.
    Indeterminate,
}

/// Independent runtime classification and drained closure outcome.
#[must_use]
pub struct Receipt<F, R> {
    /// The region task's actual terminal result.
    pub runtime: Result<(), JoinError>,
    /// Whether the pool invoked the closure and what it returned.
    pub work: WorkOutcome<F, R>,
}

/// Owns a region task until the pool closure has actually been released.
#[must_use = "join to observe worker retirement and recover its outcome"]
pub struct Drained<F, R> {
    task: TaskHandle<()>,
    slot: Arc<Mutex<Slot<F, R>>>,
    signal: Arc<Signal>,
    joined: bool,
}

/// Start a single bounded blocking operation without an inline fallback.
/// The caller supplies the runtime-owned context and retains the returned owner.
pub fn start<F, R>(cx: &Cx, work: F) -> Result<Drained<F, R>, StartRefusal<F>>
where
    F: FnOnce(Cx) -> R + Send + 'static,
    R: Send + 'static,
{
    if cx.checkpoint().is_err() {
        return Err(StartRefusal {
            reason: StartFailure::Cancelled,
            work: Some(work),
        });
    }
    let Some(pool) = cx.blocking_pool_handle() else {
        return Err(StartRefusal {
            reason: StartFailure::NoPool,
            work: Some(work),
        });
    };
    let slot = Arc::new(Mutex::new(Slot {
        work: Some(work),
        result: None,
    }));
    let signal = Arc::new(Signal::new());
    let finish = Finish(Arc::clone(&signal));
    let worker_slot = Arc::clone(&slot);
    let worker_signal = Arc::clone(&signal);
    let started = cx.spawn(move |child| async move {
        let worker_child = child.clone();
        let task = pool.spawn(move || {
            let _finish = finish;
            if worker_child.checkpoint().is_err() {
                return;
            }
            let work = worker_slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .work
                .take();
            if let Some(work) = work {
                let result = catch_unwind(AssertUnwindSafe(|| work(worker_child)));
                worker_slot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .result = Some(result);
            }
        });
        poll_fn(|context| {
            if child.checkpoint().is_err() {
                task.cancel();
                worker_signal
                    .cancellation_observed
                    .store(true, Ordering::Release);
            }
            worker_signal.poll(context, 0)
        })
        .await;
    });
    match started {
        Ok(task) => Ok(Drained {
            task,
            slot,
            signal,
            joined: false,
        }),
        Err(reason) => {
            let work = slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .work
                .take();
            Err(StartRefusal {
                reason: StartFailure::Spawn(reason),
                work,
            })
        }
    }
}

impl<F, R> Drained<F, R> {
    /// Request cooperative cancellation. Join still waits for actual release.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Whether the coordinator observed cancellation and fenced queued work.
    pub fn cancellation_observed(&self) -> bool {
        self.signal.cancellation_observed.load(Ordering::Acquire)
    }

    /// Wait for both closure release and task retirement. Dropping this
    /// borrowing wait does not discard the work and can be retried.
    /// Returns `None` only if this owner was already joined.
    pub async fn join(&mut self) -> Option<Receipt<F, R>> {
        if self.joined {
            return None;
        }
        poll_fn(|cx| self.signal.poll(cx, 1)).await;
        let runtime = poll_fn(|cx| self.task.poll_join(cx)).await;
        let (pending, result) = {
            let mut slot = self.slot.lock().unwrap_or_else(|error| error.into_inner());
            (slot.work.take(), slot.result.take())
        };
        let work = match (pending, result) {
            (Some(work), None) => WorkOutcome::NotStarted(work),
            (None, Some(Ok(result))) => WorkOutcome::Finished(result),
            (None, Some(Err(_))) => WorkOutcome::Panicked,
            _ => WorkOutcome::Indeterminate,
        };
        self.joined = true;
        Some(Receipt { runtime, work })
    }
}

impl<F, R> Drop for Drained<F, R> {
    fn drop(&mut self) {
        if !self.joined {
            self.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Weak, atomic::AtomicUsize};
    use std::task::Wake;

    struct ReentrantWake {
        signal: Weak<Signal>,
        wakes: AtomicUsize,
    }
    impl Wake for ReentrantWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let signal = self.signal.upgrade().expect("signal exists");
            let _guard = signal
                .waiters
                .try_lock()
                .expect("wake must occur outside lock");
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn completion_wakes_both_waiters_without_holding_the_lock() {
        let signal = Arc::new(Signal::new());
        let probe = Arc::new(ReentrantWake {
            signal: Arc::downgrade(&signal),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut cx = Context::from_waker(&waker);
        assert!(signal.poll(&mut cx, 0).is_pending());
        assert!(signal.poll(&mut cx, 1).is_pending());
        signal.finish();
        assert_eq!(probe.wakes.load(Ordering::Relaxed), 2);
        assert!(signal.poll(&mut cx, 0).is_ready());
        assert!(signal.poll(&mut cx, 1).is_ready());
    }
}
