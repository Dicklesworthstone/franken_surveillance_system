#![forbid(unsafe_code)]
//! Region-owned, non-detached worker groups backed by Asupersync's `Runtime` and `BlockingPool`.
//!
//! Semantic plane: `"authority"`.
//!
//! Replaces ad-hoc detached `std::thread::spawn` / `thread::Builder::new().spawn` calls with
//! bounded worker groups tied to an explicit canonical [`RegionId`] and [`WorkerCancelToken`]
//! (`asupersync::cx::Cx<asupersync::cx::cap::None>`). Every spawned worker is counted,
//! cooperatively cancelled during `request -> drain -> finalize`, and deterministically drained
//! and joined before [`ScopedWorkerGroup::drain_and_shutdown`] or `Drop` returns.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use asupersync::runtime::{BlockingPoolHandle, Runtime, RuntimeBuilder};
use fss_core::RegionId;

use crate::asupersync_ops::boundaries::{BoundaryError, CxTimerBoundary};

/// Hard ceiling on configured blocking threads for a single [`ScopedWorkerGroup`].
pub const MAX_SCOPED_GROUP_THREADS: usize = 256;

/// Typed refusal from [`ScopedWorkerGroup`] or [`ScopedRegionWorker`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopedWorkerError {
    /// Invalid thread, concurrency, name, or timeout configuration.
    InvalidBounds {
        /// Secret-free validation message.
        detail: &'static str,
    },
    /// Asupersync runtime or blocking pool construction failed.
    RuntimeBuild {
        /// Secret-free runtime construction failure description.
        detail: String,
    },
    /// Worker admission was refused because cancellation or shutdown was already requested.
    Cancelled,
    /// Worker admission was refused because active workers reached `max_active_workers`.
    CapacityReached {
        /// Configured hard cap on active workers.
        limit: usize,
    },
    /// The underlying Asupersync blocking pool is unavailable or closed.
    PoolClosed,
}

impl fmt::Display for ScopedWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBounds { detail } => write!(f, "invalid scoped worker bounds: {detail}"),
            Self::RuntimeBuild { detail } => {
                write!(
                    f,
                    "failed to initialize Asupersync worker runtime: {detail}"
                )
            }
            Self::Cancelled => f.write_str("scoped worker group is cancelling or closed"),
            Self::CapacityReached { limit } => {
                write!(f, "scoped worker group reached max_active_workers={limit}")
            }
            Self::PoolClosed => f.write_str("Asupersync blocking pool is unavailable or closed"),
        }
    }
}

impl std::error::Error for ScopedWorkerError {}

struct WorkerCancelState {
    cancelled: AtomicBool,
    cx: asupersync::cx::Cx<asupersync::cx::cap::None>,
}

/// Cooperative cancellation handle bridging an atomic fast path with an Asupersync `Cx`.
#[derive(Clone)]
pub struct WorkerCancelToken {
    inner: Arc<WorkerCancelState>,
}

impl Default for WorkerCancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WorkerCancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerCancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl WorkerCancelToken {
    /// Creates an active, uncancelled worker cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WorkerCancelState {
                cancelled: AtomicBool::new(false),
                cx: asupersync::Cx::detached_cancel_context(),
            }),
        }
    }

    /// Requests cooperative cancellation and signals the underlying Asupersync `Cx`.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner
                .cx
                .cancel_fast(asupersync::types::CancelKind::User);
        }
    }

    /// Returns `true` once cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire) || self.inner.cx.is_cancelled()
    }

    /// Evaluates a cooperative cancellation checkpoint.
    pub fn checkpoint(&self) -> Result<(), ScopedWorkerError> {
        if self.is_cancelled() {
            Err(ScopedWorkerError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Borrows the underlying detached Asupersync cancellation context.
    #[must_use]
    pub fn asupersync_cx(&self) -> &asupersync::cx::Cx<asupersync::cx::cap::None> {
        &self.inner.cx
    }

    /// Cooperatively sleeps for `duration` in bounded `slice` increments, waking early on cancel.
    pub fn sleep_cooperative(
        &self,
        duration: Duration,
        slice: Duration,
    ) -> Result<(), BoundaryError> {
        CxTimerBoundary::sleep_cooperative_sync(self, duration, slice)
    }
}

/// Validated resource and drain bounds for a [`ScopedWorkerGroup`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerGroupBounds {
    /// Owning canonical region identifier.
    pub region_id: RegionId,
    /// Stable thread-name prefix for OS observability.
    pub name_prefix: String,
    /// Minimum resident blocking threads in the Asupersync pool.
    pub min_threads: usize,
    /// Hard maximum blocking threads in the Asupersync pool.
    pub max_threads: usize,
    /// Hard maximum concurrent admitted workers.
    pub max_active_workers: usize,
    /// Maximum drain grace window waited during `drain_and_shutdown` / `Drop`.
    pub drain_timeout: Duration,
}

impl WorkerGroupBounds {
    /// Constructs validated bounds for an Asupersync-owned worker group.
    pub fn new(
        region_id: RegionId,
        name_prefix: impl Into<String>,
        min_threads: usize,
        max_threads: usize,
        max_active_workers: usize,
        drain_timeout: Duration,
    ) -> Result<Self, ScopedWorkerError> {
        let name_prefix = name_prefix.into();
        if name_prefix.is_empty() || name_prefix.len() > 64 {
            return Err(ScopedWorkerError::InvalidBounds {
                detail: "name_prefix must be 1..=64 bytes",
            });
        }
        if max_threads == 0 || max_threads > MAX_SCOPED_GROUP_THREADS {
            return Err(ScopedWorkerError::InvalidBounds {
                detail: "max_threads must be in 1..=256",
            });
        }
        if min_threads > max_threads {
            return Err(ScopedWorkerError::InvalidBounds {
                detail: "min_threads must be <= max_threads",
            });
        }
        if max_active_workers == 0 {
            return Err(ScopedWorkerError::InvalidBounds {
                detail: "max_active_workers must be at least 1",
            });
        }
        if drain_timeout.is_zero() {
            return Err(ScopedWorkerError::InvalidBounds {
                detail: "drain_timeout must be non-zero",
            });
        }
        Ok(Self {
            region_id,
            name_prefix,
            min_threads,
            max_threads,
            max_active_workers,
            drain_timeout,
        })
    }
}

/// Quiescence receipt emitted when a [`ScopedWorkerGroup`] finishes `request -> drain -> finalize`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerGroupDrainReceipt {
    /// Owning canonical region identifier.
    pub region_id: RegionId,
    /// Remaining active workers after drain (`0` indicates full worker quiescence).
    pub active_workers: usize,
    /// Cumulative workers admitted during the group's lifetime.
    pub total_spawned: u64,
    /// Cumulative workers that returned normally.
    pub completed_workers: u64,
    /// Cumulative workers isolated by panic unwind capture.
    pub panicked_workers: u64,
    /// Whether the underlying Asupersync runtime completed teardown within `drain_timeout`.
    pub runtime_quiescent: bool,
    /// Whether all workers reached zero active count before `drain_timeout`.
    pub drained_within_timeout: bool,
}

/// Alias matching single-worker completion receipts.
pub type ScopedWorkerReceipt = WorkerGroupDrainReceipt;

struct WorkerGroupShared {
    region_id: RegionId,
    max_active_workers: usize,
    cancel: WorkerCancelToken,
    closed: AtomicBool,
    active_workers: AtomicUsize,
    total_spawned: AtomicU64,
    completed_workers: AtomicU64,
    panicked_workers: AtomicU64,
    drain_lock: Mutex<()>,
    drain_cv: Condvar,
}

impl WorkerGroupShared {
    fn try_reserve_slot(&self) -> Result<(), ScopedWorkerError> {
        if self.closed.load(Ordering::Acquire) || self.cancel.is_cancelled() {
            return Err(ScopedWorkerError::Cancelled);
        }
        let mut current = self.active_workers.load(Ordering::Acquire);
        while current < self.max_active_workers {
            match self.active_workers.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if self.closed.load(Ordering::Acquire) || self.cancel.is_cancelled() {
                        self.release_slot(false, false);
                        return Err(ScopedWorkerError::Cancelled);
                    }
                    self.total_spawned.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(observed) => current = observed,
            }
        }
        Err(ScopedWorkerError::CapacityReached {
            limit: self.max_active_workers,
        })
    }

    fn release_slot(&self, completed: bool, panicked: bool) {
        if completed {
            self.completed_workers.fetch_add(1, Ordering::Relaxed);
        }
        if panicked {
            self.panicked_workers.fetch_add(1, Ordering::Relaxed);
        }
        let remaining = self
            .active_workers
            .fetch_sub(1, Ordering::AcqRel)
            .saturating_sub(1);
        if remaining == 0 {
            let _guard = self.drain_lock.lock();
            self.drain_cv.notify_all();
        }
    }

    fn wait_until_drained(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let Ok(mut guard) = self.drain_lock.lock() else {
            return self.active_workers.load(Ordering::Acquire) == 0;
        };
        while self.active_workers.load(Ordering::Acquire) > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.active_workers.load(Ordering::Acquire) == 0;
            }
            match self.drain_cv.wait_timeout(guard, remaining) {
                Ok((next_guard, _)) => guard = next_guard,
                Err(_) => return self.active_workers.load(Ordering::Acquire) == 0,
            }
        }
        true
    }
}

struct WorkerRunGuard {
    shared: Arc<WorkerGroupShared>,
    completed: bool,
    panicked: bool,
}

impl Drop for WorkerRunGuard {
    fn drop(&mut self) {
        self.shared.release_slot(self.completed, self.panicked);
    }
}

/// Cloneable, bounded spawner handle scoped to a live [`ScopedWorkerGroup`].
#[derive(Clone)]
pub struct ScopedWorkerSpawner {
    pool: BlockingPoolHandle,
    shared: Arc<WorkerGroupShared>,
}

impl ScopedWorkerSpawner {
    /// Returns the owning canonical [`RegionId`].
    #[must_use]
    pub fn region_id(&self) -> &RegionId {
        &self.shared.region_id
    }

    /// Returns the shared cooperative cancellation token for this worker group.
    #[must_use]
    pub fn cancel_token(&self) -> WorkerCancelToken {
        self.shared.cancel.clone()
    }

    /// Returns the current number of active workers in the group.
    #[must_use]
    pub fn active_workers(&self) -> usize {
        self.shared.active_workers.load(Ordering::Acquire)
    }

    /// Admits and spawns a region-owned worker onto the group's Asupersync `BlockingPool`.
    pub fn spawn_worker<F>(&self, work: F) -> Result<(), ScopedWorkerError>
    where
        F: FnOnce(WorkerCancelToken) + Send + 'static,
    {
        self.shared.try_reserve_slot()?;
        let shared = Arc::clone(&self.shared);
        let cancel = self.shared.cancel.clone();
        let _handle = self.pool.spawn(move || {
            let mut guard = WorkerRunGuard {
                shared,
                completed: false,
                panicked: false,
            };
            if cancel.is_cancelled() {
                guard.completed = true;
                return;
            }
            match catch_unwind(AssertUnwindSafe(move || work(cancel))) {
                Ok(()) => guard.completed = true,
                Err(_) => guard.panicked = true,
            }
        });
        Ok(())
    }
}

/// Region-owned, bounded worker group backed by an explicit Asupersync `Runtime` + `BlockingPool`.
///
/// Guarantees deterministic `request -> drain -> finalize` cleanup on both explicit
/// [`Self::drain_and_shutdown`] and `Drop`, eliminating detached OS threads.
pub struct ScopedWorkerGroup {
    runtime: Option<Runtime>,
    pool: BlockingPoolHandle,
    shared: Arc<WorkerGroupShared>,
    drain_timeout: Duration,
}

impl ScopedWorkerGroup {
    /// Creates an Asupersync-backed worker group with explicit bounded capacity and drain window.
    pub fn new(bounds: WorkerGroupBounds) -> Result<Self, ScopedWorkerError> {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(bounds.min_threads, bounds.max_threads)
            .thread_name_prefix(bounds.name_prefix)
            .build()
            .map_err(|err| ScopedWorkerError::RuntimeBuild {
                detail: err.to_string(),
            })?;
        let Some(pool) = runtime.blocking_handle() else {
            return Err(ScopedWorkerError::PoolClosed);
        };
        let shared = Arc::new(WorkerGroupShared {
            region_id: bounds.region_id,
            max_active_workers: bounds.max_active_workers,
            cancel: WorkerCancelToken::new(),
            closed: AtomicBool::new(false),
            active_workers: AtomicUsize::new(0),
            total_spawned: AtomicU64::new(0),
            completed_workers: AtomicU64::new(0),
            panicked_workers: AtomicU64::new(0),
            drain_lock: Mutex::new(()),
            drain_cv: Condvar::new(),
        });
        Ok(Self {
            runtime: Some(runtime),
            pool,
            shared,
            drain_timeout: bounds.drain_timeout,
        })
    }

    /// Returns the owning canonical [`RegionId`].
    #[must_use]
    pub fn region_id(&self) -> &RegionId {
        &self.shared.region_id
    }

    /// Returns the cooperative [`WorkerCancelToken`] bound to this worker group.
    #[must_use]
    pub fn cancel_token(&self) -> WorkerCancelToken {
        self.shared.cancel.clone()
    }

    /// Returns a cloneable bounded spawner targeting this group's Asupersync blocking pool.
    #[must_use]
    pub fn spawner(&self) -> ScopedWorkerSpawner {
        ScopedWorkerSpawner {
            pool: self.pool.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns the number of currently active workers.
    #[must_use]
    pub fn active_workers(&self) -> usize {
        self.shared.active_workers.load(Ordering::Acquire)
    }

    /// Admits and spawns a region-owned worker onto this group's Asupersync blocking pool.
    pub fn spawn_worker<F>(&self, work: F) -> Result<(), ScopedWorkerError>
    where
        F: FnOnce(WorkerCancelToken) + Send + 'static,
    {
        self.spawner().spawn_worker(work)
    }

    /// Phase 1 (`request`): signals cooperative cancellation to all workers and closes admission.
    pub fn request_cancel(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.cancel.cancel();
    }

    /// Executes strict `request -> drain -> finalize` and returns the verified quiescence receipt.
    #[must_use]
    pub fn drain_and_shutdown(mut self) -> WorkerGroupDrainReceipt {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> WorkerGroupDrainReceipt {
        self.request_cancel();
        let started = Instant::now();
        let drained_within_timeout = self.shared.wait_until_drained(self.drain_timeout);
        let remaining = self
            .drain_timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(50));
        let runtime_quiescent = self
            .runtime
            .take()
            .is_none_or(|rt| rt.shutdown_timeout(remaining));
        WorkerGroupDrainReceipt {
            region_id: self.shared.region_id.clone(),
            active_workers: self.shared.active_workers.load(Ordering::Acquire),
            total_spawned: self.shared.total_spawned.load(Ordering::Acquire),
            completed_workers: self.shared.completed_workers.load(Ordering::Acquire),
            panicked_workers: self.shared.panicked_workers.load(Ordering::Acquire),
            runtime_quiescent,
            drained_within_timeout,
        }
    }
}

impl Drop for ScopedWorkerGroup {
    fn drop(&mut self) {
        if self.runtime.is_some() {
            let _ = self.shutdown_inner();
        }
    }
}

/// Single region-owned worker built atop a 1-slot [`ScopedWorkerGroup`] with join-on-drop.
pub struct ScopedRegionWorker {
    group: ScopedWorkerGroup,
}

impl ScopedRegionWorker {
    /// Spawns a single region-owned worker bound to `region_id` and `drain_timeout`.
    pub fn spawn<F>(
        region_id: RegionId,
        name: impl Into<String>,
        drain_timeout: Duration,
        work: F,
    ) -> Result<Self, ScopedWorkerError>
    where
        F: FnOnce(WorkerCancelToken) + Send + 'static,
    {
        let bounds = WorkerGroupBounds::new(region_id, name, 1, 1, 1, drain_timeout)?;
        let group = ScopedWorkerGroup::new(bounds)?;
        group.spawn_worker(work)?;
        Ok(Self { group })
    }

    /// Returns the cooperative cancellation token passed to the worker.
    #[must_use]
    pub fn cancel_token(&self) -> WorkerCancelToken {
        self.group.cancel_token()
    }

    /// Signals cooperative cancellation without yet blocking for join.
    pub fn request_cancel(&self) {
        self.group.request_cancel();
    }

    /// Returns `true` while the worker closure is still executing.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.group.active_workers() > 0
    }

    /// Cancels, drains, and joins the worker deterministically, returning its quiescence receipt.
    #[must_use]
    pub fn join_and_finalize(self) -> ScopedWorkerReceipt {
        self.group.drain_and_shutdown()
    }
}
