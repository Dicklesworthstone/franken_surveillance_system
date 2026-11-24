#![forbid(unsafe_code)]
//! Structured Asupersync 0.5.0 runtime operations for FSS crates.
//!
//! Semantic plane: `"authority"`.
//!
//! Provides the canonical, `#![forbid(unsafe_code)]`, explicit-`Cx` building blocks
//! used across FSS runtime, IPC, daemon, and capture boundaries:
//!
//! * [`StructuredRegionRunner`]: pairs [`crate::authority::AuthorityCx`] + [`fss_core::RegionTree`]
//!   with region-owned `asupersync::Cx::spawn` tasks and deterministic
//!   `request -> drain -> finalize` quiescence proofs (`active_tasks == 0`,
//!   `leaked_obligations == 0`).
//! * [`ScopedWorkerGroup`] / [`ScopedRegionWorker`]: replaces detached OS threads
//!   with bounded Asupersync `Runtime` + `BlockingPool` workers bound to a canonical
//!   [`fss_core::RegionId`] and [`WorkerCancelToken`], guaranteed to drain and join on
//!   shutdown or drop.
//! * [`CxTimerBoundary`] / [`CxNetBoundary`]: cooperative `Cx`-checked sleep, backoff,
//!   deadline, and bounded async I/O helpers that run identically under production
//!   wall clocks and deterministic virtual-clock harnesses.

/// Cooperative `Cx`-checked timer, backoff, deadline, and network I/O boundaries.
pub mod boundaries;
/// Structured `asupersync::Cx` + canonical `RegionTree` lifecycle runner.
pub mod region_runner;
/// Region-owned, non-detached worker groups backed by Asupersync's blocking pool.
pub mod scoped_worker;

pub use boundaries::{
    BackoffPolicy, BoundaryError, CxNetBoundary, CxTimerBoundary, MAX_COOPERATIVE_SLICE,
    MIN_COOPERATIVE_SLICE, PollBudget, PollStep,
};
pub use region_runner::{
    RegionRunError, RegionRunReceipt, ScopedTaskHandle, StructuredRegionRunner,
};
pub use scoped_worker::{
    MAX_SCOPED_GROUP_THREADS, ScopedRegionWorker, ScopedWorkerError, ScopedWorkerGroup,
    ScopedWorkerReceipt, ScopedWorkerSpawner, WorkerCancelToken, WorkerGroupBounds,
    WorkerGroupDrainReceipt,
};
