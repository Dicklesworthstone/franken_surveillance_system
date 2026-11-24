#![forbid(unsafe_code)]
//! Cooperative `asupersync::Cx`-gated timer, backoff, and network I/O boundaries.
//!
//! Semantic plane: `"authority"`.
//!
//! Every helper accepts an explicit `&asupersync::Cx` (never ambient lookup),
//! checks `cx.checkpoint()` before and after every await point, reads time
//! strictly through `cx.now()` so identical code executes identically under
//! native wall-clock runtimes and deterministic virtual-clock harnesses, and
//! bounds every retry/poll loop with an explicit [`PollBudget`].

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::yield_now;
use asupersync::time::{sleep, sleep_until, timeout};
use asupersync::types::Time;

use crate::asupersync_ops::scoped_worker::WorkerCancelToken;

/// Minimum cooperative sleep slice enforced by synchronous cancel-checked waits.
pub const MIN_COOPERATIVE_SLICE: Duration = Duration::from_millis(1);
/// Maximum cooperative sleep slice enforced by synchronous cancel-checked waits.
pub const MAX_COOPERATIVE_SLICE: Duration = Duration::from_millis(50);

/// Typed, secret-free error returned by `Cx`-checked timer and network boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryError {
    /// The explicit `asupersync::Cx` or cooperative cancellation token fired.
    Cancelled,
    /// The virtual or wall deadline elapsed before the operation completed.
    DeadlineExceeded {
        /// Bound deadline timestamp in nanoseconds.
        deadline_ns: u64,
        /// Observed clock timestamp at expiration in nanoseconds.
        observed_ns: u64,
    },
    /// A bounded poll or retry loop exhausted its finite attempt budget.
    PollBudgetExhausted {
        /// Configured maximum poll or retry count.
        max_polls: u32,
    },
    /// Caller supplied invalid timeout, backoff, or budget parameters.
    InvalidConfig {
        /// Static non-secret description of the invalid parameter.
        detail: &'static str,
    },
    /// The underlying I/O boundary returned an operating-system error kind.
    Io(io::ErrorKind),
    /// The transport peer closed cleanly before delivering all expected bytes.
    PeerClosed,
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("asupersync boundary cancelled"),
            Self::DeadlineExceeded {
                deadline_ns,
                observed_ns,
            } => write!(
                f,
                "asupersync boundary deadline {deadline_ns}ns exceeded at {observed_ns}ns"
            ),
            Self::PollBudgetExhausted { max_polls } => {
                write!(
                    f,
                    "asupersync poll budget exhausted after {max_polls} polls"
                )
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid asupersync boundary configuration: {detail}")
            }
            Self::Io(kind) => write!(f, "asupersync I/O boundary failed: {kind:?}"),
            Self::PeerClosed => f.write_str("asupersync transport peer closed unexpectedly"),
        }
    }
}

impl std::error::Error for BoundaryError {}

/// Finite poll-count budget preventing unbounded spin or polling loops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollBudget {
    max_polls: u32,
    used: u32,
}

impl PollBudget {
    /// Constructs a finite poll budget (`max_polls >= 1`).
    pub const fn new(max_polls: u32) -> Result<Self, BoundaryError> {
        if max_polls == 0 {
            return Err(BoundaryError::InvalidConfig {
                detail: "max_polls must be at least 1",
            });
        }
        Ok(Self { max_polls, used: 0 })
    }

    /// Consumes one poll step, returning the 1-based ordinal or `PollBudgetExhausted`.
    pub fn consume(&mut self) -> Result<u32, BoundaryError> {
        if self.used >= self.max_polls {
            return Err(BoundaryError::PollBudgetExhausted {
                max_polls: self.max_polls,
            });
        }
        self.used = self.used.saturating_add(1);
        Ok(self.used)
    }

    /// Returns total polls consumed so far.
    #[must_use]
    pub const fn used(&self) -> u32 {
        self.used
    }

    /// Returns remaining polls before exhaustion.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.max_polls.saturating_sub(self.used)
    }

    /// Returns the configured maximum polls.
    #[must_use]
    pub const fn max_polls(&self) -> u32 {
        self.max_polls
    }
}

/// Deterministic jittered exponential backoff policy bounded by `[min_delay, max_delay]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackoffPolicy {
    /// Minimum retry delay.
    pub min_delay: Duration,
    /// Maximum retry delay ceiling.
    pub max_delay: Duration,
    /// Finite retry attempt ceiling (`>= 1`).
    pub max_attempts: u32,
    /// Deterministic jitter seed (no ambient RNG).
    pub seed: u64,
}

impl BackoffPolicy {
    /// Validates and builds a deterministic backoff policy.
    pub fn new(
        min_delay: Duration,
        max_delay: Duration,
        max_attempts: u32,
        seed: u64,
    ) -> Result<Self, BoundaryError> {
        if min_delay.is_zero() {
            return Err(BoundaryError::InvalidConfig {
                detail: "min_delay must be non-zero",
            });
        }
        if max_delay < min_delay {
            return Err(BoundaryError::InvalidConfig {
                detail: "max_delay must be >= min_delay",
            });
        }
        if max_attempts == 0 {
            return Err(BoundaryError::InvalidConfig {
                detail: "max_attempts must be at least 1",
            });
        }
        Ok(Self {
            min_delay,
            max_delay,
            max_attempts,
            seed,
        })
    }

    /// Computes the deterministic jittered delay for zero-based `attempt`.
    ///
    /// Returns `None` once `attempt >= max_attempts`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }
        let min_ns = duration_to_u64_nanos(self.min_delay).max(1);
        let max_ns = duration_to_u64_nanos(self.max_delay).max(min_ns);
        let shift = attempt.min(30);
        let exp_ns = min_ns.saturating_mul(1_u64 << shift).min(max_ns);
        let jitter_span = (exp_ns / 5).max(1);
        let span_width = jitter_span.saturating_mul(2).saturating_add(1);
        let mixed =
            splitmix64(self.seed ^ (u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        let offset = mixed % span_width;
        let jittered = exp_ns
            .saturating_sub(jitter_span)
            .saturating_add(offset)
            .clamp(min_ns, max_ns);
        Some(Duration::from_nanos(jittered))
    }
}

/// One step outcome returned by a caller-supplied non-blocking poll closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollStep<T> {
    /// Operation produced its terminal value.
    Ready(T),
    /// Operation would block and may be retried after a cooperative timer yield.
    Pending,
    /// Underlying peer closed cleanly before completing the operation.
    Closed,
}

/// Cooperative `asupersync::Cx`-checked clock, sleep, backoff, and deadline boundary.
pub struct CxTimerBoundary;

impl CxTimerBoundary {
    /// Evaluates the cooperative cancellation checkpoint on `cx`.
    pub fn checkpoint(cx: &Cx) -> Result<(), BoundaryError> {
        cx.checkpoint().map_err(|_| BoundaryError::Cancelled)
    }

    /// Reads the explicit runtime clock (wall clock in production, virtual clock in lab harnesses).
    #[must_use]
    pub fn now_ns(cx: &Cx) -> u64 {
        cx.now().as_nanos()
    }

    /// Cooperatively sleeps for `duration` using `cx`'s clock and timer wheel.
    ///
    /// Re-checks `cx.checkpoint()` immediately upon wakeup so cancellation woken
    /// during timer parking is always surfaced as [`BoundaryError::Cancelled`].
    pub async fn sleep(cx: &Cx, duration: Duration) -> Result<(), BoundaryError> {
        Self::checkpoint(cx)?;
        if duration.is_zero() {
            yield_now().await;
            return Self::checkpoint(cx);
        }
        sleep(cx.now(), duration).await;
        Self::checkpoint(cx)
    }

    /// Cooperatively sleeps until absolute runtime timestamp `deadline_ns`.
    pub async fn sleep_until_ns(cx: &Cx, deadline_ns: u64) -> Result<(), BoundaryError> {
        Self::checkpoint(cx)?;
        if cx.now().as_nanos() >= deadline_ns {
            return Ok(());
        }
        sleep_until(Time::from_nanos(deadline_ns)).await;
        Self::checkpoint(cx)
    }

    /// Runs `future` under a `cx.now()`-anchored timeout while preserving cancellation priority.
    pub async fn with_timeout<F, T>(
        cx: &Cx,
        duration: Duration,
        future: F,
    ) -> Result<T, BoundaryError>
    where
        F: Future<Output = T>,
    {
        Self::checkpoint(cx)?;
        let start = cx.now();
        let deadline_ns = start
            .as_nanos()
            .saturating_add(duration_to_u64_nanos(duration));
        let outcome = timeout(start, duration, future).await;
        if cx.is_cancel_requested() || cx.is_cancelled() {
            return Err(BoundaryError::Cancelled);
        }
        match outcome {
            Ok(value) => Ok(value),
            Err(_) => Err(BoundaryError::DeadlineExceeded {
                deadline_ns,
                observed_ns: cx.now().as_nanos(),
            }),
        }
    }

    /// Sleeps for the deterministic backoff window for zero-based `attempt`.
    pub async fn sleep_backoff(
        cx: &Cx,
        policy: &BackoffPolicy,
        attempt: u32,
    ) -> Result<Duration, BoundaryError> {
        let Some(delay) = policy.delay_for_attempt(attempt) else {
            return Err(BoundaryError::PollBudgetExhausted {
                max_polls: policy.max_attempts,
            });
        };
        Self::sleep(cx, delay).await?;
        Ok(delay)
    }

    /// Cooperative sliced synchronous wait bound to a [`WorkerCancelToken`].
    ///
    /// Used strictly at synchronous bridge boundaries (such as non-blocking socket
    /// poll loops inside an Asupersync blocking worker) so cancellation interrupts
    /// waits within `slice.clamp(1ms, 50ms)`.
    pub fn sleep_cooperative_sync(
        cancel: &WorkerCancelToken,
        duration: Duration,
        slice: Duration,
    ) -> Result<(), BoundaryError> {
        if cancel.is_cancelled() {
            return Err(BoundaryError::Cancelled);
        }
        if duration.is_zero() {
            return Ok(());
        }
        let step = slice.clamp(MIN_COOPERATIVE_SLICE, MAX_COOPERATIVE_SLICE);
        let deadline = Instant::now() + duration;
        loop {
            if cancel.is_cancelled() {
                return Err(BoundaryError::Cancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            // fss-asupersync-guard:allow-cooperative-sleep
            std::thread::sleep(remaining.min(step));
        }
    }

    /// Cooperative sliced synchronous wait bound to an `AtomicBool` shutdown flag.
    pub fn sleep_cooperative_flag(
        shutdown: &AtomicBool,
        duration: Duration,
        slice: Duration,
    ) -> Result<(), BoundaryError> {
        if shutdown.load(Ordering::Acquire) {
            return Err(BoundaryError::Cancelled);
        }
        if duration.is_zero() {
            return Ok(());
        }
        let step = slice.clamp(MIN_COOPERATIVE_SLICE, MAX_COOPERATIVE_SLICE);
        let deadline = Instant::now() + duration;
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Err(BoundaryError::Cancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            // fss-asupersync-guard:allow-cooperative-sleep
            std::thread::sleep(remaining.min(step));
        }
    }
}

/// Cooperative `asupersync::Cx`-checked network and pollable I/O helpers.
pub struct CxNetBoundary;

impl CxNetBoundary {
    /// Drives a non-blocking poll closure until ready, cancelled, timed out, or budget-exhausted.
    ///
    /// Executes identically under native wall-clock and virtual-clock runtimes because all
    /// deadline checks and backoff intervals route through [`CxTimerBoundary`].
    pub async fn poll_until_ready<T, F>(
        cx: &Cx,
        mut budget: PollBudget,
        deadline_duration: Duration,
        poll_interval: Duration,
        mut step: F,
    ) -> Result<T, BoundaryError>
    where
        F: FnMut(&Cx) -> Result<PollStep<T>, BoundaryError>,
    {
        CxTimerBoundary::checkpoint(cx)?;
        let start_ns = cx.now().as_nanos();
        let deadline_ns = start_ns.saturating_add(duration_to_u64_nanos(deadline_duration));
        let step_delay = poll_interval.max(Duration::from_nanos(1));

        loop {
            CxTimerBoundary::checkpoint(cx)?;
            let _ = budget.consume()?;
            match step(cx)? {
                PollStep::Ready(value) => return Ok(value),
                PollStep::Closed => return Err(BoundaryError::PeerClosed),
                PollStep::Pending => {
                    let now_ns = cx.now().as_nanos();
                    if now_ns >= deadline_ns {
                        return Err(BoundaryError::DeadlineExceeded {
                            deadline_ns,
                            observed_ns: now_ns,
                        });
                    }
                    let remaining = Duration::from_nanos(deadline_ns.saturating_sub(now_ns));
                    CxTimerBoundary::sleep(cx, step_delay.min(remaining)).await?;
                }
            }
        }
    }

    /// Reads exactly `buf.len()` bytes from an Asupersync `AsyncRead` under a bounded `Cx` timeout.
    pub async fn read_exact_bounded<R>(
        cx: &Cx,
        reader: &mut R,
        buf: &mut [u8],
        io_timeout: Duration,
    ) -> Result<(), BoundaryError>
    where
        R: AsyncRead + Unpin,
    {
        if buf.is_empty() {
            return CxTimerBoundary::checkpoint(cx);
        }
        CxTimerBoundary::with_timeout(cx, io_timeout, async {
            let mut offset = 0_usize;
            while offset < buf.len() {
                CxTimerBoundary::checkpoint(cx)?;
                let n = poll_fn(|task_cx| {
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Err(BoundaryError::Cancelled));
                    }
                    let mut read_buf = ReadBuf::new(&mut buf[offset..]);
                    match Pin::new(&mut *reader).poll_read(task_cx, &mut read_buf) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                        Poll::Ready(Err(err)) => Poll::Ready(Err(BoundaryError::Io(err.kind()))),
                    }
                })
                .await?;
                if n == 0 {
                    return Err(BoundaryError::PeerClosed);
                }
                offset = offset.saturating_add(n);
            }
            Ok(())
        })
        .await?
    }

    /// Writes all `data` bytes to an Asupersync `AsyncWrite` under a bounded `Cx` timeout.
    pub async fn write_all_bounded<W>(
        cx: &Cx,
        writer: &mut W,
        data: &[u8],
        io_timeout: Duration,
    ) -> Result<(), BoundaryError>
    where
        W: AsyncWrite + Unpin,
    {
        if data.is_empty() {
            return CxTimerBoundary::checkpoint(cx);
        }
        CxTimerBoundary::with_timeout(cx, io_timeout, async {
            let mut offset = 0_usize;
            while offset < data.len() {
                CxTimerBoundary::checkpoint(cx)?;
                let n = poll_fn(|task_cx| {
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Err(BoundaryError::Cancelled));
                    }
                    match Pin::new(&mut *writer).poll_write(task_cx, &data[offset..]) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
                        Poll::Ready(Err(err)) => Poll::Ready(Err(BoundaryError::Io(err.kind()))),
                    }
                })
                .await?;
                if n == 0 {
                    return Err(BoundaryError::PeerClosed);
                }
                offset = offset.saturating_add(n);
            }
            Ok(())
        })
        .await?
    }
}

pub(crate) fn duration_to_u64_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

const fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
