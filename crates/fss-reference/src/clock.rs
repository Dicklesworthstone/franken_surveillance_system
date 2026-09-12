#![forbid(unsafe_code)]
//! Deterministic virtual clock acting as the explicit time authority for reference execution.
//!
//! Preserves time monotonicity by construction. Skew, jitter, and pauses are injectable
//! for fault schedule exploration; backward-step attempts are strictly rejected as typed
//! [`ReferenceError::BackwardStepAttempt`] faults without mutating clock state.

use fss_core::{CaptureInterval, TimestampNs};

use crate::ReferenceError;
use crate::source::VirtualCameraSpec;

/// Maximum allowable skew in parts per million (+/- 500_000 ppm = +/- 50% rate).
pub const MAX_SKEW_PPM: i64 = 500_000;

/// Deterministic, monotonic virtual clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualClock {
    start_ns: TimestampNs,
    current_ns: TimestampNs,
    seed: u64,
    prng_state: u64,
    skew_ppm: i64,
    max_jitter_ns: u64,
    step_count: u64,
}

impl VirtualClock {
    /// Constructs a new virtual clock anchored at `start_ns` with deterministic `seed`.
    #[must_use]
    pub fn new(seed: u64, start_ns: TimestampNs) -> Self {
        let prng_state = if seed == 0 {
            0xd1b5_4a32_d192_ed03_u64
        } else {
            seed ^ 0x9e37_79b9_7f4a_7c15_u64
        };
        Self {
            start_ns,
            current_ns: start_ns,
            seed,
            prng_state,
            skew_ppm: 0,
            max_jitter_ns: 0,
            step_count: 0,
        }
    }

    /// Constructs a virtual clock initialized from a [`VirtualCameraSpec`].
    #[must_use]
    pub fn from_spec(spec: &VirtualCameraSpec) -> Self {
        Self::new(spec.seed, TimestampNs(spec.start_ns))
    }

    /// Returns the current virtual timestamp.
    #[must_use]
    pub const fn now(&self) -> TimestampNs {
        self.current_ns
    }

    /// Returns the initial anchor timestamp.
    #[must_use]
    pub const fn start_ns(&self) -> TimestampNs {
        self.start_ns
    }

    /// Returns the initial seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the total number of successful forward steps taken.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Returns the current skew in parts-per-million.
    #[must_use]
    pub const fn skew_ppm(&self) -> i64 {
        self.skew_ppm
    }

    /// Returns the configured maximum jitter in nanoseconds.
    #[must_use]
    pub const fn max_jitter_ns(&self) -> u64 {
        self.max_jitter_ns
    }

    /// Injects clock skew in parts-per-million (e.g. +1000 = +0.1%, -1000 = -0.1%).
    ///
    /// Skew is bounded to `[-MAX_SKEW_PPM, MAX_SKEW_PPM]`.
    pub fn inject_skew(&mut self, skew_ppm: i64) -> Result<(), ReferenceError> {
        if !(-MAX_SKEW_PPM..=MAX_SKEW_PPM).contains(&skew_ppm) {
            return Err(ReferenceError::InvalidClockParameter("skew_ppm"));
        }
        self.skew_ppm = skew_ppm;
        Ok(())
    }

    /// Injects maximum jitter in nanoseconds.
    ///
    /// Jitter will be deterministically sampled from `[0, max_jitter_ns]` on each advance.
    pub fn inject_jitter(&mut self, max_jitter_ns: u64) {
        self.max_jitter_ns = max_jitter_ns;
    }

    /// Injects a virtual pause of `duration_ns`.
    ///
    /// Advances current time forward by `duration_ns` without intermediate events.
    pub fn inject_pause(&mut self, duration_ns: u64) -> Result<TimestampNs, ReferenceError> {
        let new_time = self
            .current_ns
            .0
            .checked_add(i128::from(duration_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        self.current_ns = TimestampNs(new_time);
        Ok(self.current_ns)
    }

    /// Attempts to step the clock backwards by `delta_ns`.
    ///
    /// This attempt is strictly REJECTED as a typed [`ReferenceError::BackwardStepAttempt`]
    /// fault to preserve monotonicity. The clock state remains unmodified.
    pub fn step_backward(&mut self, delta_ns: u64) -> Result<TimestampNs, ReferenceError> {
        let attempted = self
            .current_ns
            .0
            .checked_sub(i128::from(delta_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        Err(ReferenceError::BackwardStepAttempt {
            current: self.current_ns,
            attempted: TimestampNs(attempted),
        })
    }

    /// Injects an explicit backward-step attempt.
    ///
    /// Always rejected as a typed fault.
    pub fn inject_backward_step(&mut self, delta_ns: u64) -> Result<TimestampNs, ReferenceError> {
        self.step_backward(delta_ns)
    }

    /// Sets the clock time to `target`.
    ///
    /// If `target < current_ns`, the transition is rejected as a backward-step fault.
    pub fn set_time(&mut self, target: TimestampNs) -> Result<TimestampNs, ReferenceError> {
        if target.0 < self.current_ns.0 {
            return Err(ReferenceError::BackwardStepAttempt {
                current: self.current_ns,
                attempted: target,
            });
        }
        self.current_ns = target;
        Ok(self.current_ns)
    }

    /// Advances virtual time by `nominal_delta_ns` modified by active skew and jitter.
    ///
    /// Monotonicity is verified: if effective delta is non-positive or would move time backwards,
    /// the step is rejected and the clock remains unchanged.
    pub fn advance(&mut self, nominal_delta_ns: u64) -> Result<TimestampNs, ReferenceError> {
        let nominal = i128::from(nominal_delta_ns);
        let skew_offset = nominal
            .checked_mul(i128::from(self.skew_ppm))
            .ok_or(ReferenceError::ArithmeticOverflow)?
            / 1_000_000;

        let jitter = if self.max_jitter_ns > 0 {
            let sample = self.next_u64();
            i128::from(sample % (self.max_jitter_ns + 1))
        } else {
            0
        };

        let effective_delta = nominal
            .checked_add(skew_offset)
            .ok_or(ReferenceError::ArithmeticOverflow)?
            .checked_add(jitter)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        if effective_delta < 0 {
            let attempted = self.current_ns.0.wrapping_add(effective_delta);
            return Err(ReferenceError::BackwardStepAttempt {
                current: self.current_ns,
                attempted: TimestampNs(attempted),
            });
        }

        let new_time = self
            .current_ns
            .0
            .checked_add(effective_delta)
            .ok_or(ReferenceError::ArithmeticOverflow)?;

        if new_time < self.current_ns.0 {
            return Err(ReferenceError::BackwardStepAttempt {
                current: self.current_ns,
                attempted: TimestampNs(new_time),
            });
        }

        self.current_ns = TimestampNs(new_time);
        self.step_count = self
            .step_count
            .checked_add(1)
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        Ok(self.current_ns)
    }

    /// Reads a conservative [`CaptureInterval`] anchored at the current virtual time.
    ///
    /// Returns `[now, now + uncertainty_ns]`.
    pub fn read_interval(
        &mut self,
        uncertainty_ns: u64,
    ) -> Result<CaptureInterval, ReferenceError> {
        let earliest = self.current_ns;
        let latest_raw = earliest
            .0
            .checked_add(i128::from(uncertainty_ns))
            .ok_or(ReferenceError::ArithmeticOverflow)?;
        let latest = TimestampNs(latest_raw);
        let interval = CaptureInterval::new(earliest, latest)?;
        Ok(interval)
    }

    fn next_u64(&mut self) -> u64 {
        self.prng_state ^= self.prng_state << 13;
        self.prng_state ^= self.prng_state >> 7;
        self.prng_state ^= self.prng_state << 17;
        self.prng_state
    }
}
