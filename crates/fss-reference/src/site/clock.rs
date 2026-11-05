#![forbid(unsafe_code)]
//! Bounded site-node clock correlation (VIT-019); no clock or network I/O.
//!
//! A correlation is conditional on a caller-owned, same-session monotonic clock,
//! an explicitly bounded UTC-minus-local correction, and the declared drift/slew
//! policy. The source digest names the caller's exact synchronization evidence;
//! it does not authenticate a time server or certify its accuracy. Camera/NVR
//! timestamps are deliberately absent from this API.
//!
//! Later host samples can contradict the declared continuity model. Compatible
//! samples do not prove that no step occurred between observations, refresh the
//! original synchronization age, or narrow its uncertainty. A detected step or
//! monotonic regression permanently invalidates this correlation.

use std::fmt;

use fss_core::{ContentDigest, DigestAlgorithm};

use super::{
    ClockOffsetDirection, ClockWitness, MAX_CLOCK_UNCERTAINTY_NS, MIN_PLAUSIBLE_WALL_CLOCK_UNIX_NS,
};

const PARTS_PER_BILLION: u64 = 1_000_000_000;

/// One wall-clock read bracketed by reads of the owning monotonic clock.
///
/// The wall read occurred somewhere in the inclusive monotonic bracket, not
/// necessarily at its midpoint. All three values are observations supplied by an
/// explicit I/O owner; constructing this value does not obtain or prove them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostClockSample {
    /// Monotonic sample taken before the wall-clock read.
    pub monotonic_before_ns: u64,
    /// Uncorrected local wall-clock read, in nanoseconds since the Unix epoch.
    pub wall_clock_unix_ns: u64,
    /// Monotonic sample taken after the wall-clock read.
    pub monotonic_after_ns: u64,
}

/// Inclusive, signed UTC-minus-local-wall correction interval, in nanoseconds.
///
/// A positive correction means that the local clock is behind the supplied UTC
/// assertion. The interval must have nonzero width; no exact synchronization is
/// inferred from a scalar offset or an omitted uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockOffsetInterval {
    /// Earliest allowed correction.
    pub lower_ns: i64,
    /// Latest allowed correction.
    pub upper_ns: i64,
}

/// Explicit bounds for a single clock-correlation lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockCorrelationPolicy {
    /// Maximum span of each bracketed host sample. Nonzero and no greater than
    /// `max_age_ns`; a slow clock read is refused instead of treated as instant.
    pub max_sample_bracket_ns: u64,
    /// Maximum absolute drift/slew relative to the monotonic clock, in parts per
    /// billion. Must be less than one billion; this is a declared assumption,
    /// not a measured accuracy claim or permission to adjust a clock.
    pub max_drift_ppb: u64,
    /// Maximum age measured conservatively from the first edge of the original
    /// synchronization bracket. Later compatible samples never renew it.
    pub max_age_ns: u64,
}

/// Inclusive Unix-nanosecond interval. No saturation is used to construct it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcInterval {
    /// Earliest represented instant.
    pub earliest_ns: u64,
    /// Latest represented instant.
    pub latest_ns: u64,
}

impl UtcInterval {
    /// Whether this interval contains the supplied integer instant.
    #[must_use]
    pub const fn contains(self, instant_ns: u64) -> bool {
        self.earliest_ns <= instant_ns && instant_ns <= self.latest_ns
    }
}

/// Successful comparison of two sampled host clocks under the explicit policy.
/// This is evidence only at the sampled instants, not continuous monitoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSampleCheck {
    /// The previously accepted sample, or the same sample for an exact retry.
    pub previous: HostClockSample,
    /// The sample just accepted.
    pub current: HostClockSample,
    /// Allowed uncorrected wall-clock readings from the original sample.
    pub from_origin: UtcInterval,
    /// Allowed uncorrected wall-clock readings from the previous sample.
    pub from_previous: UtcInterval,
}

/// Static refusal categories, without endpoints or untrusted source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockCorrelationError {
    /// Invalid policy, including a zero lifetime or unbounded slew.
    InvalidPolicy,
    /// Reversed/oversized bracket or implausible local epoch.
    InvalidSample,
    /// Reversed or exact-zero-width synchronization correction.
    InvalidOffsetInterval,
    /// Source is not a nonzero, non-laboratory SHA-256 evidence identity.
    InvalidSourceDigest,
    /// A query precedes the completed synchronization sample.
    BeforeSynchronization,
    /// The original synchronization has exceeded its explicit age ceiling.
    Expired,
    /// A required endpoint, radius or correction cannot be represented.
    ArithmeticOverflow,
    /// The conservative result exceeds the existing clock-witness uncertainty
    /// ceiling, has zero uncertainty, or has an implausible corrected epoch.
    UncertaintyLimit,
    /// A later sample ran backwards or overlapped the previous sample's bracket.
    MonotonicDiscontinuity,
    /// Sampled local wall time contradicts the declared drift/slew model.
    WallClockDiscontinuity,
    /// A prior discontinuity invalidated this correlation; it cannot be revived.
    Invalidated,
}

impl fmt::Display for ClockCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid site clock correlation policy",
            Self::InvalidSample => "invalid site host clock sample",
            Self::InvalidOffsetInterval => "invalid site clock correction interval",
            Self::InvalidSourceDigest => "invalid site clock evidence identity",
            Self::BeforeSynchronization => "site clock query precedes synchronization",
            Self::Expired => "site clock synchronization expired",
            Self::ArithmeticOverflow => "site clock interval is not representable",
            Self::UncertaintyLimit => "site clock witness uncertainty is unsupported",
            Self::MonotonicDiscontinuity => "site monotonic clock discontinuity",
            Self::WallClockDiscontinuity => "site wall clock discontinuity",
            Self::Invalidated => "site clock correlation was invalidated",
        })
    }
}

impl std::error::Error for ClockCorrelationError {}

/// Checked correlation for one caller-owned monotonic clock session.
///
/// This owner performs no I/O and retains only constant-size state. The caller
/// binds the sample, policy, correction and exact source evidence to the native
/// session before attaching a witness to a source observation. Reusing these
/// numbers with another process's monotonic origin is not supported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockCorrelation {
    origin: HostClockSample,
    offset: ClockOffsetInterval,
    source_digest: ContentDigest,
    policy: ClockCorrelationPolicy,
    last_sample: HostClockSample,
    invalidated: bool,
}

impl ClockCorrelation {
    /// Validate a supplied synchronization and the first host sample.
    ///
    /// `offset` applies at `sample`; the synchronization owner must widen an
    /// older offset before supplying it here. The sample's bracket and all future
    /// drift are added independently. Exact source bytes are neither fetched nor
    /// authenticated by this function.
    pub fn new(
        sample: HostClockSample,
        offset: ClockOffsetInterval,
        source_digest: ContentDigest,
        policy: ClockCorrelationPolicy,
    ) -> Result<Self, ClockCorrelationError> {
        if policy.max_sample_bracket_ns == 0
            || policy.max_age_ns == 0
            || policy.max_sample_bracket_ns > policy.max_age_ns
            || policy.max_drift_ppb >= PARTS_PER_BILLION
        {
            return Err(ClockCorrelationError::InvalidPolicy);
        }
        validate_sample(sample, policy)?;
        if offset.lower_ns >= offset.upper_ns {
            return Err(ClockCorrelationError::InvalidOffsetInterval);
        }
        if source_digest.algorithm() != DigestAlgorithm::Sha256
            || source_digest.is_laboratory()
            || source_digest.bytes() == [0; 32]
        {
            return Err(ClockCorrelationError::InvalidSourceDigest);
        }
        let correlation = Self {
            origin: sample,
            offset,
            source_digest,
            policy,
            last_sample: sample,
            invalidated: false,
        };
        // A correlation whose initial witness already exceeds the v1 contract
        // cannot become usable by waiting or by rounding its bounds inward.
        correlation.witness_at(sample.monotonic_after_ns)?;
        Ok(correlation)
    }

    /// Original synchronization bracket; later checks never replace it.
    #[must_use]
    pub const fn origin(&self) -> HostClockSample {
        self.origin
    }

    /// The exact caller-bound synchronization evidence identity.
    #[must_use]
    pub const fn source_digest(&self) -> ContentDigest {
        self.source_digest
    }

    /// Original signed correction; subsequent compatible samples cannot narrow it.
    #[must_use]
    pub const fn offset_interval(&self) -> ClockOffsetInterval {
        self.offset
    }

    /// Declared immutable lifetime, sampling and drift policy.
    #[must_use]
    pub const fn policy(&self) -> ClockCorrelationPolicy {
        self.policy
    }

    /// Last accepted sample. A detected discontinuity leaves it unchanged.
    #[must_use]
    pub const fn last_sample(&self) -> HostClockSample {
        self.last_sample
    }

    /// End of the most recently accepted host-clock bracket.
    #[must_use]
    pub const fn last_checked_monotonic_ns(&self) -> u64 {
        self.last_sample.monotonic_after_ns
    }

    /// Whether any sampled discontinuity has permanently invalidated this owner.
    #[must_use]
    pub const fn is_invalidated(&self) -> bool {
        self.invalidated
    }

    /// Project one same-session monotonic instant to a conservative UTC interval.
    ///
    /// The earliest supported query is the end of the original bracket. This is
    /// a node-clock projection, not camera exposure/capture time or an assertion
    /// that buffered media arrived at the represented instant.
    pub fn project(&self, monotonic_ns: u64) -> Result<UtcInterval, ClockCorrelationError> {
        self.check_live_at(monotonic_ns)?;
        let earliest_elapsed = monotonic_ns - self.origin.monotonic_after_ns;
        let latest_elapsed = monotonic_ns - self.origin.monotonic_before_ns;
        let drift = drift_ns(latest_elapsed, self.policy.max_drift_ppb)?;
        let earliest = i128::from(self.origin.wall_clock_unix_ns)
            + i128::from(earliest_elapsed)
            + i128::from(self.offset.lower_ns)
            - i128::from(drift);
        let latest = i128::from(self.origin.wall_clock_unix_ns)
            + i128::from(latest_elapsed)
            + i128::from(self.offset.upper_ns)
            + i128::from(drift);
        interval(earliest, latest)
    }

    /// Construct the unchanged v1 clock-witness shape at an exact observation
    /// coordinate. The full sample bracket, offset interval and drift growth are
    /// enclosed by its symmetric uncertainty; no endpoint is rounded inward.
    ///
    /// The offset fields describe the correction applied to the nominal local
    /// projection. Positive UTC-minus-local offsets map to `Behind`. The caller
    /// must additionally account for its observation/read bracket, and must bind
    /// this coordinate to the receipt's actual first RTP timestamp observation.
    pub fn witness_at(&self, monotonic_ns: u64) -> Result<ClockWitness, ClockCorrelationError> {
        let projected = self.project(monotonic_ns)?;
        let offset_center =
            (i128::from(self.offset.lower_ns) + i128::from(self.offset.upper_ns)).div_euclid(2);
        let bracket_half = (self.origin.monotonic_after_ns - self.origin.monotonic_before_ns) / 2;
        let center = i128::from(self.origin.wall_clock_unix_ns)
            + i128::from(monotonic_ns - self.origin.monotonic_after_ns)
            + i128::from(bracket_half)
            + offset_center;
        let center =
            u64::try_from(center).map_err(|_| ClockCorrelationError::ArithmeticOverflow)?;
        let lower_radius = center
            .checked_sub(projected.earliest_ns)
            .ok_or(ClockCorrelationError::ArithmeticOverflow)?;
        let upper_radius = projected
            .latest_ns
            .checked_sub(center)
            .ok_or(ClockCorrelationError::ArithmeticOverflow)?;
        let radius = lower_radius.max(upper_radius);
        if radius == 0
            || radius > MAX_CLOCK_UNCERTAINTY_NS
            || center < MIN_PLAUSIBLE_WALL_CLOCK_UNIX_NS
        {
            return Err(ClockCorrelationError::UncertaintyLimit);
        }
        // The symmetric representation may be a nanosecond wider than the
        // asymmetric interval. Refuse rather than saturate either extra edge.
        center
            .checked_sub(radius)
            .and_then(|_| center.checked_add(radius))
            .ok_or(ClockCorrelationError::ArithmeticOverflow)?;
        Ok(ClockWitness {
            wall_clock_unix_ns: center,
            monotonic_ns,
            ntp_offset_ns: u64::try_from(offset_center.unsigned_abs())
                .map_err(|_| ClockCorrelationError::ArithmeticOverflow)?,
            ntp_offset_direction: if offset_center > 0 {
                ClockOffsetDirection::Behind
            } else {
                ClockOffsetDirection::Ahead
            },
            ntp_uncertainty_ns: radius,
        })
    }

    /// Compare a later host sample against both the original sample and the last
    /// accepted sample. Exact repeated samples are idempotent.
    ///
    /// A contradiction invalidates all subsequent projections, including earlier
    /// instants: a sampled step does not reveal exactly when the discontinuity
    /// happened. Successful checks neither re-anchor nor tighten synchronization.
    pub fn observe_later_sample(
        &mut self,
        sample: HostClockSample,
    ) -> Result<ClockSampleCheck, ClockCorrelationError> {
        if self.invalidated {
            return Err(ClockCorrelationError::Invalidated);
        }
        // A reversed bracket is itself an observed monotonic regression. Do
        // not leave an earlier correlation usable merely because the sample
        // cannot also pass the stateless constructor's shape validation.
        if sample.monotonic_after_ns < sample.monotonic_before_ns {
            self.invalidated = true;
            return Err(ClockCorrelationError::MonotonicDiscontinuity);
        }
        validate_sample(sample, self.policy)?;
        if sample != self.last_sample
            && sample.monotonic_before_ns < self.last_sample.monotonic_after_ns
        {
            self.invalidated = true;
            return Err(ClockCorrelationError::MonotonicDiscontinuity);
        }
        self.check_live_at(sample.monotonic_after_ns)?;
        let from_origin = local_sample_window(self.origin, sample, self.policy.max_drift_ppb)?;
        let from_previous =
            local_sample_window(self.last_sample, sample, self.policy.max_drift_ppb)?;
        if !from_origin.contains(sample.wall_clock_unix_ns)
            || !from_previous.contains(sample.wall_clock_unix_ns)
        {
            self.invalidated = true;
            return Err(ClockCorrelationError::WallClockDiscontinuity);
        }
        let checked = ClockSampleCheck {
            previous: self.last_sample,
            current: sample,
            from_origin,
            from_previous,
        };
        self.last_sample = sample;
        Ok(checked)
    }

    fn check_live_at(&self, monotonic_ns: u64) -> Result<(), ClockCorrelationError> {
        if self.invalidated {
            return Err(ClockCorrelationError::Invalidated);
        }
        if monotonic_ns < self.origin.monotonic_after_ns {
            return Err(ClockCorrelationError::BeforeSynchronization);
        }
        if monotonic_ns - self.origin.monotonic_before_ns > self.policy.max_age_ns {
            return Err(ClockCorrelationError::Expired);
        }
        Ok(())
    }
}

pub(super) fn validate_sample(
    sample: HostClockSample,
    policy: ClockCorrelationPolicy,
) -> Result<(), ClockCorrelationError> {
    let span = sample
        .monotonic_after_ns
        .checked_sub(sample.monotonic_before_ns)
        .ok_or(ClockCorrelationError::InvalidSample)?;
    if span > policy.max_sample_bracket_ns
        || sample.wall_clock_unix_ns < MIN_PLAUSIBLE_WALL_CLOCK_UNIX_NS
    {
        return Err(ClockCorrelationError::InvalidSample);
    }
    Ok(())
}

pub(super) fn drift_ns(elapsed_ns: u64, max_drift_ppb: u64) -> Result<u64, ClockCorrelationError> {
    let widened = (u128::from(elapsed_ns) * u128::from(max_drift_ppb))
        .div_ceil(u128::from(PARTS_PER_BILLION));
    u64::try_from(widened).map_err(|_| ClockCorrelationError::ArithmeticOverflow)
}

fn interval(earliest: i128, latest: i128) -> Result<UtcInterval, ClockCorrelationError> {
    if earliest > latest {
        return Err(ClockCorrelationError::ArithmeticOverflow);
    }
    Ok(UtcInterval {
        earliest_ns: u64::try_from(earliest)
            .map_err(|_| ClockCorrelationError::ArithmeticOverflow)?,
        latest_ns: u64::try_from(latest).map_err(|_| ClockCorrelationError::ArithmeticOverflow)?,
    })
}

pub(super) fn local_sample_window(
    previous: HostClockSample,
    current: HostClockSample,
    max_drift_ppb: u64,
) -> Result<UtcInterval, ClockCorrelationError> {
    // Exact duplicate samples are admitted as the same observation. There is no
    // elapsed-time, uncertainty or freshness benefit from presenting them twice.
    if current == previous {
        return Ok(UtcInterval {
            earliest_ns: previous.wall_clock_unix_ns,
            latest_ns: previous.wall_clock_unix_ns,
        });
    }
    let earliest_elapsed = current
        .monotonic_before_ns
        .checked_sub(previous.monotonic_after_ns)
        .ok_or(ClockCorrelationError::MonotonicDiscontinuity)?;
    let latest_elapsed = current
        .monotonic_after_ns
        .checked_sub(previous.monotonic_before_ns)
        .ok_or(ClockCorrelationError::MonotonicDiscontinuity)?;
    let drift = drift_ns(latest_elapsed, max_drift_ppb)?;
    interval(
        i128::from(previous.wall_clock_unix_ns) + i128::from(earliest_elapsed) - i128::from(drift),
        i128::from(previous.wall_clock_unix_ns) + i128::from(latest_elapsed) + i128::from(drift),
    )
}
