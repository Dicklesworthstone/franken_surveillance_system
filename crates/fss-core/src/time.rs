//! Time intervals that preserve capture uncertainty and clock-basis semantics.

use core::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder};
pub use crate::evidence::ClockBasis;
use crate::{CanonicalEncode, CanonicalEncoder, ContractError};

impl core::hash::Hash for ClockBasis {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

/// Nanoseconds on a declared clock basis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimestampNs(pub i128);

impl TimestampNs {
    /// Zero timestamp instant.
    pub const ZERO: Self = Self(0);
    /// Minimum representable timestamp.
    pub const MIN: Self = Self(i128::MIN);
    /// Maximum representable timestamp.
    pub const MAX: Self = Self(i128::MAX);

    /// Adds nanoseconds with overflow check, failing closed on overflow with [`ContractError::ArithmeticOverflow`].
    pub fn checked_add_ns(self, delta_ns: i128) -> Result<Self, ContractError> {
        self.0
            .checked_add(delta_ns)
            .map(Self)
            .ok_or(ContractError::ArithmeticOverflow)
    }

    /// Adds nanoseconds with explicit [`TimeIntervalError`] on overflow.
    pub fn checked_add(self, delta_ns: i128) -> Result<Self, TimeIntervalError> {
        self.0
            .checked_add(delta_ns)
            .map(Self)
            .ok_or(TimeIntervalError::ArithmeticOverflow)
    }

    /// Subtracts nanoseconds with overflow check, failing closed on overflow with [`ContractError::ArithmeticOverflow`].
    pub fn checked_sub_ns(self, delta_ns: i128) -> Result<Self, ContractError> {
        self.0
            .checked_sub(delta_ns)
            .map(Self)
            .ok_or(ContractError::ArithmeticOverflow)
    }

    /// Subtracts nanoseconds with explicit [`TimeIntervalError`] on overflow.
    pub fn checked_sub(self, delta_ns: i128) -> Result<Self, TimeIntervalError> {
        self.0
            .checked_sub(delta_ns)
            .map(Self)
            .ok_or(TimeIntervalError::ArithmeticOverflow)
    }

    /// Returns nanoseconds duration between `self` and an earlier timestamp.
    ///
    /// Fails with [`ContractError::InvertedTimeInterval`] if `earlier > self`.
    pub fn checked_duration_since(self, earlier: Self) -> Result<u128, ContractError> {
        if earlier > self {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(self.0.abs_diff(earlier.0))
    }

    /// Returns the absolute difference in nanoseconds between two timestamps.
    #[must_use]
    pub fn abs_diff(self, other: Self) -> u128 {
        self.0.abs_diff(other.0)
    }
}

impl fmt::Display for TimestampNs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ns", self.0)
    }
}

impl CanonicalEncode for TimestampNs {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.i128(self.0);
    }
}

impl CanonicalDecode for TimestampNs {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.i128().map(Self)
    }
}

impl CanonicalEncode for ClockBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::UtcDisciplined => 1,
            Self::DeviceMonotonic => 2,
            Self::HostMonotonic => 3,
            Self::Estimated => 4,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for ClockBasis {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.u8()?;
        match tag {
            1 => Ok(Self::UtcDisciplined),
            2 => Ok(Self::DeviceMonotonic),
            3 => Ok(Self::HostMonotonic),
            4 => Ok(Self::Estimated),
            other => Err(ContractError::UnknownClockBasis(other)),
        }
    }
}

/// Errors arising from conservative time-interval arithmetic and validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TimeIntervalError {
    /// Interval is inverted: earliest > latest.
    InvertedInterval {
        /// Earliest bound.
        earliest: i128,
        /// Latest bound.
        latest: i128,
    },
    /// Arithmetic overflow occurred in i128 nanosecond timestamp calculation.
    ArithmeticOverflow,
    /// Operations attempted across differing clock bases.
    ClockBasisMismatch {
        /// Expected clock basis.
        expected: ClockBasis,
        /// Actual clock basis.
        actual: ClockBasis,
    },
    /// Intervals are disjoint with an uncovered gap; cannot form a single contiguous interval.
    DisjointIntervals {
        /// Uncovered gap in nanoseconds.
        gap_ns: u128,
    },
    /// Monotonicity violation: uncertainty widening attempted to narrow an interval.
    NonMonotoneUncertaintyNarrowing,
    /// Unrecognized canonical encoding tag for clock basis.
    UnknownClockBasis(u8),
}

impl fmt::Display for TimeIntervalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvertedInterval { earliest, latest } => {
                write!(
                    formatter,
                    "inverted time interval: earliest ({earliest}ns) > latest ({latest}ns)"
                )
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("arithmetic overflow in nanosecond timestamp calculation")
            }
            Self::ClockBasisMismatch { expected, actual } => {
                write!(
                    formatter,
                    "clock basis mismatch: expected {expected:?}, actual {actual:?}"
                )
            }
            Self::DisjointIntervals { gap_ns } => {
                write!(
                    formatter,
                    "disjoint time intervals separated by {gap_ns}ns uncovered gap"
                )
            }
            Self::NonMonotoneUncertaintyNarrowing => formatter.write_str(
                "operation attempted to narrow interval uncertainty (monotone widening required)",
            ),
            Self::UnknownClockBasis(tag) => {
                write!(formatter, "unknown canonical clock basis tag: {tag}")
            }
        }
    }
}

impl std::error::Error for TimeIntervalError {}

impl From<TimeIntervalError> for ContractError {
    fn from(err: TimeIntervalError) -> Self {
        match err {
            TimeIntervalError::InvertedInterval { .. } => ContractError::InvertedTimeInterval,
            TimeIntervalError::ArithmeticOverflow => ContractError::ArithmeticOverflow,
            TimeIntervalError::NonMonotoneUncertaintyNarrowing => {
                ContractError::NonMonotoneUncertaintyNarrowing
            }
            TimeIntervalError::ClockBasisMismatch { .. } => ContractError::GenerationConflict,
            TimeIntervalError::DisjointIntervals { .. } => ContractError::CoverageUncertified,
            TimeIntervalError::UnknownClockBasis(tag) => ContractError::UnknownClockBasis(tag),
        }
    }
}

/// Result of computing the union of two conservative time intervals.
///
/// An uncovered gap is NEVER collapsed into a point or contiguous interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IntervalUnion {
    /// The intervals overlap or abut; the union is a single continuous interval.
    Contiguous(CaptureInterval),
    /// The intervals are separated by an uncovered gap of `gap_ns` nanoseconds.
    Disjoint {
        /// The chronologically earlier interval.
        earlier: CaptureInterval,
        /// The chronologically later interval.
        later: CaptureInterval,
        /// The width of the uncovered gap between them in nanoseconds.
        gap_ns: u128,
    },
}

impl IntervalUnion {
    /// Returns true if the union is a single contiguous interval.
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        matches!(self, Self::Contiguous(_))
    }

    /// Returns true if the union contains an uncovered gap.
    #[must_use]
    pub const fn is_disjoint(&self) -> bool {
        matches!(self, Self::Disjoint { .. })
    }

    /// Unwraps the contiguous interval if contiguous, or fails with [`TimeIntervalError::DisjointIntervals`].
    pub fn into_contiguous(self) -> Result<CaptureInterval, TimeIntervalError> {
        match self {
            Self::Contiguous(interval) => Ok(interval),
            Self::Disjoint { gap_ns, .. } => Err(TimeIntervalError::DisjointIntervals { gap_ns }),
        }
    }

    /// Returns the uncovered gap in nanoseconds, or 0 if contiguous.
    #[must_use]
    pub const fn gap_ns(&self) -> u128 {
        match self {
            Self::Contiguous(_) => 0,
            Self::Disjoint { gap_ns, .. } => *gap_ns,
        }
    }
}

/// Result of evaluating whether one conservative capture interval contains another.
///
/// Because intervals represent bounded uncertainty around when an event occurred,
/// a partial boundary overlap leaves containment of the underlying true instant
/// indeterminate without additional evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IntervalContainment {
    /// The subject interval definitely and entirely contains the target.
    Contains,
    /// The subject interval abuts the target (adjacent in discrete nanoseconds with 0ns gap).
    Abutting,
    /// The subject interval is definitely disjoint from the target by an uncovered gap.
    Disjoint {
        /// Distance between the two intervals in nanoseconds (strictly > 0).
        gap_ns: u128,
    },
    /// The subject interval partially overlaps the target's boundary;
    /// containment of the true underlying instant is indeterminate.
    Indeterminate {
        /// The overlapping sub-interval.
        overlap: CaptureInterval,
    },
}

impl IntervalContainment {
    /// Returns true if the target is definitely contained within the subject.
    #[must_use]
    pub const fn is_definite_contains(&self) -> bool {
        matches!(self, Self::Contains)
    }

    /// Returns true if the intervals abut (adjacent with 0ns gap).
    #[must_use]
    pub const fn is_abutting(&self) -> bool {
        matches!(self, Self::Abutting)
    }

    /// Returns true if the intervals are definitely disjoint.
    #[must_use]
    pub const fn is_definite_disjoint(&self) -> bool {
        matches!(self, Self::Disjoint { .. })
    }

    /// Returns true if containment is indeterminate due to boundary overlap.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }
}

/// Temporal precedence relation between two conservative capture intervals.
/// Temporal precedence relation between two conservative capture intervals.
///
/// If intervals have interior overlap, the true event instant in one could have occurred
/// before, at, or after the true event instant in the other (`Indeterminate`).
/// If intervals touch at an exact boundary point, the earlier interval cannot occur after
/// the later interval (`BeforeOrAt`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TemporalPrecedence {
    /// Self is definitely and strictly before other, separated by `gap_ns`.
    Before {
        /// Uncovered gap in nanoseconds between self.latest and other.earliest.
        gap_ns: u128,
    },
    /// Self is definitely and strictly after other, separated by `gap_ns`.
    After {
        /// Uncovered gap in nanoseconds between other.latest and self.earliest.
        gap_ns: u128,
    },
    /// Intervals touch at an exact boundary point (`self.latest == other.earliest`);
    /// self cannot have occurred after other.
    BeforeOrAt {
        /// The exact boundary point in nanoseconds where self.latest == other.earliest.
        point: TimestampNs,
    },
    /// Intervals touch at an exact boundary point (`self.earliest == other.latest`);
    /// self cannot have occurred before other.
    AfterOrAt {
        /// The exact boundary point in nanoseconds where self.earliest == other.latest.
        point: TimestampNs,
    },
    /// Intervals have interior overlap (> 0 duration overlap); relative temporal order
    /// of the underlying events is indeterminate (could be before, at, or after).
    Indeterminate {
        /// The overlapping region.
        overlap: CaptureInterval,
    },
}

impl TemporalPrecedence {
    /// Returns true if self definitely precedes other.
    #[must_use]
    pub const fn is_definitely_before(&self) -> bool {
        matches!(self, Self::Before { .. })
    }

    /// Returns true if self definitely succeeds other.
    #[must_use]
    pub const fn is_definitely_after(&self) -> bool {
        matches!(self, Self::After { .. })
    }

    /// Returns true if intervals touch at boundary and self cannot be after other.
    #[must_use]
    pub const fn is_before_or_at(&self) -> bool {
        matches!(self, Self::BeforeOrAt { .. })
    }

    /// Returns true if intervals touch at boundary and self cannot be before other.
    #[must_use]
    pub const fn is_after_or_at(&self) -> bool {
        matches!(self, Self::AfterOrAt { .. })
    }

    /// Returns true if relative order is indeterminate due to interior overlap.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }

    /// Returns true if self weakly precedes other (strictly before or touching at boundary).
    #[must_use]
    pub const fn is_weakly_before(&self) -> bool {
        matches!(self, Self::Before { .. } | Self::BeforeOrAt { .. })
    }

    /// Returns true if self weakly succeeds other (strictly after or touching at boundary).
    #[must_use]
    pub const fn is_weakly_after(&self) -> bool {
        matches!(self, Self::After { .. } | Self::AfterOrAt { .. })
    }
}

/// A conservative closed interval within which an observation was captured.
///
/// Implements canonical ordering sorted by `(earliest, latest)` so interval sets
/// and indices maintain deterministic order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureInterval {
    /// Earliest possible capture time.
    pub earliest: TimestampNs,
    /// Latest possible capture time.
    pub latest: TimestampNs,
}

impl CaptureInterval {
    /// Constructs a non-inverted interval.
    pub fn new(earliest: TimestampNs, latest: TimestampNs) -> Result<Self, ContractError> {
        if earliest > latest {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(Self { earliest, latest })
    }

    /// Constructs a non-inverted interval, returning typed [`TimeIntervalError`].
    pub fn new_checked(
        earliest: TimestampNs,
        latest: TimestampNs,
    ) -> Result<Self, TimeIntervalError> {
        if earliest > latest {
            return Err(TimeIntervalError::InvertedInterval {
                earliest: earliest.0,
                latest: latest.0,
            });
        }
        Ok(Self { earliest, latest })
    }

    /// Constructs a degenerate zero-uncertainty point interval where `earliest == latest`.
    #[must_use]
    pub const fn point(timestamp: TimestampNs) -> Self {
        Self {
            earliest: timestamp,
            latest: timestamp,
        }
    }

    /// Returns true if the interval is a degenerate point where `earliest == latest`.
    #[must_use]
    pub const fn is_point(self) -> bool {
        self.earliest.0 == self.latest.0
    }

    /// Returns the interval width in nanoseconds.
    #[must_use]
    pub fn uncertainty_ns(self) -> u128 {
        self.latest.0.abs_diff(self.earliest.0)
    }

    /// Returns true when two uncertain intervals can describe the same instant.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.earliest <= other.latest && other.earliest <= self.latest
    }

    /// Returns true when this interval immediately touches another without any gap.
    #[must_use]
    pub fn abuts(self, other: Self) -> bool {
        if self.overlaps(other) {
            return false;
        }
        if self.latest.0 < other.earliest.0 {
            self.latest.0.checked_add(1) == Some(other.earliest.0)
        } else {
            other.latest.0.checked_add(1) == Some(self.earliest.0)
        }
    }

    /// Returns true when this interval contains another interval.
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        self.earliest <= other.earliest && self.latest >= other.latest
    }

    /// Returns true when this interval contains a specific timestamp.
    #[must_use]
    pub fn contains_timestamp(self, ts: TimestampNs) -> bool {
        self.earliest <= ts && ts <= self.latest
    }

    /// Returns the intersection of two intervals, or `None` if they are disjoint.
    #[must_use]
    pub fn intersection(self, other: Self) -> Option<Self> {
        let earliest = self.earliest.max(other.earliest);
        let latest = self.latest.min(other.latest);
        if earliest <= latest {
            Some(Self { earliest, latest })
        } else {
            None
        }
    }

    /// Returns the conservative bounding interval (convex hull) spanning both intervals.
    ///
    /// Note: Unlike [`CaptureInterval::union`], this bridges any uncovered gap.
    /// For gap-preserving semantic combination, use [`CaptureInterval::union`].
    #[must_use]
    pub fn hull(self, other: Self) -> Self {
        let res = Self {
            earliest: self.earliest.min(other.earliest),
            latest: self.latest.max(other.latest),
        };
        // Debug-independent assertion that convex hull never narrows uncertainty
        assert!(
            res.uncertainty_ns() >= self.uncertainty_ns()
                && res.uncertainty_ns() >= other.uncertainty_ns(),
            "convex hull narrowed uncertainty"
        );
        res
    }

    /// Rigidly shifts both interval bounds by `delta_ns`, preserving interval width.
    ///
    /// Fails closed on arithmetic overflow with [`ContractError::ArithmeticOverflow`].
    pub fn checked_shift(self, delta_ns: i128) -> Result<Self, ContractError> {
        let earliest = self.earliest.checked_add_ns(delta_ns)?;
        let latest = self.latest.checked_add_ns(delta_ns)?;
        let res = Self::new(earliest, latest)?;
        // Debug-independent assertion that rigid shift preserves uncertainty
        assert_eq!(
            res.uncertainty_ns(),
            self.uncertainty_ns(),
            "rigid shift narrowed uncertainty"
        );
        Ok(res)
    }

    /// Rigidly shifts both bounds by `delta_ns`, preserving interval width.
    pub fn checked_translate(self, delta_ns: i128) -> Result<Self, ContractError> {
        self.checked_shift(delta_ns)
    }

    /// Computes the union of two intervals.
    ///
    /// If the intervals overlap or abut, produces a contiguous [`CaptureInterval`].
    /// If the intervals are disjoint, preserves the uncovered gap as [`IntervalUnion::Disjoint`].
    /// Never collapses an uncovered gap into a point.
    #[must_use]
    pub fn union(self, other: Self) -> IntervalUnion {
        if self.overlaps(other) || self.abuts(other) {
            let res = Self {
                earliest: self.earliest.min(other.earliest),
                latest: self.latest.max(other.latest),
            };
            // Debug-independent assertion that contiguous union never narrows uncertainty
            assert!(
                res.uncertainty_ns() >= self.uncertainty_ns()
                    && res.uncertainty_ns() >= other.uncertainty_ns(),
                "contiguous union narrowed uncertainty"
            );
            IntervalUnion::Contiguous(res)
        } else if self.latest < other.earliest {
            let diff = other.earliest.0.abs_diff(self.latest.0);
            let gap_ns = diff.saturating_sub(1);
            IntervalUnion::Disjoint {
                earlier: self,
                later: other,
                gap_ns,
            }
        } else {
            let diff = self.earliest.0.abs_diff(other.latest.0);
            let gap_ns = diff.saturating_sub(1);
            IntervalUnion::Disjoint {
                earlier: other,
                later: self,
                gap_ns,
            }
        }
    }

    /// Computes contiguous union, failing closed if intervals are separated by an uncovered gap.
    pub fn checked_contiguous_union(self, other: Self) -> Result<Self, TimeIntervalError> {
        self.union(other).into_contiguous()
    }

    /// Classifies containment of `other` within `self`.
    #[must_use]
    pub fn classify_containment(self, other: Self) -> IntervalContainment {
        if self.earliest <= other.earliest && other.latest <= self.latest {
            IntervalContainment::Contains
        } else if self.abuts(other) {
            IntervalContainment::Abutting
        } else if !self.overlaps(other) {
            let diff = if other.latest < self.earliest {
                self.earliest.0.abs_diff(other.latest.0)
            } else {
                other.earliest.0.abs_diff(self.latest.0)
            };
            let gap_ns = diff.saturating_sub(1);
            IntervalContainment::Disjoint { gap_ns }
        } else {
            let earliest = self.earliest.max(other.earliest);
            let latest = self.latest.min(other.latest);
            IntervalContainment::Indeterminate {
                overlap: Self { earliest, latest },
            }
        }
    }

    /// Evaluates temporal precedence between `self` and `other`.
    #[must_use]
    pub fn temporal_precedence(self, other: Self) -> TemporalPrecedence {
        if self.latest < other.earliest {
            let diff = other.earliest.0.abs_diff(self.latest.0);
            let gap_ns = diff.saturating_sub(1);
            TemporalPrecedence::Before { gap_ns }
        } else if self.earliest > other.latest {
            let diff = self.earliest.0.abs_diff(other.latest.0);
            let gap_ns = diff.saturating_sub(1);
            TemporalPrecedence::After { gap_ns }
        } else if self.latest == other.earliest {
            TemporalPrecedence::BeforeOrAt { point: self.latest }
        } else if self.earliest == other.latest {
            TemporalPrecedence::AfterOrAt {
                point: self.earliest,
            }
        } else {
            let earliest = self.earliest.max(other.earliest);
            let latest = self.latest.min(other.latest);
            TemporalPrecedence::Indeterminate {
                overlap: Self { earliest, latest },
            }
        }
    }

    /// Returns true if self is strictly before other (`self.latest < other.earliest`).
    #[must_use]
    pub fn is_strictly_before(self, other: Self) -> bool {
        self.latest < other.earliest
    }

    /// Returns true if self is strictly after other (`self.earliest > other.latest`).
    #[must_use]
    pub fn is_strictly_after(self, other: Self) -> bool {
        self.earliest > other.latest
    }

    /// Conservative clock skew widening: widens both earliest and latest bounds by `max_skew_ns`.
    ///
    /// Monotonic: uncertainty always widens or stays equal, never narrows.
    /// Fails closed on arithmetic overflow.
    pub fn widen_skew(self, max_skew_ns: u128) -> Result<Self, TimeIntervalError> {
        if max_skew_ns > (i128::MAX as u128) {
            return Err(TimeIntervalError::ArithmeticOverflow);
        }
        let skew = max_skew_ns as i128;
        let new_earliest = self
            .earliest
            .0
            .checked_sub(skew)
            .ok_or(TimeIntervalError::ArithmeticOverflow)?;
        let new_latest = self
            .latest
            .0
            .checked_add(skew)
            .ok_or(TimeIntervalError::ArithmeticOverflow)?;
        let widened = Self {
            earliest: TimestampNs(new_earliest),
            latest: TimestampNs(new_latest),
        };
        if widened.uncertainty_ns() < self.uncertainty_ns() {
            return Err(TimeIntervalError::NonMonotoneUncertaintyNarrowing);
        }
        Ok(widened)
    }

    /// Conservative asymmetric uncertainty widening: widens earlier bound by `earlier_ns`
    /// and later bound by `later_ns`.
    ///
    /// Fails closed on arithmetic overflow.
    pub fn widen_asymmetric(
        self,
        earlier_ns: u128,
        later_ns: u128,
    ) -> Result<Self, TimeIntervalError> {
        if earlier_ns > (i128::MAX as u128) || later_ns > (i128::MAX as u128) {
            return Err(TimeIntervalError::ArithmeticOverflow);
        }
        let earlier_delta = earlier_ns as i128;
        let later_delta = later_ns as i128;
        let new_earliest = self
            .earliest
            .0
            .checked_sub(earlier_delta)
            .ok_or(TimeIntervalError::ArithmeticOverflow)?;
        let new_latest = self
            .latest
            .0
            .checked_add(later_delta)
            .ok_or(TimeIntervalError::ArithmeticOverflow)?;
        let widened = Self {
            earliest: TimestampNs(new_earliest),
            latest: TimestampNs(new_latest),
        };
        if widened.uncertainty_ns() < self.uncertainty_ns() {
            return Err(TimeIntervalError::NonMonotoneUncertaintyNarrowing);
        }
        Ok(widened)
    }

    /// Applies widening deltas, enforcing that the operation is strictly monotone
    /// (an operation may never narrow an interval).
    pub fn apply_monotone_widening(
        self,
        earliest_widening_ns: u128,
        latest_widening_ns: u128,
    ) -> Result<Self, TimeIntervalError> {
        self.widen_asymmetric(earliest_widening_ns, latest_widening_ns)
    }

    /// Computes interval union after verifying that both operands share the same clock basis.
    pub fn union_with_basis(
        self,
        self_basis: ClockBasis,
        other: Self,
        other_basis: ClockBasis,
    ) -> Result<IntervalUnion, TimeIntervalError> {
        if self_basis != other_basis {
            return Err(TimeIntervalError::ClockBasisMismatch {
                expected: self_basis,
                actual: other_basis,
            });
        }
        Ok(self.union(other))
    }

    /// Computes interval intersection after verifying that both operands share the same clock basis.
    pub fn intersection_with_basis(
        self,
        self_basis: ClockBasis,
        other: Self,
        other_basis: ClockBasis,
    ) -> Result<Option<Self>, TimeIntervalError> {
        if self_basis != other_basis {
            return Err(TimeIntervalError::ClockBasisMismatch {
                expected: self_basis,
                actual: other_basis,
            });
        }
        Ok(self.intersection(other))
    }

    /// Evaluates containment after verifying that both operands share the same clock basis.
    pub fn containment_with_basis(
        self,
        self_basis: ClockBasis,
        other: Self,
        other_basis: ClockBasis,
    ) -> Result<IntervalContainment, TimeIntervalError> {
        if self_basis != other_basis {
            return Err(TimeIntervalError::ClockBasisMismatch {
                expected: self_basis,
                actual: other_basis,
            });
        }
        Ok(self.classify_containment(other))
    }

    /// Evaluates temporal precedence after verifying that both operands share the same clock basis.
    pub fn temporal_precedence_with_basis(
        self,
        self_basis: ClockBasis,
        other: Self,
        other_basis: ClockBasis,
    ) -> Result<TemporalPrecedence, TimeIntervalError> {
        if self_basis != other_basis {
            return Err(TimeIntervalError::ClockBasisMismatch {
                expected: self_basis,
                actual: other_basis,
            });
        }
        Ok(self.temporal_precedence(other))
    }
}

impl fmt::Display for CaptureInterval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}, {}]", self.earliest, self.latest)
    }
}

impl CanonicalEncode for CaptureInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.earliest.encode_canonical(encoder);
        self.latest.encode_canonical(encoder);
    }
}

impl CanonicalDecode for CaptureInterval {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let earliest = TimestampNs::decode_canonical(decoder)?;
        let latest = TimestampNs::decode_canonical(decoder)?;
        Self::new(earliest, latest)
    }
}

/// A conservative capture interval with an explicit declared clock basis.
///
/// Invariant: cross-basis operations require identical clock bases and reject mismatches.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureIntervalWithBasis {
    /// Closed interval bounds.
    pub interval: CaptureInterval,
    /// Declared clock basis.
    pub basis: ClockBasis,
}

impl CaptureIntervalWithBasis {
    /// Constructs an interval on a declared clock basis.
    #[must_use]
    pub const fn new(interval: CaptureInterval, basis: ClockBasis) -> Self {
        Self { interval, basis }
    }

    /// Verifies clock bases match, returning [`TimeIntervalError::ClockBasisMismatch`] if not.
    pub fn check_clock_basis(&self, other: &Self) -> Result<(), TimeIntervalError> {
        if self.basis != other.basis {
            return Err(TimeIntervalError::ClockBasisMismatch {
                expected: self.basis,
                actual: other.basis,
            });
        }
        Ok(())
    }

    /// Computes the union of two intervals on the same clock basis.
    pub fn union(&self, other: &Self) -> Result<IntervalUnion, TimeIntervalError> {
        self.check_clock_basis(other)?;
        Ok(self.interval.union(other.interval))
    }

    /// Computes the intersection of two intervals on the same clock basis.
    pub fn intersection(&self, other: &Self) -> Result<Option<CaptureInterval>, TimeIntervalError> {
        self.check_clock_basis(other)?;
        Ok(self.interval.intersection(other.interval))
    }

    /// Evaluates containment of `other` within `self` on the same clock basis.
    pub fn containment(&self, other: &Self) -> Result<IntervalContainment, TimeIntervalError> {
        self.check_clock_basis(other)?;
        Ok(self.interval.classify_containment(other.interval))
    }

    /// Evaluates temporal precedence between `self` and `other` on the same clock basis.
    pub fn temporal_precedence(
        &self,
        other: &Self,
    ) -> Result<TemporalPrecedence, TimeIntervalError> {
        self.check_clock_basis(other)?;
        Ok(self.interval.temporal_precedence(other.interval))
    }

    /// Monotonically widens uncertainty to account for clock skew.
    pub fn widen_skew(&self, max_skew_ns: u128) -> Result<Self, TimeIntervalError> {
        let interval = self.interval.widen_skew(max_skew_ns)?;
        Ok(Self {
            interval,
            basis: self.basis,
        })
    }

    /// Monotonically widens uncertainty with asymmetric bounds.
    pub fn widen_asymmetric(
        &self,
        earlier_ns: u128,
        later_ns: u128,
    ) -> Result<Self, TimeIntervalError> {
        let interval = self.interval.widen_asymmetric(earlier_ns, later_ns)?;
        Ok(Self {
            interval,
            basis: self.basis,
        })
    }
}

impl CanonicalEncode for CaptureIntervalWithBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.interval.encode_canonical(encoder);
        self.basis.encode_canonical(encoder);
    }
}

impl CanonicalDecode for CaptureIntervalWithBasis {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let interval = CaptureInterval::decode_canonical(decoder)?;
        let basis = ClockBasis::decode_canonical(decoder)?;
        Ok(Self { interval, basis })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_preserve_uncertainty() -> Result<(), ContractError> {
        let first = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
        let second = CaptureInterval::new(TimestampNs(19), TimestampNs(30))?;
        assert_eq!(first.uncertainty_ns(), 10);
        assert!(first.overlaps(second));
        assert!(first.contains_timestamp(TimestampNs(15)));
        assert!(!first.contains_timestamp(TimestampNs(25)));
        Ok(())
    }

    #[test]
    fn inverted_interval_rejected() -> Result<(), ContractError> {
        let res = CaptureInterval::new(TimestampNs(20), TimestampNs(10));
        assert_eq!(res, Err(ContractError::InvertedTimeInterval));
        Ok(())
    }

    #[test]
    fn point_interval_has_zero_uncertainty() -> Result<(), ContractError> {
        let pt = CaptureInterval::point(TimestampNs(500));
        assert_eq!(pt.uncertainty_ns(), 0);
        assert!(pt.is_point());
        assert!(pt.contains_timestamp(TimestampNs(500)));
        assert!(!pt.contains_timestamp(TimestampNs(501)));
        Ok(())
    }

    #[test]
    fn intersection_and_hull() -> Result<(), ContractError> {
        let a = CaptureInterval::new(TimestampNs(10), TimestampNs(30))?;
        let b = CaptureInterval::new(TimestampNs(20), TimestampNs(40))?;
        let c = CaptureInterval::new(TimestampNs(50), TimestampNs(60))?;

        let isect = a.intersection(b);
        assert_eq!(
            isect,
            Some(CaptureInterval::new(TimestampNs(20), TimestampNs(30))?)
        );
        assert_eq!(a.intersection(c), None);

        let hull_ac = a.hull(c);
        assert_eq!(
            hull_ac,
            CaptureInterval::new(TimestampNs(10), TimestampNs(60))?
        );
        Ok(())
    }

    #[test]
    fn canonical_encode_decode_round_trip() -> Result<(), ContractError> {
        let interval = CaptureInterval::new(TimestampNs(-100), TimestampNs(250))?;
        let bytes = interval.canonical_bytes();

        let decoded = CaptureInterval::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded, interval);
        Ok(())
    }

    #[test]
    fn decode_rejects_inverted_interval() -> Result<(), ContractError> {
        let mut encoder = CanonicalEncoder::new();
        TimestampNs(100).encode_canonical(&mut encoder);
        TimestampNs(50).encode_canonical(&mut encoder);
        let bytes = encoder.finish();

        let result = CaptureInterval::from_canonical_bytes(&bytes);
        assert_eq!(result, Err(ContractError::InvertedTimeInterval));
        Ok(())
    }

    #[test]
    fn canonical_ordering() -> Result<(), ContractError> {
        let i1 = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
        let i2 = CaptureInterval::new(TimestampNs(10), TimestampNs(30))?;
        let i3 = CaptureInterval::new(TimestampNs(15), TimestampNs(20))?;

        assert!(i1 < i2);
        assert!(i2 < i3);
        assert!(i1 < i3);
        Ok(())
    }
}
