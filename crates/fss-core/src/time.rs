//! Time intervals that preserve capture uncertainty.

use core::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder};
use crate::{CanonicalEncode, CanonicalEncoder, ContractError};

/// Nanoseconds on a declared clock basis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimestampNs(pub i128);

impl TimestampNs {
    /// Zero timestamp instant.
    pub const ZERO: Self = Self(0);

    /// Adds nanoseconds with overflow check.
    pub fn checked_add_ns(self, delta_ns: i128) -> Result<Self, ContractError> {
        self.0
            .checked_add(delta_ns)
            .map(Self)
            .ok_or(ContractError::InvertedTimeInterval)
    }

    /// Subtracts nanoseconds with overflow check.
    pub fn checked_sub_ns(self, delta_ns: i128) -> Result<Self, ContractError> {
        self.0
            .checked_sub(delta_ns)
            .map(Self)
            .ok_or(ContractError::InvertedTimeInterval)
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

    /// Constructs a degenerate zero-uncertainty point interval where `earliest == latest`.
    #[must_use]
    pub const fn point(timestamp: TimestampNs) -> Self {
        Self {
            earliest: timestamp,
            latest: timestamp,
        }
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
    #[must_use]
    pub fn hull(self, other: Self) -> Self {
        Self {
            earliest: self.earliest.min(other.earliest),
            latest: self.latest.max(other.latest),
        }
    }

    /// Shifts the interval bounds by separate offsets, validating non-inversion.
    pub fn checked_shift(
        self,
        earliest_offset_ns: i128,
        latest_offset_ns: i128,
    ) -> Result<Self, ContractError> {
        let earliest = self.earliest.checked_add_ns(earliest_offset_ns)?;
        let latest = self.latest.checked_add_ns(latest_offset_ns)?;
        Self::new(earliest, latest)
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
    fn inverted_interval_rejected() {
        assert_eq!(
            CaptureInterval::new(TimestampNs(20), TimestampNs(10)),
            Err(ContractError::InvertedTimeInterval)
        );
    }

    #[test]
    fn point_interval_has_zero_uncertainty() {
        let pt = CaptureInterval::point(TimestampNs(500));
        assert_eq!(pt.uncertainty_ns(), 0);
        assert!(pt.contains_timestamp(TimestampNs(500)));
        assert!(!pt.contains_timestamp(TimestampNs(501)));
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
    fn decode_rejects_inverted_interval() {
        let mut encoder = CanonicalEncoder::new();
        TimestampNs(100).encode_canonical(&mut encoder);
        TimestampNs(50).encode_canonical(&mut encoder);
        let bytes = encoder.finish();

        let result = CaptureInterval::from_canonical_bytes(&bytes);
        assert_eq!(result, Err(ContractError::InvertedTimeInterval));
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
