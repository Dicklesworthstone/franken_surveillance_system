//! Time intervals that preserve capture uncertainty.

use crate::{CanonicalEncode, CanonicalEncoder, ContractError};

/// Nanoseconds on a declared clock basis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimestampNs(pub i128);

impl CanonicalEncode for TimestampNs {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.i128(self.0);
    }
}

/// A conservative closed interval within which an observation was captured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

impl CanonicalEncode for CaptureInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.earliest.encode_canonical(encoder);
        self.latest.encode_canonical(encoder);
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
        Ok(())
    }
}
