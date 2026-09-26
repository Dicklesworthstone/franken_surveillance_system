#![forbid(unsafe_code)]
//! Retention deadlines are owner assertions in Unix nanoseconds, never sensor capture hints.
//! Eligibility is evaluated conservatively over an explicitly supplied time interval. It is
//! only a proposal: even an eligible deadline remains an active hold until approved expiry.

use fss_core::{CanonicalDecoder, CanonicalEncoder, CaptureInterval, TimestampNs};

use super::{HOLD_DEADLINE_DOMAIN, HOLD_DOMAIN, HoldError};

/// One-way lifecycle of a site-local hold identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldState {
    /// Preserve the named import's current and later retained derivative closure indefinitely.
    Held,
    /// Explicitly released indefinite hold. No content is deleted by this transition.
    Released,
    /// Preserve at least until the specified Unix-nanosecond deadline. The hold remains active
    /// afterward until an exact, time-attested expiry is approved; ordinary release is refused.
    Until {
        /// Earliest permitted expiry, inclusive, in the owner's declared UTC coordinate system.
        not_before: TimestampNs,
    },
    /// Explicitly approved expiry of a deadline hold. The owner's time assertion is retained
    /// verbatim; this is not an independently authenticated or calibrated clock measurement.
    Expired {
        /// Exact deadline of the predecessor, never a replacement or shortened deadline.
        not_before: TimestampNs,
        /// Owner-attested current time bounds in Unix nanoseconds, not media capture time.
        attested_now: CaptureInterval,
    },
}

/// Read-only evaluation of a hold under an owner-attested time interval. None grants deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionReadiness {
    /// An indefinite hold requires an explicit release, never clock-based expiry.
    ExplicitReleaseRequired,
    /// Even the latest attested time is before the deadline.
    NotDue,
    /// The attested interval straddles the deadline; expiry is refused.
    TimeUncertain,
    /// The earliest attested time reached the deadline, but approved expiry is still required.
    EligibleForExpiry,
    /// This identifier already has a terminal release or expiry record.
    Terminal,
}

impl RetentionReadiness {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitReleaseRequired => "explicit_release_required",
            Self::NotDue => "not_due",
            Self::TimeUncertain => "time_uncertain",
            Self::EligibleForExpiry => "eligible_for_expiry",
            Self::Terminal => "terminal",
        }
    }
}

impl HoldState {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Released => "released",
            Self::Until { .. } => "retained_until",
            Self::Expired { .. } => "expired",
        }
    }

    /// Whether deletion must still respect this hold, irrespective of wall-clock time.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Held | Self::Until { .. })
    }

    /// Owner-declared minimum-retention deadline, including on a terminal expiry record.
    #[must_use]
    pub const fn not_before(self) -> Option<TimestampNs> {
        match self {
            Self::Until { not_before } | Self::Expired { not_before, .. } => Some(not_before),
            Self::Held | Self::Released => None,
        }
    }

    /// Time assertion retained with an expiry. There is no implicit system-clock read.
    #[must_use]
    pub const fn attested_now(self) -> Option<CaptureInterval> {
        match self {
            Self::Expired { attested_now, .. } => Some(attested_now),
            _ => None,
        }
    }

    /// Evaluate eligibility without releasing a hold, changing authority or inferring time.
    /// All 128 timestamp bits are compared directly: no midpoint or overflowing subtraction.
    pub fn readiness(self, attested_now: CaptureInterval) -> Result<RetentionReadiness, HoldError> {
        CaptureInterval::new(attested_now.earliest, attested_now.latest)?;
        Ok(match self {
            Self::Held => RetentionReadiness::ExplicitReleaseRequired,
            Self::Released | Self::Expired { .. } => RetentionReadiness::Terminal,
            Self::Until { not_before } if attested_now.earliest >= not_before => {
                RetentionReadiness::EligibleForExpiry
            }
            Self::Until { not_before } if attested_now.latest < not_before => {
                RetentionReadiness::NotDue
            }
            Self::Until { .. } => RetentionReadiness::TimeUncertain,
        })
    }

    pub(super) fn validate(self) -> Result<(), HoldError> {
        if let Self::Expired {
            not_before,
            attested_now,
        } = self
            && (Self::Until { not_before }).readiness(attested_now)?
                != RetentionReadiness::EligibleForExpiry
        {
            return Err(HoldError::RetentionNotElapsed);
        }
        Ok(())
    }

    pub(super) const fn generation(self) -> u64 {
        if self.is_active() { 1 } else { 2 }
    }

    /// The same rule is used in preview and history reconstruction. No downgrade to an
    /// ordinary hold, deadline replacement, premature expiry, or cross-kind release is legal.
    pub(super) fn permits_successor(self, next: Self) -> bool {
        if next.validate().is_err() {
            return false;
        }
        match (self, next) {
            (Self::Held, Self::Released) => true,
            (
                Self::Until { not_before },
                Self::Expired {
                    not_before: next_deadline,
                    ..
                },
            ) => not_before == next_deadline,
            _ => false,
        }
    }

    pub(super) const fn wire_version(self) -> u32 {
        match self {
            Self::Held | Self::Released => 1,
            Self::Until { .. } | Self::Expired { .. } => 2,
        }
    }

    /// Versioned payload domain. The hold object namespace itself stays unchanged.
    #[must_use]
    pub const fn record_domain(self) -> &'static str {
        match self.wire_version() {
            1 => HOLD_DOMAIN,
            _ => HOLD_DEADLINE_DOMAIN,
        }
    }

    pub(super) fn encode(self, e: &mut CanonicalEncoder) {
        match self {
            Self::Held => e.u8(0),
            Self::Released => e.u8(1),
            Self::Until { not_before } => {
                e.u8(2);
                e.i128(not_before.0);
            }
            Self::Expired {
                not_before,
                attested_now,
            } => {
                e.u8(3);
                e.i128(not_before.0);
                e.i128(attested_now.earliest.0);
                e.i128(attested_now.latest.0);
            }
        }
    }

    pub(super) fn decode(version: u32, d: &mut CanonicalDecoder<'_>) -> Result<Self, HoldError> {
        let state = match (version, d.u8()?) {
            (1, 0) => Self::Held,
            (1, 1) => Self::Released,
            (2, 2) => Self::Until {
                not_before: TimestampNs(d.i128()?),
            },
            (2, 3) => Self::Expired {
                not_before: TimestampNs(d.i128()?),
                attested_now: CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?,
            },
            _ => return Err(HoldError::InvalidRecord),
        };
        state.validate().map_err(|_| HoldError::InvalidRecord)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(first: i128, last: i128) -> CaptureInterval {
        CaptureInterval {
            earliest: TimestampNs(first),
            latest: TimestampNs(last),
        }
    }

    #[test]
    fn expiry_uses_the_earliest_bound_and_keeps_eligibility_distinct_from_release()
    -> Result<(), HoldError> {
        let state = HoldState::Until {
            not_before: TimestampNs(10),
        };
        for (bounds, expected) in [
            ((8, 9), RetentionReadiness::NotDue),
            ((9, 10), RetentionReadiness::TimeUncertain),
            ((9, 11), RetentionReadiness::TimeUncertain),
            ((10, 10), RetentionReadiness::EligibleForExpiry),
            ((10, 11), RetentionReadiness::EligibleForExpiry),
        ] {
            let now = time(bounds.0, bounds.1);
            assert_eq!(state.readiness(now)?, expected);
            let next = HoldState::Expired {
                not_before: TimestampNs(10),
                attested_now: now,
            };
            assert_eq!(
                state.permits_successor(next),
                expected == RetentionReadiness::EligibleForExpiry
            );
            assert!(state.is_active());
        }
        Ok(())
    }

    #[test]
    fn lifecycle_never_shortens_converts_or_implicitly_releases_a_hold() {
        let until = HoldState::Until {
            not_before: TimestampNs(10),
        };
        let expired = HoldState::Expired {
            not_before: TimestampNs(10),
            attested_now: time(10, 12),
        };
        let states = [HoldState::Held, HoldState::Released, until, expired];
        for (i, from) in states.iter().enumerate() {
            for (j, to) in states.iter().enumerate() {
                assert_eq!(
                    from.permits_successor(*to),
                    (i, j) == (0, 1) || (i, j) == (2, 3)
                );
            }
        }
        assert!(!until.permits_successor(HoldState::Expired {
            not_before: TimestampNs(9),
            attested_now: time(10, 12)
        }));
        assert!(!until.permits_successor(HoldState::Expired {
            not_before: TimestampNs(11),
            attested_now: time(12, 12)
        }));
    }

    #[test]
    fn full_width_times_and_invalid_intervals_do_not_overflow() -> Result<(), HoldError> {
        let min = HoldState::Until {
            not_before: TimestampNs(i128::MIN),
        };
        let max = HoldState::Until {
            not_before: TimestampNs(i128::MAX),
        };
        assert_eq!(
            min.readiness(time(i128::MIN, i128::MAX))?,
            RetentionReadiness::EligibleForExpiry
        );
        assert_eq!(
            max.readiness(time(i128::MIN, i128::MAX))?,
            RetentionReadiness::TimeUncertain
        );
        assert_eq!(
            max.readiness(time(i128::MAX, i128::MAX))?,
            RetentionReadiness::EligibleForExpiry
        );
        assert!(max.readiness(time(1, 0)).is_err());
        assert!(HoldState::Held.readiness(time(1, 0)).is_err());
        Ok(())
    }

    #[test]
    fn state_codec_keeps_v1_bytes_and_rejects_cross_version_tags() -> Result<(), HoldError> {
        for state in [
            HoldState::Held,
            HoldState::Released,
            HoldState::Until {
                not_before: TimestampNs(i128::MIN),
            },
            HoldState::Expired {
                not_before: TimestampNs(i128::MAX),
                attested_now: time(i128::MAX, i128::MAX),
            },
        ] {
            let mut e = CanonicalEncoder::new();
            state.encode(&mut e);
            let bytes = e.finish();
            let mut d = CanonicalDecoder::new(&bytes);
            assert_eq!(HoldState::decode(state.wire_version(), &mut d)?, state);
            d.ensure_finished()?;
            let wrong = if state.wire_version() == 1 { 2 } else { 1 };
            assert!(HoldState::decode(wrong, &mut CanonicalDecoder::new(&bytes)).is_err());
        }
        Ok(())
    }
}
