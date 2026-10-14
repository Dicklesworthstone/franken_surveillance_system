#![forbid(unsafe_code)]
//! Whole-supervision admission accounting, separate from observed socket usage.
//!
//! Reserve a connection's complete declared byte/call/work ceilings before it
//! can open a socket. Reservations never refund at EOF, connect failure, retry,
//! or cancellation. This conservative reference contract does not confuse a
//! retirement acknowledgement with proof that unused capacity can be reclaimed.

use crate::rtsp::tcp::TcpLimits;
use std::fmt;

/// Independent aggregate ceilings for all admitted native connection attempts.
/// These values limit admission; they neither grant network authority nor claim
/// that the reserved bytes were actually transferred or durably retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectBudget {
    /// Sum of the admitted connections' maximum received bytes.
    pub received_bytes: u64,
    /// Sum of the admitted connections' maximum sent bytes.
    pub sent_bytes: u64,
    /// Sum of the admitted connections' combined read/write call ceilings.
    pub io_calls: u64,
    /// Sum of the admitted connections' native driver-step ceilings.
    /// The reconnect scheduler's own step allowance remains independent.
    pub connection_steps: u64,
}

/// The first component that refused an atomic reservation, in canonical order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectBudgetDimension {
    /// Native receive-byte allowance.
    ReceivedBytes,
    /// Native send-byte allowance.
    SentBytes,
    /// Native read/write call allowance.
    IoCalls,
    /// Native connection driver-work allowance.
    ConnectionSteps,
}

/// Payload-free refusal; a failed reservation changes no resource accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectBudgetRefusal {
    /// Empty grant, invalid native limits, or invalid finite attempt count.
    Configuration,
    /// A declared aggregate cannot be represented; never saturate an approval.
    Overflow(ReconnectBudgetDimension),
    /// The complete next attempt does not fit the remaining aggregate grant.
    /// Supply an explicitly smaller native allowance or obtain a new grant.
    Exhausted(ReconnectBudgetDimension),
}
impl fmt::Display for ReconnectBudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP reconnect resource refusal: {self:?}")
    }
}
impl std::error::Error for ReconnectBudgetRefusal {}

impl ReconnectBudget {
    const ZERO: Self = Self {
        received_bytes: 0,
        sent_bytes: 0,
        io_calls: 0,
        connection_steps: 0,
    };

    /// Price the worst-case aggregate for a finite, unchanged native profile.
    /// This is a pure calculation, not an authority or I/O operation.
    pub fn for_attempts(
        transport: TcpLimits,
        connection_steps: u64,
        attempts: u32,
    ) -> Result<Self, ReconnectBudgetRefusal> {
        if !(1..=1024).contains(&attempts) {
            return Err(ReconnectBudgetRefusal::Configuration);
        }
        Self::connection(transport, connection_steps)?.scale(attempts)
    }

    /// A supplied whole-run grant must explicitly allow every native dimension.
    /// A zero-valued usage snapshot is valid accounting, but is not a grant.
    pub fn validate(self) -> Result<(), ReconnectBudgetRefusal> {
        if self.received_bytes == 0
            || self.sent_bytes == 0
            || self.io_calls == 0
            || self.connection_steps == 0
        {
            return Err(ReconnectBudgetRefusal::Configuration);
        }
        Ok(())
    }

    pub(super) fn connection(
        transport: TcpLimits,
        connection_steps: u64,
    ) -> Result<Self, ReconnectBudgetRefusal> {
        transport
            .validate()
            .map_err(|_| ReconnectBudgetRefusal::Configuration)?;
        let cost = Self {
            received_bytes: transport.max_received_bytes,
            sent_bytes: transport.max_sent_bytes,
            io_calls: transport.max_io_calls,
            connection_steps,
        };
        cost.validate()?;
        Ok(cost)
    }

    fn scale(self, attempts: u32) -> Result<Self, ReconnectBudgetRefusal> {
        use ReconnectBudgetDimension as D;
        let multiply = |value: u64, dimension| {
            value
                .checked_mul(u64::from(attempts))
                .ok_or(ReconnectBudgetRefusal::Overflow(dimension))
        };
        Ok(Self {
            received_bytes: multiply(self.received_bytes, D::ReceivedBytes)?,
            sent_bytes: multiply(self.sent_bytes, D::SentBytes)?,
            io_calls: multiply(self.io_calls, D::IoCalls)?,
            connection_steps: multiply(self.connection_steps, D::ConnectionSteps)?,
        })
    }

    fn plus(self, cost: Self, limit: Self) -> Result<Self, ReconnectBudgetRefusal> {
        use ReconnectBudgetDimension as D;
        let add = |used: u64, amount: u64, maximum: u64, dimension| {
            let next = used
                .checked_add(amount)
                .ok_or(ReconnectBudgetRefusal::Overflow(dimension))?;
            if next > maximum {
                return Err(ReconnectBudgetRefusal::Exhausted(dimension));
            }
            Ok(next)
        };
        Ok(Self {
            received_bytes: add(
                self.received_bytes,
                cost.received_bytes,
                limit.received_bytes,
                D::ReceivedBytes,
            )?,
            sent_bytes: add(self.sent_bytes, cost.sent_bytes, limit.sent_bytes, D::SentBytes)?,
            io_calls: add(self.io_calls, cost.io_calls, limit.io_calls, D::IoCalls)?,
            connection_steps: add(
                self.connection_steps,
                cost.connection_steps,
                limit.connection_steps,
                D::ConnectionSteps,
            )?,
        })
    }
}

/// Read-only admission snapshot. Observed TCP totals remain with each original
/// native owner/retirement; these reservations must never be reported as usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectBudgetState {
    limit: Option<ReconnectBudget>,
    reserved: ReconnectBudget,
    attempts: u32,
}
impl ReconnectBudgetState {
    /// Fixed whole-run ceiling. An automatic grant is unknown until the first
    /// connection profile is successfully reserved, not an unlimited allowance.
    pub fn limit(self) -> Option<ReconnectBudget> {
        self.limit
    }

    /// Irreversibly admitted maxima, including failed connection attempts.
    pub fn reserved(self) -> ReconnectBudget {
        self.reserved
    }

    /// Number of completely admitted resource reservations.
    pub fn admitted_attempts(self) -> u32 {
        self.attempts
    }

    /// Capacity that can still be explicitly assigned to later attempts.
    /// None means no first profile has established an automatic whole-run grant.
    pub fn remaining(self) -> Option<ReconnectBudget> {
        let limit = self.limit?;
        Some(ReconnectBudget {
            received_bytes: limit.received_bytes.checked_sub(self.reserved.received_bytes)?,
            sent_bytes: limit.sent_bytes.checked_sub(self.reserved.sent_bytes)?,
            io_calls: limit.io_calls.checked_sub(self.reserved.io_calls)?,
            connection_steps: limit
                .connection_steps
                .checked_sub(self.reserved.connection_steps)?,
        })
    }
}

// The scheduler is the only production mutator. There is deliberately no reset,
// refund, mutable snapshot, or method granting network authority.
#[derive(Debug)]
pub(super) struct ReservationLedger {
    state: ReconnectBudgetState,
}
impl ReservationLedger {
    pub(super) fn automatic() -> Self {
        Self {
            state: ReconnectBudgetState {
                limit: None,
                reserved: ReconnectBudget::ZERO,
                attempts: 0,
            },
        }
    }

    pub(super) fn bounded(limit: ReconnectBudget) -> Result<Self, ReconnectBudgetRefusal> {
        limit.validate()?;
        Ok(Self {
            state: ReconnectBudgetState {
                limit: Some(limit),
                reserved: ReconnectBudget::ZERO,
                attempts: 0,
            },
        })
    }

    pub(super) fn state(&self) -> ReconnectBudgetState {
        self.state
    }

    pub(super) fn reserve(
        &mut self,
        cost: ReconnectBudget,
        maximum_attempts: u32,
    ) -> Result<(), ReconnectBudgetRefusal> {
        cost.validate()?;
        if !(1..=1024).contains(&maximum_attempts) || self.state.attempts >= maximum_attempts {
            return Err(ReconnectBudgetRefusal::Configuration);
        }
        let limit = match self.state.limit {
            Some(limit) => limit,
            None => cost.scale(maximum_attempts)?,
        };
        // Build a complete candidate before mutating any dimension or first-profile pin.
        let reserved = self.state.reserved.plus(cost, limit)?;
        self.state = ReconnectBudgetState {
            limit: Some(limit),
            reserved,
            attempts: self.state.attempts + 1,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(n: u64) -> ReconnectBudget {
        ReconnectBudget {
            received_bytes: n,
            sent_bytes: n,
            io_calls: n,
            connection_steps: n,
        }
    }

    #[test]
    fn every_dimension_refuses_atomically_without_refunding_previous_attempts()
    -> Result<(), ReconnectBudgetRefusal> {
        use ReconnectBudgetDimension as D;
        for dimension in [D::ReceivedBytes, D::SentBytes, D::IoCalls, D::ConnectionSteps] {
            let mut ledger = ReservationLedger::bounded(budget(10))?;
            ledger.reserve(budget(4), 4)?;
            let before = ledger.state();
            let mut excessive = budget(1);
            match dimension {
                D::ReceivedBytes => excessive.received_bytes = 7,
                D::SentBytes => excessive.sent_bytes = 7,
                D::IoCalls => excessive.io_calls = 7,
                D::ConnectionSteps => excessive.connection_steps = 7,
            }
            assert_eq!(
                ledger.reserve(excessive, 4),
                Err(ReconnectBudgetRefusal::Exhausted(dimension))
            );
            assert_eq!(ledger.state(), before);
            ledger.reserve(budget(6), 4)?;
            assert_eq!(ledger.state().admitted_attempts(), 2);
            assert_eq!(ledger.state().remaining(), Some(budget(0)));
            assert!(ledger.reserve(budget(1), 4).is_err());
            assert_eq!(ledger.state().reserved(), budget(10));
        }
        Ok(())
    }

    #[test]
    fn automatic_aggregate_is_pinned_once_and_smaller_attempts_do_not_reprice_it()
    -> Result<(), ReconnectBudgetRefusal> {
        let mut ledger = ReservationLedger::automatic();
        assert_eq!(ledger.state().limit(), None);
        assert_eq!(ledger.state().remaining(), None);
        ledger.reserve(budget(10), 3)?;
        ledger.reserve(budget(2), 3)?;
        assert_eq!(ledger.state().limit(), Some(budget(30)));
        assert_eq!(ledger.state().reserved(), budget(12));
        assert_eq!(ledger.state().remaining(), Some(budget(18)));
        ledger.reserve(budget(10), 3)?;
        let before = ledger.state();
        assert!(ledger.reserve(budget(1), 3).is_err());
        assert_eq!(ledger.state(), before);
        Ok(())
    }

    #[test]
    fn automatic_overflow_never_pins_a_partial_aggregate() -> Result<(), ReconnectBudgetRefusal> {
        let mut ledger = ReservationLedger::automatic();
        let before = ledger.state();
        assert_eq!(
            ledger.reserve(budget(u64::MAX), 2),
            Err(ReconnectBudgetRefusal::Overflow(ReconnectBudgetDimension::ReceivedBytes))
        );
        assert_eq!(ledger.state(), before);
        ledger.reserve(budget(1), 2)?;
        assert_eq!(ledger.state().limit(), Some(budget(2)));
        Ok(())
    }

    #[test]
    fn explicit_counter_overflow_never_wraps_into_available_capacity()
    -> Result<(), ReconnectBudgetRefusal> {
        let mut ledger = ReservationLedger::bounded(budget(u64::MAX))?;
        ledger.reserve(budget(u64::MAX - 1), 2)?;
        let before = ledger.state();
        assert_eq!(
            ledger.reserve(budget(2), 2),
            Err(ReconnectBudgetRefusal::Overflow(ReconnectBudgetDimension::ReceivedBytes))
        );
        assert_eq!(ledger.state(), before);
        Ok(())
    }

    #[test]
    fn native_pricing_checks_all_dimensions_and_rejects_invalid_profiles()
    -> Result<(), ReconnectBudgetRefusal> {
        let limits = TcpLimits::default();
        assert_eq!(
            ReconnectBudget::for_attempts(limits, 17, 3)?,
            ReconnectBudget {
                received_bytes: limits.max_received_bytes * 3,
                sent_bytes: limits.max_sent_bytes * 3,
                io_calls: limits.max_io_calls * 3,
                connection_steps: 51,
            }
        );
        for count in [0, 1025] {
            assert!(ReconnectBudget::for_attempts(limits, 17, count).is_err());
        }
        assert!(ReconnectBudget::for_attempts(limits, 0, 3).is_err());
        let mut invalid = limits;
        invalid.chunk_bytes = 0;
        assert!(ReconnectBudget::for_attempts(invalid, 17, 3).is_err());
        assert!(ReservationLedger::bounded(budget(0)).is_err());
        Ok(())
    }
}
