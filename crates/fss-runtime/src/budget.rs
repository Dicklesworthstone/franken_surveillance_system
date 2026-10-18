//! Typed budget accounting: budgets only ever decrement to a typed
//! exhaustion state. There is no ambient top-up and no silent overdraw.
//!
//! Deterministic: the ledger is a pure value; the caller supplies costs and
//! pressure signals. (FSS-021 slice 1 / FSS-022 groundwork.)

/// A budget covering the dimensions FSS acquisition paths spend.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Budget {
    /// Bounded work units (frames, packets, steps).
    pub work_units: u64,
    /// Bounded bytes (payload + retained custody).
    pub bytes: u64,
    /// Bounded wall-clock nanoseconds for an operation.
    pub wall_ns: u64,
}

impl Budget {
    /// A budget of the given shape.
    #[must_use]
    pub const fn new(work_units: u64, bytes: u64, wall_ns: u64) -> Self {
        Self {
            work_units,
            bytes,
            wall_ns,
        }
    }

    /// Zero in every dimension (spending anything exhausts it).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            work_units: 0,
            bytes: 0,
            wall_ns: 0,
        }
    }

    /// Whether every dimension is exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.work_units == 0 && self.bytes == 0 && self.wall_ns == 0
    }
}

/// A decremented-only ledger over one budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetLedger {
    remaining: Budget,
}

/// Typed exhaustion with the exact dimension that stopped the spend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetExhausted {
    /// Work-unit bound hit.
    WorkUnits {
        /// Remaining at refusal.
        remaining: u64,
        /// Requested spend.
        requested: u64,
    },
    /// Byte bound hit.
    Bytes {
        /// Remaining at refusal.
        remaining: u64,
        /// Requested spend.
        requested: u64,
    },
    /// Wall-time bound hit.
    WallNs {
        /// Remaining at refusal.
        remaining: u64,
        /// Requested spend.
        requested: u64,
    },
}

impl core::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkUnits { remaining, requested } => {
                write!(f, "work-unit budget exhausted ({remaining} left, {requested} requested)")
            }
            Self::Bytes { remaining, requested } => {
                write!(f, "byte budget exhausted ({remaining} left, {requested} requested)")
            }
            Self::WallNs { remaining, requested } => {
                write!(f, "wall-time budget exhausted ({remaining} left, {requested} requested)")
            }
        }
    }
}

impl std::error::Error for BudgetExhausted {}

impl BudgetLedger {
    /// Open a ledger over `initial`.
    #[must_use]
    pub const fn new(initial: Budget) -> Self {
        Self { remaining: initial }
    }

    /// Current remaining budget.
    #[must_use]
    pub const fn remaining(&self) -> Budget {
        self.remaining
    }

    /// Spend work units; overdraft is a typed refusal, not a clamp.
    pub fn spend_work(&mut self, units: u64) -> Result<(), BudgetExhausted> {
        if units > self.remaining.work_units {
            return Err(BudgetExhausted::WorkUnits {
                remaining: self.remaining.work_units,
                requested: units,
            });
        }
        self.remaining.work_units -= units;
        Ok(())
    }

    /// Spend bytes; overdraft is a typed refusal, not a clamp.
    pub fn spend_bytes(&mut self, bytes: u64) -> Result<(), BudgetExhausted> {
        if bytes > self.remaining.bytes {
            return Err(BudgetExhausted::Bytes {
                remaining: self.remaining.bytes,
                requested: bytes,
            });
        }
        self.remaining.bytes -= bytes;
        Ok(())
    }

    /// Spend wall time; overdraft is a typed refusal, not a clamp.
    pub fn spend_wall(&mut self, ns: u64) -> Result<(), BudgetExhausted> {
        if ns > self.remaining.wall_ns {
            return Err(BudgetExhausted::WallNs {
                remaining: self.remaining.wall_ns,
                requested: ns,
            });
        }
        self.remaining.wall_ns -= ns;
        Ok(())
    }
}
