//! Typed budget ledger over the canonical `BudgetVector` (FSS-022).
//!
//! The ledger is the only mutable budget state in the runtime core: it tracks
//! consumption against an immutable per-authority limit, refuses overdrafts
//! with the exact dimension named, and derives the registered
//! `ResourcePressure` ladder from utilization so degradation is an observable
//! typed signal, never a silent drop.
//!
//! ## Pressure derivation policy (reference mapping)
//!
//! Utilization per metered dimension is `consumed / limit`. Dimensions with a
//! zero limit are unmetered and excluded (an unmetered dimension can never
//! carry consumption: any spend would have been refused as an overdraft).
//! The effective pressure is the maximum utilization mapped onto the ladder:
//!
//! | utilization `u`   | pressure      |
//! |-------------------|---------------|
//! | `u < 0.50`        | `Nominal`     |
//! | `0.50 ≤ u < 0.80` | `Elevated`    |
//! | `0.80 ≤ u < 0.95` | `Constrained` |
//! | `u ≥ 0.95`        | `Critical`    |
//!
//! The privacy-exposure and operator-attention dimensions are validated
//! quantities owned by `fss-core`'s contract machinery; this ledger meters the
//! nine numeric dimensions and leaves those two to their owning contracts.

use fss_core::{BudgetDimension, BudgetVector, ResourcePressure};

/// Utilization at or above which pressure becomes `Elevated`.
pub const ELEVATED_AT: f64 = 0.50;
/// Utilization at or above which pressure becomes `Constrained`.
pub const CONSTRAINED_AT: f64 = 0.80;
/// Utilization at or above which pressure becomes `Critical`.
pub const CRITICAL_AT: f64 = 0.95;

/// Typed ledger refusal. Overdrafts name the exact dimension, the requested
/// quantity, and what remained — never a clamp, never a silent truncation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// A checked reservation settlement would return uncharged capacity.
    RefundExceedsConsumed {
        /// The dimension that would be over-refunded.
        dimension: BudgetDimension,
        /// The requested refund.
        requested: u64,
        /// The quantity still charged to the parent.
        consumed: u64,
    },
    /// The spend would exceed the remaining budget in one dimension.
    Overdraft {
        /// The dimension whose limit would be exceeded.
        dimension: BudgetDimension,
        /// The requested quantity.
        requested: u64,
        /// The remaining quantity at the time of refusal.
        remaining: u64,
    },
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RefundExceedsConsumed {
                dimension,
                requested,
                consumed,
            } => write!(
                f,
                "budget refund in {} exceeds consumption: requested {requested}, consumed {consumed}",
                dimension.as_str()
            ),
            Self::Overdraft {
                dimension,
                requested,
                remaining,
            } => write!(
                f,
                "budget overdraft in {}: requested {requested}, remaining {remaining}",
                dimension.as_str()
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

/// The nine numeric dimensions metered by this ledger (privacy-exposure and
/// operator-attention are validated quantities owned by contract machinery).
pub const METERED: [BudgetDimension; 9] = [
    BudgetDimension::LatencyMs,
    BudgetDimension::Tokens,
    BudgetDimension::Bytes,
    BudgetDimension::ModelCalls,
    BudgetDimension::CpuMillis,
    BudgetDimension::AcceleratorMillis,
    BudgetDimension::EnergyMillijoules,
    BudgetDimension::NetworkBytes,
    BudgetDimension::StorageOperations,
];

/// Reads one dimension's quantity from a vector (0 for the two
/// validated contract-owned dimensions).
#[must_use]
pub fn read_dim(vector: &BudgetVector, dimension: BudgetDimension) -> u64 {
    match dimension {
        BudgetDimension::LatencyMs => vector.latency_ms,
        BudgetDimension::Tokens => vector.tokens,
        BudgetDimension::Bytes => vector.bytes,
        BudgetDimension::ModelCalls => u64::from(vector.model_calls),
        BudgetDimension::CpuMillis => vector.cpu_millis,
        BudgetDimension::AcceleratorMillis => vector.accelerator_millis,
        BudgetDimension::EnergyMillijoules => vector.energy_millijoules,
        BudgetDimension::NetworkBytes => vector.network_bytes,
        BudgetDimension::StorageOperations => vector.storage_operations,
        // Validated quantities owned by contract machinery; unmetered here.
        BudgetDimension::PrivacyExposure | BudgetDimension::OperatorAttentionSeconds => 0,
    }
}

fn add(vector: &mut BudgetVector, dimension: BudgetDimension, qty: u64) {
    match dimension {
        BudgetDimension::LatencyMs => vector.latency_ms += qty,
        BudgetDimension::Tokens => vector.tokens += qty,
        BudgetDimension::Bytes => vector.bytes += qty,
        BudgetDimension::ModelCalls => {
            vector.model_calls = vector
                .model_calls
                .saturating_add(qty.min(u64::from(u32::MAX)) as u32);
        }
        BudgetDimension::CpuMillis => vector.cpu_millis += qty,
        BudgetDimension::AcceleratorMillis => vector.accelerator_millis += qty,
        BudgetDimension::EnergyMillijoules => vector.energy_millijoules += qty,
        BudgetDimension::NetworkBytes => vector.network_bytes += qty,
        BudgetDimension::StorageOperations => vector.storage_operations += qty,
        BudgetDimension::PrivacyExposure | BudgetDimension::OperatorAttentionSeconds => {}
    }
}

fn sub(vector: &mut BudgetVector, dimension: BudgetDimension, qty: u64) {
    match dimension {
        BudgetDimension::LatencyMs => vector.latency_ms = vector.latency_ms.saturating_sub(qty),
        BudgetDimension::Tokens => vector.tokens = vector.tokens.saturating_sub(qty),
        BudgetDimension::Bytes => vector.bytes = vector.bytes.saturating_sub(qty),
        BudgetDimension::ModelCalls => {
            vector.model_calls = vector
                .model_calls
                .saturating_sub(qty.min(u64::from(u32::MAX)) as u32);
        }
        BudgetDimension::CpuMillis => vector.cpu_millis = vector.cpu_millis.saturating_sub(qty),
        BudgetDimension::AcceleratorMillis => {
            vector.accelerator_millis = vector.accelerator_millis.saturating_sub(qty);
        }
        BudgetDimension::EnergyMillijoules => {
            vector.energy_millijoules = vector.energy_millijoules.saturating_sub(qty);
        }
        BudgetDimension::NetworkBytes => {
            vector.network_bytes = vector.network_bytes.saturating_sub(qty);
        }
        BudgetDimension::StorageOperations => {
            vector.storage_operations = vector.storage_operations.saturating_sub(qty);
        }
        BudgetDimension::PrivacyExposure | BudgetDimension::OperatorAttentionSeconds => {}
    }
}

/// Stateful ledger tracking consumption against one authority's immutable
/// `BudgetVector` limit. All arithmetic is checked; the consumed vector never
/// exceeds the limit in any metered dimension.
#[derive(Clone, Debug)]
pub struct BudgetLedger {
    limit: BudgetVector,
    consumed: BudgetVector,
}

impl BudgetLedger {
    /// Opens a ledger against an immutable limit. Consumption starts at zero.
    #[must_use]
    pub fn new(limit: BudgetVector) -> Self {
        Self {
            limit,
            consumed: BudgetVector::ZERO,
        }
    }

    /// The immutable limit this ledger meters against.
    #[must_use]
    pub fn limit(&self) -> &BudgetVector {
        &self.limit
    }

    /// The consumed vector so far.
    #[must_use]
    pub fn consumed(&self) -> &BudgetVector {
        &self.consumed
    }

    /// The remaining vector (limit minus consumed). Invariant: never negative
    /// in any metered dimension because overdrafts are refused before commit.
    #[must_use]
    pub fn remaining(&self) -> BudgetVector {
        self.limit
            .checked_sub(&self.consumed)
            .unwrap_or(BudgetVector::ZERO)
    }

    /// Spends `qty` in one dimension. Refuses with the exact remaining
    /// quantity when the spend would overdraw; the ledger is unchanged on
    /// refusal.
    pub fn spend(&mut self, dimension: BudgetDimension, qty: u64) -> Result<(), LedgerError> {
        let remaining =
            read_dim(&self.limit, dimension).saturating_sub(read_dim(&self.consumed, dimension));
        if qty > remaining {
            return Err(LedgerError::Overdraft {
                dimension,
                requested: qty,
                remaining,
            });
        }
        add(&mut self.consumed, dimension, qty);
        Ok(())
    }

    /// Spends a whole vector atomically: the first dimension that would
    /// overdraw refuses and no dimension is committed.
    pub fn spend_vector(&mut self, delta: &BudgetVector) -> Result<(), LedgerError> {
        for dimension in METERED {
            let qty = read_dim(delta, dimension);
            let remaining = read_dim(&self.limit, dimension)
                .saturating_sub(read_dim(&self.consumed, dimension));
            if qty > remaining {
                return Err(LedgerError::Overdraft {
                    dimension,
                    requested: qty,
                    remaining,
                });
            }
        }
        for dimension in METERED {
            add(&mut self.consumed, dimension, read_dim(delta, dimension));
        }
        Ok(())
    }

    /// Refunds `qty` in one dimension (e.g. a reservation released unused).
    /// Saturates at zero consumption; refunding more than consumed is a
    /// caller accounting error but never makes the ledger negative.
    pub fn refund(&mut self, dimension: BudgetDimension, qty: u64) {
        sub(&mut self.consumed, dimension, qty);
    }

    /// Return only metered capacity. Contract-owned continuous quantities
    /// are never represented as runtime refunds.
    pub(crate) fn unused_metered(&self) -> BudgetVector {
        let mut unused = BudgetVector::ZERO;
        for dimension in METERED {
            add(
                &mut unused,
                dimension,
                read_dim(&self.limit, dimension) - read_dim(&self.consumed, dimension),
            );
        }
        unused
    }

    /// Settle a scope-owned reservation through checked atomic subtraction.
    /// Unlike the standalone ledger adjustment API, over-refunds are refused.
    pub(crate) fn refund_vector(&mut self, refund: &BudgetVector) -> Result<(), LedgerError> {
        for dimension in METERED {
            let requested = read_dim(refund, dimension);
            let consumed = read_dim(&self.consumed, dimension);
            if requested > consumed {
                return Err(LedgerError::RefundExceedsConsumed {
                    dimension,
                    requested,
                    consumed,
                });
            }
        }
        for dimension in METERED {
            sub(&mut self.consumed, dimension, read_dim(refund, dimension));
        }
        Ok(())
    }

    /// Utilization of one metered dimension: `consumed / limit`, or `None`
    /// when the dimension is unmetered (zero limit).
    #[must_use]
    pub fn utilization(&self, dimension: BudgetDimension) -> Option<f64> {
        let limit = read_dim(&self.limit, dimension);
        if limit == 0 {
            return None;
        }
        Some(read_dim(&self.consumed, dimension) as f64 / limit as f64)
    }

    /// The derived pressure: maximum utilization across metered dimensions
    /// mapped onto the registered ladder (see module docs for the policy).
    #[must_use]
    pub fn pressure(&self) -> ResourcePressure {
        let mut max_u = 0.0_f64;
        for dimension in METERED {
            if let Some(u) = self.utilization(dimension)
                && u > max_u
            {
                max_u = u;
            }
        }
        if max_u >= CRITICAL_AT {
            ResourcePressure::Critical
        } else if max_u >= CONSTRAINED_AT {
            ResourcePressure::Constrained
        } else if max_u >= ELEVATED_AT {
            ResourcePressure::Elevated
        } else {
            ResourcePressure::Nominal
        }
    }
}

/// Spending access to an authority's immutable allowance. It cannot replace or
/// refund the ledger. Its authority constructor ties the lifetime to the bound
/// region tree so closure cannot race outstanding spending access.
pub struct BudgetSpender<'a> {
    ledger: &'a mut BudgetLedger,
}

impl<'a> BudgetSpender<'a> {
    pub(crate) fn new(ledger: &'a mut BudgetLedger) -> Self {
        Self { ledger }
    }

    /// Account for work without admitting new work or conferring I/O authority.
    pub fn spend(&mut self, dimension: BudgetDimension, qty: u64) -> Result<(), LedgerError> {
        self.ledger.spend(dimension, qty)
    }

    /// Account for a complete numeric vector atomically.
    pub fn spend_vector(&mut self, delta: &BudgetVector) -> Result<(), LedgerError> {
        self.ledger.spend_vector(delta)
    }

    /// The allowance left before this spend.
    #[must_use]
    pub fn remaining(&self) -> BudgetVector {
        self.ledger.remaining()
    }
}
