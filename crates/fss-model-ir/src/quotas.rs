#![forbid(unsafe_code)]
//! Model invocation quotas and memory-pressure handling (FSS-073).
//!
//! Extends the FSS-072 invocation protocol with admission control:
//!
//! - [`InvocationQuota`] — per-model cumulative budgets: invocation count
//!   and total node-work. Every executed invocation debits the ledger
//!   atomically with its receipt's actuals; a refused invocation debits
//!   nothing. Quotas are per `model_root` identity, never global.
//! - [`MemoryAdmission`] — an explicit memory-pressure gate for
//!   `prepare`/`execute`: under `Constrained` or `Critical` pressure the
//!   ledger refuses new invocations (typed, naming the pressure) while
//!   never cancelling work already admitted; admission decisions are
//!   caller-time and deterministic.
//!
//! Pressure follows the registered ladder semantics: nominal admits;
//!   constrained/critical admit only work already under the caller's
//!   stated reserve floor; the gate never silently degrades — every
//!   refusal is typed with the pressure level that caused it.

use fss_core::{ContentDigest, ResourcePressure, TimestampNs};

use crate::graph::ModelIrGraph;
use crate::invocation::{ModelInvocationSpec, ModelReceipt, PreparedInvocation, execute};

/// Typed quota/pressure refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotaError {
    /// The model's cumulative invocation budget is exhausted.
    InvocationsExhausted {
        /// The model identity.
        model_root: ContentDigest,
        /// Used count at refusal.
        used: u64,
        /// The configured maximum.
        maximum: u64,
    },
    /// The model's cumulative node-work budget is exhausted.
    NodeWorkExhausted {
        /// The model identity.
        model_root: ContentDigest,
        /// Used nodes at refusal.
        used: u64,
        /// The configured maximum.
        maximum: u64,
    },
    /// Memory pressure refuses new admission (names the level).
    PressureRefused {
        /// The pressure level at refusal.
        pressure: ResourcePressure,
        /// Model identity.
        model_root: ContentDigest,
    },
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvocationsExhausted {
                model_root,
                used,
                maximum,
            } => write!(
                f,
                "quota: invocations for {model_root:?} exhausted ({used}/{maximum})"
            ),
            Self::NodeWorkExhausted {
                model_root,
                used,
                maximum,
            } => write!(
                f,
                "quota: node work for {model_root:?} exhausted ({used}/{maximum})"
            ),
            Self::PressureRefused {
                pressure,
                model_root,
            } => write!(
                f,
                "memory pressure '{}' refuses admission of {model_root:?}",
                pressure.as_str()
            ),
        }
    }
}

impl std::error::Error for QuotaError {}

/// Per-model cumulative quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvocationQuota {
    /// Maximum invocations admitted for this model identity.
    pub max_invocations: u64,
    /// Maximum total node-work across all invocations.
    pub max_total_nodes: u64,
}

/// Memory-pressure admission policy: the pressure level at which new
/// invocations are still admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAdmission {
    /// Admit under any pressure (the caller owns the risk explicitly).
    AdmitAlways,
    /// Admit while pressure is below `Constrained`.
    RefuseConstrained,
    /// Admit only while nominal (the default conservative posture).
    NominalOnly,
}

impl MemoryAdmission {
    /// Whether this policy admits at the given pressure.
    #[must_use]
    pub const fn admits(self, pressure: ResourcePressure) -> bool {
        match self {
            Self::AdmitAlways => true,
            Self::RefuseConstrained => !matches!(
                pressure,
                ResourcePressure::Constrained | ResourcePressure::Critical
            ),
            Self::NominalOnly => matches!(pressure, ResourcePressure::Nominal),
        }
    }
}

/// One model's quota ledger state. Node accounting is RESERVATION-based:
/// prepare reserves the graph's worst case (node count, clamped by the
/// spec's own budget); execute debits the receipt's actuals and releases
/// the unused reservation — so a refused prepare never overshoots the
/// budget and an abstained execution releases its reservation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LedgerRow {
    invocations_used: u64,
    nodes_used: u64,
    nodes_reserved: u64,
}

/// The quota + pressure admission ledger, keyed by model identity.
#[derive(Clone, Debug)]
pub struct InvocationQuotaLedger {
    quota: InvocationQuota,
    policy: MemoryAdmission,
    rows: std::collections::BTreeMap<ContentDigest, LedgerRow>,
}

impl Default for InvocationQuotaLedger {
    fn default() -> Self {
        Self::new(
            InvocationQuota {
                max_invocations: u64::MAX,
                max_total_nodes: u64::MAX,
            },
            MemoryAdmission::NominalOnly,
        )
    }
}

impl InvocationQuotaLedger {
    /// Opens a ledger with the per-model quota and admission policy.
    #[must_use]
    pub fn new(quota: InvocationQuota, policy: MemoryAdmission) -> Self {
        Self {
            quota,
            policy,
            rows: std::collections::BTreeMap::new(),
        }
    }

    /// The node reservation a prepare of `graph` under `spec` would place:
    /// the graph's node count clamped by the spec's own budget.
    fn reservation_for(graph: &ModelIrGraph, spec: &ModelInvocationSpec) -> u64 {
        (graph.node_count() as u64).min(spec.max_nodes as u64)
    }

    /// Whether a new invocation of `model_root` would be admitted at the
    /// given pressure — pure check, no mutation. Node capacity counts the
    /// outstanding reservations, so admission can never overshoot.
    #[must_use]
    pub fn would_admit(&self, model_root: ContentDigest, pressure: ResourcePressure) -> bool {
        if !self.policy.admits(pressure) {
            return false;
        }
        match self.rows.get(&model_root) {
            None => true,
            Some(row) => {
                row.invocations_used < self.quota.max_invocations
                    && row.nodes_used + row.nodes_reserved < self.quota.max_total_nodes
            }
        }
    }

    /// Admission-gated prepare: runs the FSS-072 [`prepare`] only if the
    /// quota and pressure policy admit this model.
    ///
    /// # Errors
    /// [`QuotaError`] refusals name the exact budget or pressure level;
    /// underlying prepare errors pass through unchanged.
    pub fn prepare(
        &mut self,
        graph: &ModelIrGraph,
        spec: &ModelInvocationSpec,
        pressure: ResourcePressure,
    ) -> Result<PreparedInvocation, crate::invocation::InvocationError> {
        if !self.policy.admits(pressure) {
            return Err(crate::invocation::InvocationError::Quota(
                QuotaError::PressureRefused {
                    pressure,
                    model_root: spec.model_root,
                },
            ));
        }
        let row = self.rows.get(&spec.model_root);
        if let Some(row) = row
            && row.invocations_used >= self.quota.max_invocations
        {
            return Err(crate::invocation::InvocationError::Quota(
                QuotaError::InvocationsExhausted {
                    model_root: spec.model_root,
                    used: row.invocations_used,
                    maximum: self.quota.max_invocations,
                },
            ));
        }
        let reserve = Self::reservation_for(graph, spec);
        if let Some(row) = row
            && row.nodes_used + row.nodes_reserved + reserve > self.quota.max_total_nodes
        {
            return Err(crate::invocation::InvocationError::Quota(
                QuotaError::NodeWorkExhausted {
                    model_root: spec.model_root,
                    used: row.nodes_used + row.nodes_reserved,
                    maximum: self.quota.max_total_nodes,
                },
            ));
        }
        let prepared = crate::invocation::prepare(graph, spec)?;
        // Reservation placed only after a successful prepare.
        let row = self.rows.entry(spec.model_root).or_default();
        row.nodes_reserved = row.nodes_reserved.saturating_add(reserve);
        Ok(prepared)
    }

    /// Executes the prepared invocation through the FSS-072 executor and
    /// debits the ledger with the RECEIPT'S ACTUALS (nodes evaluated, or
    /// zero for abstained/quarantined outcomes — uncertainty never
    /// consumes budget).
    ///
    /// # Errors
    /// Underlying execution errors pass through; the ledger is unchanged
    /// on error.
    pub fn execute_and_debit(
        &mut self,
        graph: &ModelIrGraph,
        prepared: &PreparedInvocation,
        now: TimestampNs,
    ) -> Result<ModelReceipt, crate::invocation::InvocationError> {
        let _ = now;
        let receipt = execute(graph, prepared)?;
        let nodes = match &receipt.outcome {
            crate::invocation::InvocationOutcome::Completed {
                nodes_evaluated, ..
            } => *nodes_evaluated as u64,
            _ => 0,
        };
        let graph_count = (graph.node_count() as u64).min(prepared.spec().max_nodes as u64);
        let row = self.rows.entry(model_root_of(prepared)).or_default();
        row.invocations_used = row
            .invocations_used
            .saturating_add(u64::from(receipt.outcome_is_counted()));
        row.nodes_used = row.nodes_used.saturating_add(nodes);
        // Release this invocation's reservation (actuals are now on the
        // books; the worst-case hold goes away).
        row.nodes_reserved = row.nodes_reserved.saturating_sub(graph_count);
        Ok(receipt)
    }

    /// Current usage for one model identity: (invocations, node work
    /// debited). Zero when never invoked.
    #[must_use]
    pub fn usage(&self, model_root: ContentDigest) -> (u64, u64) {
        match self.rows.get(&model_root) {
            None => (0, 0),
            Some(row) => (row.invocations_used, row.nodes_used),
        }
    }

    /// Outstanding node reservations for one model identity (admitted,
    /// not yet executed).
    #[must_use]
    pub fn reservations(&self, model_root: ContentDigest) -> u64 {
        self.rows
            .get(&model_root)
            .map_or(0, |row| row.nodes_reserved)
    }
}

fn model_root_of(prepared: &PreparedInvocation) -> ContentDigest {
    prepared.spec().model_root
}
