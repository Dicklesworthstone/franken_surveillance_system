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

/// Exact bounded resource dimension checked by [`JobResourceAdmissionLedger`] (`MODEL-INV-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeDimension {
    /// Serialized input tensor / payload bytes.
    InputBytes,
    /// Decoded image pixels admitted into preprocessing.
    DecodedPixels,
    /// Token count admitted into sequence/multimodal models.
    Tokens,
    /// Peak live activation memory in bytes.
    ActivationMemoryBytes,
    /// Operator temporary scratch memory in bytes.
    ScratchMemoryBytes,
    /// Logical operator work units (MACs / FLOPs).
    OperatorWork,
    /// Hard job execution deadline in nanoseconds.
    DeadlineNs,
    /// Maximum serialized output bytes.
    OutputBytes,
    /// Bounded concurrent / queued job count (prevents unbounded queueing).
    QueuedJobs,
}

impl EnvelopeDimension {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::DecodedPixels => "decoded_pixels",
            Self::Tokens => "tokens",
            Self::ActivationMemoryBytes => "activation_memory_bytes",
            Self::ScratchMemoryBytes => "scratch_memory_bytes",
            Self::OperatorWork => "operator_work",
            Self::DeadlineNs => "deadline_ns",
            Self::OutputBytes => "output_bytes",
            Self::QueuedJobs => "queued_jobs",
        }
    }
}

/// Hard eight-dimension plus queue-depth resource envelope (`MODEL-INV-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobResourceEnvelope {
    /// Maximum input payload bytes per job.
    pub max_input_bytes: u64,
    /// Maximum decoded pixels per job.
    pub max_decoded_pixels: u64,
    /// Maximum tokens per job.
    pub max_tokens: u64,
    /// Maximum activation memory in bytes (per-job and aggregate host pool ceiling).
    pub max_activation_memory_bytes: u64,
    /// Maximum scratch memory in bytes (per-job and aggregate host pool ceiling).
    pub max_scratch_memory_bytes: u64,
    /// Maximum logical operator work units per job.
    pub max_operator_work: u64,
    /// Maximum execution deadline in nanoseconds per job.
    pub max_deadline_ns: u64,
    /// Maximum output bytes per job.
    pub max_output_bytes: u64,
    /// Hard ceiling on simultaneously admitted/queued jobs (no unbounded queueing).
    pub max_queued_jobs: u32,
}

/// Resource reservation request presented before a model job starts (`MODEL-INV-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobResourceRequest {
    /// Requested input payload bytes.
    pub input_bytes: u64,
    /// Requested decoded pixels.
    pub decoded_pixels: u64,
    /// Requested token count.
    pub tokens: u64,
    /// Requested activation memory bytes.
    pub activation_memory_bytes: u64,
    /// Requested scratch memory bytes.
    pub scratch_memory_bytes: u64,
    /// Requested operator work units.
    pub operator_work: u64,
    /// Requested execution deadline in nanoseconds.
    pub deadline_ns: u64,
    /// Requested output bytes.
    pub output_bytes: u64,
}

/// Typed fail-closed refusal when any hard resource envelope bound is exceeded (`MODEL-INV-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceEnvelopeViolation {
    /// Envelope limit was zero or invalid.
    InvalidEnvelope(EnvelopeDimension),
    /// A specific per-job or aggregate hard bound was exceeded (never host OOM or unbounded queue).
    BoundExceeded {
        /// Exact violated resource dimension.
        dimension: EnvelopeDimension,
        /// Requested (or projected aggregate) amount.
        requested: u64,
        /// Configured hard ceiling.
        limit: u64,
    },
    /// Host memory pressure refused new admission cleanly as typed abstention.
    PressureAbstained(ResourcePressure),
}

impl std::fmt::Display for ResourceEnvelopeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvelope(dim) => {
                write!(
                    f,
                    "invalid zero resource envelope bound for {}",
                    dim.as_str()
                )
            }
            Self::BoundExceeded {
                dimension,
                requested,
                limit,
            } => write!(
                f,
                "hard resource envelope exceeded on {}: requested {requested} > limit {limit}",
                dimension.as_str()
            ),
            Self::PressureAbstained(p) => {
                write!(
                    f,
                    "resource envelope abstained under pressure '{}'",
                    p.as_str()
                )
            }
        }
    }
}

impl std::error::Error for ResourceEnvelopeViolation {}

/// Active reservation handle returned by [`JobResourceAdmissionLedger::reserve_job`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobEnvelopeReservation {
    /// Reserved activation memory bytes.
    pub activation_memory_bytes: u64,
    /// Reserved scratch memory bytes.
    pub scratch_memory_bytes: u64,
}

/// Deterministic hard resource-envelope admission ledger enforcing all 8 `MODEL-INV-008`
/// dimensions plus bounded queue depth with atomic reserve/release accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobResourceAdmissionLedger {
    envelope: JobResourceEnvelope,
    policy: MemoryAdmission,
    active_jobs: u32,
    reserved_activation_bytes: u64,
    reserved_scratch_bytes: u64,
}

impl JobResourceAdmissionLedger {
    /// Creates a validated admission ledger; refuses zero ceilings fail-closed.
    pub fn new(
        envelope: JobResourceEnvelope,
        policy: MemoryAdmission,
    ) -> Result<Self, ResourceEnvelopeViolation> {
        let checks = [
            (EnvelopeDimension::InputBytes, envelope.max_input_bytes),
            (
                EnvelopeDimension::DecodedPixels,
                envelope.max_decoded_pixels,
            ),
            (EnvelopeDimension::Tokens, envelope.max_tokens),
            (
                EnvelopeDimension::ActivationMemoryBytes,
                envelope.max_activation_memory_bytes,
            ),
            (
                EnvelopeDimension::ScratchMemoryBytes,
                envelope.max_scratch_memory_bytes,
            ),
            (EnvelopeDimension::OperatorWork, envelope.max_operator_work),
            (EnvelopeDimension::DeadlineNs, envelope.max_deadline_ns),
            (EnvelopeDimension::OutputBytes, envelope.max_output_bytes),
            (
                EnvelopeDimension::QueuedJobs,
                u64::from(envelope.max_queued_jobs),
            ),
        ];
        for (dim, limit) in checks {
            if limit == 0 {
                return Err(ResourceEnvelopeViolation::InvalidEnvelope(dim));
            }
        }
        Ok(Self {
            envelope,
            policy,
            active_jobs: 0,
            reserved_activation_bytes: 0,
            reserved_scratch_bytes: 0,
        })
    }

    /// Atomically checks all 8 per-job bounds, pressure policy, queue depth, and aggregate
    /// activation/scratch ceilings before placing a reservation. On any violation, zero state mutates.
    pub fn reserve_job(
        &mut self,
        req: JobResourceRequest,
        pressure: ResourcePressure,
    ) -> Result<JobEnvelopeReservation, ResourceEnvelopeViolation> {
        if !self.policy.admits(pressure) {
            return Err(ResourceEnvelopeViolation::PressureAbstained(pressure));
        }
        let per_job = [
            (
                EnvelopeDimension::InputBytes,
                req.input_bytes,
                self.envelope.max_input_bytes,
            ),
            (
                EnvelopeDimension::DecodedPixels,
                req.decoded_pixels,
                self.envelope.max_decoded_pixels,
            ),
            (
                EnvelopeDimension::Tokens,
                req.tokens,
                self.envelope.max_tokens,
            ),
            (
                EnvelopeDimension::ActivationMemoryBytes,
                req.activation_memory_bytes,
                self.envelope.max_activation_memory_bytes,
            ),
            (
                EnvelopeDimension::ScratchMemoryBytes,
                req.scratch_memory_bytes,
                self.envelope.max_scratch_memory_bytes,
            ),
            (
                EnvelopeDimension::OperatorWork,
                req.operator_work,
                self.envelope.max_operator_work,
            ),
            (
                EnvelopeDimension::DeadlineNs,
                req.deadline_ns,
                self.envelope.max_deadline_ns,
            ),
            (
                EnvelopeDimension::OutputBytes,
                req.output_bytes,
                self.envelope.max_output_bytes,
            ),
        ];
        for (dimension, requested, limit) in per_job {
            if requested > limit {
                return Err(ResourceEnvelopeViolation::BoundExceeded {
                    dimension,
                    requested,
                    limit,
                });
            }
        }
        let next_jobs = self.active_jobs.saturating_add(1);
        if next_jobs > self.envelope.max_queued_jobs {
            return Err(ResourceEnvelopeViolation::BoundExceeded {
                dimension: EnvelopeDimension::QueuedJobs,
                requested: u64::from(next_jobs),
                limit: u64::from(self.envelope.max_queued_jobs),
            });
        }
        let next_act = self
            .reserved_activation_bytes
            .checked_add(req.activation_memory_bytes)
            .unwrap_or(u64::MAX);
        if next_act > self.envelope.max_activation_memory_bytes {
            return Err(ResourceEnvelopeViolation::BoundExceeded {
                dimension: EnvelopeDimension::ActivationMemoryBytes,
                requested: next_act,
                limit: self.envelope.max_activation_memory_bytes,
            });
        }
        let next_scratch = self
            .reserved_scratch_bytes
            .checked_add(req.scratch_memory_bytes)
            .unwrap_or(u64::MAX);
        if next_scratch > self.envelope.max_scratch_memory_bytes {
            return Err(ResourceEnvelopeViolation::BoundExceeded {
                dimension: EnvelopeDimension::ScratchMemoryBytes,
                requested: next_scratch,
                limit: self.envelope.max_scratch_memory_bytes,
            });
        }

        self.active_jobs = next_jobs;
        self.reserved_activation_bytes = next_act;
        self.reserved_scratch_bytes = next_scratch;
        Ok(JobEnvelopeReservation {
            activation_memory_bytes: req.activation_memory_bytes,
            scratch_memory_bytes: req.scratch_memory_bytes,
        })
    }

    /// Releases a previously granted reservation upon completion, cancellation, or abstention.
    pub fn release_job(&mut self, reservation: JobEnvelopeReservation) {
        self.active_jobs = self.active_jobs.saturating_sub(1);
        self.reserved_activation_bytes = self
            .reserved_activation_bytes
            .saturating_sub(reservation.activation_memory_bytes);
        self.reserved_scratch_bytes = self
            .reserved_scratch_bytes
            .saturating_sub(reservation.scratch_memory_bytes);
    }

    /// Current active/queued job count.
    #[must_use]
    pub const fn active_jobs(&self) -> u32 {
        self.active_jobs
    }

    /// Current aggregate reserved activation memory bytes.
    #[must_use]
    pub const fn reserved_activation_bytes(&self) -> u64 {
        self.reserved_activation_bytes
    }

    /// Current aggregate reserved scratch memory bytes.
    #[must_use]
    pub const fn reserved_scratch_bytes(&self) -> u64 {
        self.reserved_scratch_bytes
    }
}
