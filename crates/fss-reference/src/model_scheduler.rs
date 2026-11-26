#![forbid(unsafe_code)]
//! CPU thermal and resource-pressure-aware model scheduler with hard floors
//! (`FSS-150`, `fss-x4a.14.21`).
//!
//! Enforces explicit, deterministic admission, thread-count degradation, workload shedding,
//! hysteresis anti-flapping, and lower-priority preemption so safety-critical detectors
//! (`ModelWorkloadClass::CriticalSafetyDetector`) keep guaranteed hard floors even under
//! `ThermalState::Critical` and `ResourcePressure::Critical`:
//!
//! - **Deterministic without ambient time or OS state:** all timestamps are explicit
//!   [`TimestampNs`] inputs; thermal and pressure readings are explicit bounded samples.
//! - **Hard floors are non-negotiable:** `CriticalSafetyDetector` always retains at least
//!   `critical_min_threads`, `critical_reserved_memory_bytes`, and
//!   `critical_min_invocations_per_window`. Lower classes can never encroach on reserved critical
//!   headroom and are deterministically preempted in canonical `(reverse priority, request_id)`
//!   order when a critical request needs resources.
//! - **Non-collapsed typed outcomes:** `AdmittedFull`, `AdmittedDegradedThreads`,
//!   `AdmittedViaHardFloor`, `DeferredByPressure`, `RefusedBudgetOrCapacity`,
//!   `RefusedQuarantinedOrStale`, and `Cancelled` remain strictly distinct.
//! - **Independent reference oracle:** [`oracle_evaluate_admission`] independently computes the
//!   exact admission decision from a pure snapshot so differential/property suites can verify
//!   zero drift across the full `(ThermalState x ResourcePressure x ModelWorkloadClass)` matrix.
//! - **Sealed `FSSMMS01` v1 receipt:** every decision emits a canonical domain-separated
//!   [`ModelSchedulerReceipt`] under `fss.reference.model_scheduler_receipt.v1` carrying zero
//!   effect authority (`grants_effect_authority() == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm, ResourcePressure,
    Sha256Hasher, TimestampNs,
};

use crate::optimized_executor::ExecThreads;
use crate::scalar_executor::ScalarExecCx;

/// Registered canonical digest domain for [`ModelSchedulerReceipt`] (`FSS-150`).
pub const MODEL_SCHEDULER_RECEIPT_DOMAIN: &str = "fss.reference.model_scheduler_receipt.v1";
/// Binary wire magic header for sealed [`ModelSchedulerReceipt`] envelopes.
pub const MODEL_SCHEDULER_WIRE_MAGIC: [u8; 8] = *b"FSSMMS01";
/// Current wire format version for [`ModelSchedulerReceipt`].
pub const MODEL_SCHEDULER_WIRE_VERSION: u32 = 1;
/// Hard ceiling on serialized `FSSMMS01` wire bytes (256 KiB).
pub const MAX_MODEL_SCHEDULER_WIRE_BYTES: usize = 256 * 1024;
/// Hard ceiling on active concurrent model invocations admitted by one scheduler.
pub const MAX_SCHEDULER_ACTIVE_INVOCATIONS: usize = 64;
/// Hard ceiling on retained idempotent receipt entries in one scheduler instance.
pub const MAX_SCHEDULER_IDEMPOTENCY_ENTRIES: usize = 4_096;
/// Maximum UTF-8 byte length of a scheduler request identifier.
pub const MAX_SCHEDULER_REQUEST_ID_BYTES: usize = 128;
/// Maximum UTF-8 byte length of recovery guidance strings in a receipt.
pub const MAX_SCHEDULER_GUIDANCE_BYTES: usize = 512;
/// Minimum admissible CPU temperature sample (-40.0 C in millicelsius).
pub const MIN_CPU_TEMP_MC: i32 = -40_000;
/// Maximum admissible CPU temperature sample (+150.0 C in millicelsius).
pub const MAX_CPU_TEMP_MC: i32 = 150_000;
/// Maximum CPU utilization in parts-per-million (100.0%).
pub const MAX_CPU_UTIL_PPM: u32 = 1_000_000;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Coarse CPU thermal state derived with hysteresis from millicelsius telemetry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ThermalState {
    /// Cool nominal operating envelope; full parallelism permitted.
    Nominal = 0,
    /// Elevated temperature; background work is shed and standard work throttles threads.
    Warm = 1,
    /// High temperature; standard and background work are shed; critical detectors run bounded.
    Hot = 2,
    /// Critical thermal limit; only critical safety hard-floor work may proceed.
    Critical = 3,
}

impl ThermalState {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Warm => "warm",
            Self::Hot => "hot",
            Self::Critical => "critical",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ModelSchedulerError> {
        match tag {
            0 => Ok(Self::Nominal),
            1 => Ok(Self::Warm),
            2 => Ok(Self::Hot),
            3 => Ok(Self::Critical),
            other => Err(ModelSchedulerError::MalformedWire(format!(
                "unknown ThermalState tag {other}"
            ))),
        }
    }
}

/// Priority class of a model execution request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModelWorkloadClass {
    /// Highest-priority safety/intrusion detector protected by hard floors.
    CriticalSafetyDetector = 0,
    /// Routine multi-camera analytics and tracking.
    StandardAnalytics = 1,
    /// Best-effort enrichment, indexing, or retrospective scoring.
    BackgroundEnrichment = 2,
}

impl ModelWorkloadClass {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CriticalSafetyDetector => "critical_safety_detector",
            Self::StandardAnalytics => "standard_analytics",
            Self::BackgroundEnrichment => "background_enrichment",
        }
    }

    /// True iff this class is protected by scheduler hard floors.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(self, Self::CriticalSafetyDetector)
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ModelSchedulerError> {
        match tag {
            0 => Ok(Self::CriticalSafetyDetector),
            1 => Ok(Self::StandardAnalytics),
            2 => Ok(Self::BackgroundEnrichment),
            other => Err(ModelSchedulerError::MalformedWire(format!(
                "unknown ModelWorkloadClass tag {other}"
            ))),
        }
    }
}

/// Non-collapsed terminal admission outcome of one scheduling decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerDecisionState {
    /// Admitted with the full requested thread budget.
    AdmittedFull = 1,
    /// Admitted with reduced thread budget due to thermal, CPU, or power pressure.
    AdmittedDegradedThreads = 2,
    /// Admitted under `Critical` thermal/resource pressure via the critical safety hard floor.
    AdmittedViaHardFloor = 3,
    /// Lower-priority work deferred/shed because of thermal, resource, power, or reserve pressure.
    DeferredByPressure = 4,
    /// Hard envelope, quota, concurrency ceiling, or memory limit refused admission.
    RefusedBudgetOrCapacity = 5,
    /// Model generation is quarantined or authority generation is stale.
    RefusedQuarantinedOrStale = 6,
    /// Request was cooperatively cancelled prior to admission; zero resources consumed.
    Cancelled = 7,
}

impl SchedulerDecisionState {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmittedFull => "admitted_full",
            Self::AdmittedDegradedThreads => "admitted_degraded_threads",
            Self::AdmittedViaHardFloor => "admitted_via_hard_floor",
            Self::DeferredByPressure => "deferred_by_pressure",
            Self::RefusedBudgetOrCapacity => "refused_budget_or_capacity",
            Self::RefusedQuarantinedOrStale => "refused_quarantined_or_stale",
            Self::Cancelled => "cancelled",
        }
    }

    /// True iff the request was admitted to execute.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(
            self,
            Self::AdmittedFull | Self::AdmittedDegradedThreads | Self::AdmittedViaHardFloor
        )
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ModelSchedulerError> {
        match tag {
            1 => Ok(Self::AdmittedFull),
            2 => Ok(Self::AdmittedDegradedThreads),
            3 => Ok(Self::AdmittedViaHardFloor),
            4 => Ok(Self::DeferredByPressure),
            5 => Ok(Self::RefusedBudgetOrCapacity),
            6 => Ok(Self::RefusedQuarantinedOrStale),
            7 => Ok(Self::Cancelled),
            other => Err(ModelSchedulerError::MalformedWire(format!(
                "unknown SchedulerDecisionState tag {other}"
            ))),
        }
    }
}

/// Typed reason explaining any degradation, shedding, or refusal in [`ModelSchedulerReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerDegradationReason {
    /// Nominal admission with no pressure constraint active.
    None = 0,
    /// Warm thermal band throttled threads or shed background work.
    ThermalWarmThrottle = 1,
    /// Hot thermal band shed non-critical work and bounded critical threads.
    ThermalHotShedLowerClasses = 2,
    /// Critical thermal band limited execution to critical safety hard floors only.
    ThermalCriticalHardFloorOnly = 3,
    /// Elevated resource pressure throttled threads or shed background work.
    ResourcePressureElevated = 4,
    /// Constrained resource pressure shed non-critical work.
    ResourcePressureConstrained = 5,
    /// Critical resource pressure restricted execution to critical hard floors only.
    ResourcePressureCriticalHardFloorOnly = 6,
    /// Available memory headroom is reserved exclusively for critical hard-floor work.
    MemoryHeadroomReservedForCriticalFloor = 7,
    /// Instantaneous host power draw exceeded configured power budget.
    PowerCapThrottle = 8,
    /// Window invocation quota was exhausted.
    WindowQuotaExhausted = 9,
    /// Active concurrency ceiling or thread pool capacity was reached.
    ConcurrencyCeilingReached = 10,
    /// Request carried a stale or mismatched authority generation.
    AuthorityGenerationStale = 11,
    /// Model generation was quarantined after a prior fault/panic.
    ModelGenerationQuarantined = 12,
    /// Request was cooperatively cancelled before resource reservation.
    CooperativeCancellation = 13,
}

impl SchedulerDegradationReason {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ThermalWarmThrottle => "thermal_warm_throttle",
            Self::ThermalHotShedLowerClasses => "thermal_hot_shed_lower_classes",
            Self::ThermalCriticalHardFloorOnly => "thermal_critical_hard_floor_only",
            Self::ResourcePressureElevated => "resource_pressure_elevated",
            Self::ResourcePressureConstrained => "resource_pressure_constrained",
            Self::ResourcePressureCriticalHardFloorOnly => {
                "resource_pressure_critical_hard_floor_only"
            }
            Self::MemoryHeadroomReservedForCriticalFloor => {
                "memory_headroom_reserved_for_critical_floor"
            }
            Self::PowerCapThrottle => "power_cap_throttle",
            Self::WindowQuotaExhausted => "window_quota_exhausted",
            Self::ConcurrencyCeilingReached => "concurrency_ceiling_reached",
            Self::AuthorityGenerationStale => "authority_generation_stale",
            Self::ModelGenerationQuarantined => "model_generation_quarantined",
            Self::CooperativeCancellation => "cooperative_cancellation",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ModelSchedulerError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::ThermalWarmThrottle),
            2 => Ok(Self::ThermalHotShedLowerClasses),
            3 => Ok(Self::ThermalCriticalHardFloorOnly),
            4 => Ok(Self::ResourcePressureElevated),
            5 => Ok(Self::ResourcePressureConstrained),
            6 => Ok(Self::ResourcePressureCriticalHardFloorOnly),
            7 => Ok(Self::MemoryHeadroomReservedForCriticalFloor),
            8 => Ok(Self::PowerCapThrottle),
            9 => Ok(Self::WindowQuotaExhausted),
            10 => Ok(Self::ConcurrencyCeilingReached),
            11 => Ok(Self::AuthorityGenerationStale),
            12 => Ok(Self::ModelGenerationQuarantined),
            13 => Ok(Self::CooperativeCancellation),
            other => Err(ModelSchedulerError::MalformedWire(format!(
                "unknown SchedulerDegradationReason tag {other}"
            ))),
        }
    }
}

/// Typed errors returned by the thermal/pressure model scheduler and wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelSchedulerError {
    /// Policy configuration violated an invariant (e.g. invalid hysteresis ordering or floors).
    InvalidPolicy(String),
    /// Telemetry sample had out-of-range temperature, utilization, or zero memory limit.
    InvalidSample(String),
    /// Request failed basic validation (empty/overlong ID, zero memory estimate).
    InvalidRequest(String),
    /// Telemetry timestamp regressed earlier than the scheduler's monotonic clock.
    TimestampRegression {
        /// Previous monotonic scheduler timestamp.
        previous: TimestampNs,
        /// Rejected regressive sample timestamp.
        observed: TimestampNs,
    },
    /// Authority generation attempted a non-monotonic downgrade.
    AuthorityGenerationRegression {
        /// Current scheduler authority generation.
        current: u64,
        /// Rejected lower generation.
        requested: u64,
    },
    /// Same `request_id` was resubmitted with different semantic request fields.
    DuplicateRequestConflict {
        /// Colliding request identifier.
        request_id: String,
    },
    /// Idempotency cache reached its hard upper bound; rotate or create a fresh scheduler epoch.
    IdempotencyCacheFull {
        /// Hard configured capacity.
        capacity: usize,
    },
    /// Attempted to complete an unknown or already-completed active request.
    UnknownActiveRequest {
        /// Missing active request identifier.
        request_id: String,
    },
    /// Canonical wire encoding/decoding rejected malformed or tampered `FSSMMS01` bytes.
    MalformedWire(String),
}

impl ModelSchedulerError {
    /// Stable machine-readable error identity.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidPolicy(_) => "ERR-MODEL-SCHED-POLICY-001",
            Self::InvalidSample(_) => "ERR-MODEL-SCHED-SAMPLE-001",
            Self::InvalidRequest(_) => "ERR-MODEL-SCHED-REQUEST-001",
            Self::TimestampRegression { .. } => "ERR-MODEL-SCHED-TIME-REGRESS-001",
            Self::AuthorityGenerationRegression { .. } => "ERR-MODEL-SCHED-AUTH-REGRESS-001",
            Self::DuplicateRequestConflict { .. } => "ERR-MODEL-SCHED-IDEMPOTENCY-CONFLICT-001",
            Self::IdempotencyCacheFull { .. } => "ERR-MODEL-SCHED-CACHE-FULL-001",
            Self::UnknownActiveRequest { .. } => "ERR-MODEL-SCHED-UNKNOWN-ACTIVE-001",
            Self::MalformedWire(_) => "ERR-MODEL-SCHED-WIRE-001",
        }
    }
}

impl fmt::Display for ModelSchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(msg) => write!(f, "invalid model scheduler policy: {msg}"),
            Self::InvalidSample(msg) => write!(f, "invalid thermal/pressure sample: {msg}"),
            Self::InvalidRequest(msg) => write!(f, "invalid model work request: {msg}"),
            Self::TimestampRegression { previous, observed } => write!(
                f,
                "scheduler timestamp regressed from {} ns to {} ns",
                previous.0, observed.0
            ),
            Self::AuthorityGenerationRegression { current, requested } => write!(
                f,
                "authority generation regressed from {current} to {requested}"
            ),
            Self::DuplicateRequestConflict { request_id } => write!(
                f,
                "duplicate request_id '{request_id}' conflicted with prior semantic request"
            ),
            Self::IdempotencyCacheFull { capacity } => write!(
                f,
                "scheduler idempotency cache reached hard limit ({capacity} entries)"
            ),
            Self::UnknownActiveRequest { request_id } => {
                write!(f, "no active scheduled work with request_id '{request_id}'")
            }
            Self::MalformedWire(msg) => write!(f, "malformed FSSMMS01 wire payload: {msg}"),
        }
    }
}

impl Error for ModelSchedulerError {}

/// Hysteresis thresholds (millicelsius) and cool-down dwell preventing rapid thermal flapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThermalHysteresisConfig {
    /// Temperature entering `Warm` (>=).
    pub warm_enter_mc: i32,
    /// Temperature allowing exit from `Warm` back to `Nominal` (<=).
    pub warm_exit_mc: i32,
    /// Temperature entering `Hot` (>=).
    pub hot_enter_mc: i32,
    /// Temperature allowing exit from `Hot` back to `Warm` (<=).
    pub hot_exit_mc: i32,
    /// Temperature entering `Critical` (>=).
    pub critical_enter_mc: i32,
    /// Temperature allowing exit from `Critical` back to `Hot` (<=).
    pub critical_exit_mc: i32,
    /// Minimum dwell time (ns) before stepping DOWN a thermal state. Escalation is immediate.
    pub min_cool_dwell_ns: i128,
}

impl Default for ThermalHysteresisConfig {
    fn default() -> Self {
        Self {
            warm_enter_mc: 65_000,
            warm_exit_mc: 60_000,
            hot_enter_mc: 80_000,
            hot_exit_mc: 74_000,
            critical_enter_mc: 92_000,
            critical_exit_mc: 85_000,
            min_cool_dwell_ns: 5_000_000_000,
        }
    }
}

impl ThermalHysteresisConfig {
    /// Validate monotonic hysteresis ordering and bounded ranges.
    pub fn validate(&self) -> Result<(), ModelSchedulerError> {
        let ordered = self.warm_exit_mc >= MIN_CPU_TEMP_MC
            && self.warm_exit_mc < self.warm_enter_mc
            && self.warm_enter_mc < self.hot_exit_mc
            && self.hot_exit_mc < self.hot_enter_mc
            && self.hot_enter_mc < self.critical_exit_mc
            && self.critical_exit_mc < self.critical_enter_mc
            && self.critical_enter_mc <= MAX_CPU_TEMP_MC;
        if !ordered {
            return Err(ModelSchedulerError::InvalidPolicy(
                "thermal hysteresis thresholds must strictly satisfy warm_exit < warm_enter < hot_exit < hot_enter < critical_exit < critical_enter within [-40C, 150C]"
                    .to_owned(),
            ));
        }
        if self.min_cool_dwell_ns < 0 {
            return Err(ModelSchedulerError::InvalidPolicy(
                "min_cool_dwell_ns must be non-negative".to_owned(),
            ));
        }
        Ok(())
    }

    /// Pure deterministic thermal transition step with immediate escalation and dwell-guarded recovery.
    #[must_use]
    pub fn next_state(
        self,
        current: ThermalState,
        entered_at: TimestampNs,
        sample_ts: TimestampNs,
        cpu_temp_mc: i32,
    ) -> (ThermalState, TimestampNs) {
        let raw_up = if cpu_temp_mc >= self.critical_enter_mc {
            ThermalState::Critical
        } else if cpu_temp_mc >= self.hot_enter_mc {
            ThermalState::Hot
        } else if cpu_temp_mc >= self.warm_enter_mc {
            ThermalState::Warm
        } else {
            ThermalState::Nominal
        };

        // Escalation is immediate for thermal safety.
        if raw_up > current {
            return (raw_up, sample_ts);
        }

        // Cooling requires both dwell satisfaction and passing the lower exit threshold.
        let elapsed = sample_ts.0.saturating_sub(entered_at.0);
        if elapsed < self.min_cool_dwell_ns {
            return (current, entered_at);
        }

        let cooled = match current {
            ThermalState::Nominal => ThermalState::Nominal,
            ThermalState::Warm => {
                if cpu_temp_mc <= self.warm_exit_mc {
                    ThermalState::Nominal
                } else {
                    ThermalState::Warm
                }
            }
            ThermalState::Hot => {
                if cpu_temp_mc <= self.warm_exit_mc {
                    ThermalState::Nominal
                } else if cpu_temp_mc <= self.hot_exit_mc {
                    ThermalState::Warm
                } else {
                    ThermalState::Hot
                }
            }
            ThermalState::Critical => {
                if cpu_temp_mc <= self.warm_exit_mc {
                    ThermalState::Nominal
                } else if cpu_temp_mc <= self.hot_exit_mc {
                    ThermalState::Warm
                } else if cpu_temp_mc <= self.critical_exit_mc {
                    ThermalState::Hot
                } else {
                    ThermalState::Critical
                }
            }
        };

        if cooled != current {
            (cooled, sample_ts)
        } else {
            (current, entered_at)
        }
    }
}

/// Hard-floor scheduling policy binding thermal thresholds, concurrency caps, and reserved floors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardFloorPolicy {
    /// Maximum aggregate CPU execution threads across all concurrent model invocations.
    pub max_total_threads: ExecThreads,
    /// Non-negotiable minimum CPU execution threads guaranteed to `CriticalSafetyDetector`.
    pub critical_min_threads: ExecThreads,
    /// Non-negotiable minimum `CriticalSafetyDetector` admissions guaranteed per window.
    pub critical_min_invocations_per_window: u32,
    /// Total invocation quota across all classes per window (must be >= critical floor).
    pub max_window_invocations_total: u32,
    /// Positive window duration in nanoseconds.
    pub window_ns: i128,
    /// Memory bytes reserved exclusively for `CriticalSafetyDetector` headroom.
    pub critical_reserved_memory_bytes: u64,
    /// Hard per-request memory ceiling for `StandardAnalytics`.
    pub standard_max_memory_bytes: u64,
    /// Hard per-request memory ceiling for `BackgroundEnrichment`.
    pub background_max_memory_bytes: u64,
    /// Maximum active concurrent invocations across all classes (1..=64).
    pub max_active_invocations: usize,
    /// Thermal hysteresis thresholds and cool-down dwell.
    pub thermal_hysteresis: ThermalHysteresisConfig,
    /// Pinned `ContractBasis` digest governing this scheduling policy.
    pub contract_basis_digest: ContentDigest,
    /// Immutable policy generation counter.
    pub policy_generation: u64,
}

impl HardFloorPolicy {
    /// Validate every hard-floor invariant before constructing a scheduler.
    pub fn validate(&self) -> Result<(), ModelSchedulerError> {
        self.thermal_hysteresis.validate()?;
        if self.critical_min_threads.get() > self.max_total_threads.get() {
            return Err(ModelSchedulerError::InvalidPolicy(
                "critical_min_threads exceeds max_total_threads".to_owned(),
            ));
        }
        if self.critical_min_invocations_per_window == 0 {
            return Err(ModelSchedulerError::InvalidPolicy(
                "critical_min_invocations_per_window must be >= 1".to_owned(),
            ));
        }
        if self.max_window_invocations_total < self.critical_min_invocations_per_window {
            return Err(ModelSchedulerError::InvalidPolicy(
                "max_window_invocations_total must be >= critical_min_invocations_per_window"
                    .to_owned(),
            ));
        }
        if self.window_ns <= 0 {
            return Err(ModelSchedulerError::InvalidPolicy(
                "window_ns must be strictly positive".to_owned(),
            ));
        }
        if self.max_active_invocations == 0
            || self.max_active_invocations > MAX_SCHEDULER_ACTIVE_INVOCATIONS
        {
            return Err(ModelSchedulerError::InvalidPolicy(format!(
                "max_active_invocations must be in 1..={MAX_SCHEDULER_ACTIVE_INVOCATIONS}"
            )));
        }
        if self.critical_reserved_memory_bytes == 0 {
            return Err(ModelSchedulerError::InvalidPolicy(
                "critical_reserved_memory_bytes must be > 0".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment over all fields of this policy.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(MODEL_SCHEDULER_RECEIPT_DOMAIN);
        e.text("policy.v1");
        e.u64(self.max_total_threads.get() as u64);
        e.u64(self.critical_min_threads.get() as u64);
        e.u32(self.critical_min_invocations_per_window);
        e.u32(self.max_window_invocations_total);
        e.i128(self.window_ns);
        e.u64(self.critical_reserved_memory_bytes);
        e.u64(self.standard_max_memory_bytes);
        e.u64(self.background_max_memory_bytes);
        e.u64(self.max_active_invocations as u64);
        e.i128(i128::from(self.thermal_hysteresis.warm_enter_mc));
        e.i128(i128::from(self.thermal_hysteresis.warm_exit_mc));
        e.i128(i128::from(self.thermal_hysteresis.hot_enter_mc));
        e.i128(i128::from(self.thermal_hysteresis.hot_exit_mc));
        e.i128(i128::from(self.thermal_hysteresis.critical_enter_mc));
        e.i128(i128::from(self.thermal_hysteresis.critical_exit_mc));
        e.i128(self.thermal_hysteresis.min_cool_dwell_ns);
        e.digest(self.contract_basis_digest);
        e.u64(self.policy_generation);
        ContentDigest::sha256(&e.finish())
    }
}

/// Explicit host thermal and resource pressure snapshot supplied to the scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerPressureSample {
    /// Explicit monotonic timestamp (ns) of this sample.
    pub timestamp: TimestampNs,
    /// Measured CPU package temperature in millicelsius (e.g., 72_500 = 72.5 C).
    pub cpu_temp_mc: i32,
    /// Coarse resource pressure reported by the host runtime.
    pub resource_pressure: ResourcePressure,
    /// CPU utilization in parts-per-million (`0..=1_000_000`).
    pub cpu_util_ppm: u32,
    /// Host memory currently occupied outside or including scheduler-tracked work (bytes).
    pub memory_used_bytes: u64,
    /// Hard memory ceiling available to model workloads (bytes, must be > 0).
    pub memory_limit_bytes: u64,
    /// Optional host power cap in milliwatts.
    pub power_budget_mw: Option<u32>,
    /// Optional instantaneous host power draw in milliwatts.
    pub power_draw_mw: Option<u32>,
}

impl SchedulerPressureSample {
    /// Validate telemetry bounds before scheduling.
    pub fn validate(&self) -> Result<(), ModelSchedulerError> {
        if !(MIN_CPU_TEMP_MC..=MAX_CPU_TEMP_MC).contains(&self.cpu_temp_mc) {
            return Err(ModelSchedulerError::InvalidSample(format!(
                "cpu_temp_mc {} outside [{MIN_CPU_TEMP_MC}, {MAX_CPU_TEMP_MC}]",
                self.cpu_temp_mc
            )));
        }
        if self.cpu_util_ppm > MAX_CPU_UTIL_PPM {
            return Err(ModelSchedulerError::InvalidSample(format!(
                "cpu_util_ppm {} exceeds {MAX_CPU_UTIL_PPM}",
                self.cpu_util_ppm
            )));
        }
        if self.memory_limit_bytes == 0 {
            return Err(ModelSchedulerError::InvalidSample(
                "memory_limit_bytes must be > 0".to_owned(),
            ));
        }
        if let Some(cap) = self.power_budget_mw
            && cap == 0
        {
            return Err(ModelSchedulerError::InvalidSample(
                "power_budget_mw must be > 0 when present".to_owned(),
            ));
        }
        Ok(())
    }

    /// True iff both `power_budget_mw` and `power_draw_mw` are present and draw exceeds cap.
    #[must_use]
    pub const fn is_power_capped(&self) -> bool {
        match (self.power_budget_mw, self.power_draw_mw) {
            (Some(cap), Some(draw)) => draw > cap,
            _ => false,
        }
    }
}

/// Typed admission request for one bounded model execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelWorkRequest {
    /// Stable idempotent request identifier (1..=128 bytes).
    pub request_id: String,
    /// Scheduling priority class.
    pub workload_class: ModelWorkloadClass,
    /// Exact immutable model package/generation digest.
    pub model_generation_digest: ContentDigest,
    /// Exact kernel backend/generation digest.
    pub kernel_generation_digest: ContentDigest,
    /// Caller's desired CPU execution threads.
    pub requested_threads: ExecThreads,
    /// Estimated scratch + activation memory footprint (bytes, must be > 0).
    pub estimated_memory_bytes: u64,
    /// Estimated multiply-accumulate operations for accounting.
    pub estimated_macs: u64,
    /// Authority generation pinned by the caller; stale generations fail closed.
    pub required_authority_generation: u64,
    /// Explicit pre-admission cancellation signal.
    pub cancelled_before_admit: bool,
    /// Explicit quarantine marker (for example after an observed model panic/fault).
    pub quarantined_model: bool,
}

impl ModelWorkRequest {
    /// Validate request fields.
    pub fn validate(&self) -> Result<(), ModelSchedulerError> {
        if self.request_id.is_empty() || self.request_id.len() > MAX_SCHEDULER_REQUEST_ID_BYTES {
            return Err(ModelSchedulerError::InvalidRequest(format!(
                "request_id length must be in 1..={MAX_SCHEDULER_REQUEST_ID_BYTES}"
            )));
        }
        if self.estimated_memory_bytes == 0 {
            return Err(ModelSchedulerError::InvalidRequest(
                "estimated_memory_bytes must be > 0".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical fingerprint over semantic request fields for idempotency conflict detection.
    #[must_use]
    pub fn semantic_fingerprint(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(MODEL_SCHEDULER_RECEIPT_DOMAIN);
        e.text("request.v1");
        e.text(&self.request_id);
        e.u8(self.workload_class.tag());
        e.digest(self.model_generation_digest);
        e.digest(self.kernel_generation_digest);
        e.u64(self.requested_threads.get() as u64);
        e.u64(self.estimated_memory_bytes);
        e.u64(self.estimated_macs);
        e.u64(self.required_authority_generation);
        e.bool(self.cancelled_before_admit);
        e.bool(self.quarantined_model);
        ContentDigest::sha256(&e.finish())
    }
}

/// Active admitted invocation currently holding threads and memory in the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveScheduledWork {
    /// Stable request identifier.
    pub request_id: String,
    /// Scheduling class.
    pub workload_class: ModelWorkloadClass,
    /// Admitted CPU thread count.
    pub granted_threads: usize,
    /// Reserved memory footprint in bytes.
    pub reserved_memory_bytes: u64,
    /// Exact model generation digest.
    pub model_generation_digest: ContentDigest,
    /// Timestamp when admitted.
    pub admitted_at: TimestampNs,
}

/// Record of one lower-priority active workload deterministically preempted for a critical floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreemptedWorkRecord {
    /// Preempted workload's request identifier.
    pub request_id: String,
    /// Preempted workload's class (never `CriticalSafetyDetector`).
    pub workload_class: ModelWorkloadClass,
    /// CPU threads reclaimed by preemption.
    pub reclaimed_threads: usize,
    /// Memory bytes reclaimed by preemption.
    pub reclaimed_memory_bytes: u64,
}

/// Sealed, content-addressed `FSSMMS01` v1 scheduling receipt.
///
/// Derived cognition control metadata only: never grants effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSchedulerReceipt {
    /// Wire/schema version (`1`).
    pub format_version: u32,
    /// Idempotent request identifier.
    pub request_id: String,
    /// Workload class of this request.
    pub workload_class: ModelWorkloadClass,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Digest of the governing [`HardFloorPolicy`].
    pub policy_digest: ContentDigest,
    /// Exact model generation digest.
    pub model_generation_digest: ContentDigest,
    /// Exact kernel generation digest.
    pub kernel_generation_digest: ContentDigest,
    /// Scheduler's active authority generation at decision time.
    pub authority_generation: u64,
    /// Monotonic decision timestamp.
    pub timestamp: TimestampNs,
    /// Effective hysteresis-filtered thermal state at decision time.
    pub effective_thermal_state: ThermalState,
    /// Coarse resource pressure from the triggering telemetry sample.
    pub resource_pressure: ResourcePressure,
    /// Non-collapsed terminal admission state.
    pub decision_state: SchedulerDecisionState,
    /// Typed explanation of any throttling, shedding, or refusal.
    pub degradation_reason: SchedulerDegradationReason,
    /// Requested CPU threads.
    pub requested_threads: usize,
    /// Granted CPU threads (`>= 1` iff admitted, `0` otherwise).
    pub granted_threads: usize,
    /// True iff this admission was protected by a `CriticalSafetyDetector` hard floor.
    pub hard_floor_protected: bool,
    /// Lower-priority active jobs deterministically preempted to satisfy the critical floor.
    pub preempted_work: Vec<PreemptedWorkRecord>,
    /// Total active scheduler threads immediately after this decision.
    pub active_threads_after: usize,
    /// Total active scheduler reserved memory bytes immediately after this decision.
    pub active_memory_bytes_after: u64,
    /// Total window invocations consumed immediately after this decision.
    pub window_invocations_used: u32,
    /// Critical-class window invocations consumed immediately after this decision.
    pub critical_floor_invocations_used: u32,
    /// Bounded, actionable retry/remediation guidance (never secrets or private media).
    pub recovery_guidance: String,
    /// Canonical domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl ModelSchedulerReceipt {
    /// Model scheduling is cognition-plane resource governance only and NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Returns the admitted [`ExecThreads`] to pass straight into `OptimizedGraph` or
    /// `StaticKernelDispatcher`, or `None` when not admitted.
    #[must_use]
    pub fn admitted_exec_threads(&self) -> Option<ExecThreads> {
        if self.decision_state.is_admitted() {
            ExecThreads::new(self.granted_threads).ok()
        } else {
            None
        }
    }

    /// Recomputes the canonical domain-separated SHA-256 receipt digest.
    #[must_use]
    pub fn recompute_digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(MODEL_SCHEDULER_RECEIPT_DOMAIN);
        self.encode_body(&mut e);
        ContentDigest::sha256(&e.finish())
    }

    fn encode_body(&self, e: &mut CanonicalEncoder) {
        e.u32(self.format_version);
        e.text(&self.request_id);
        e.u8(self.workload_class.tag());
        e.digest(self.contract_basis_digest);
        e.digest(self.policy_digest);
        e.digest(self.model_generation_digest);
        e.digest(self.kernel_generation_digest);
        e.u64(self.authority_generation);
        e.i128(self.timestamp.0);
        e.u8(self.effective_thermal_state.tag());
        e.u8(resource_pressure_tag(self.resource_pressure));
        e.u8(self.decision_state.tag());
        e.u8(self.degradation_reason.tag());
        e.u64(self.requested_threads as u64);
        e.u64(self.granted_threads as u64);
        e.bool(self.hard_floor_protected);
        e.u64(self.preempted_work.len() as u64);
        for p in &self.preempted_work {
            e.text(&p.request_id);
            e.u8(p.workload_class.tag());
            e.u64(p.reclaimed_threads as u64);
            e.u64(p.reclaimed_memory_bytes);
        }
        e.u64(self.active_threads_after as u64);
        e.u64(self.active_memory_bytes_after);
        e.u32(self.window_invocations_used);
        e.u32(self.critical_floor_invocations_used);
        e.text(&self.recovery_guidance);
    }

    /// Verify internal invariants and canonical digest integrity.
    pub fn verify_integrity(&self) -> Result<(), ModelSchedulerError> {
        if self.format_version != MODEL_SCHEDULER_WIRE_VERSION {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        if self.request_id.is_empty() || self.request_id.len() > MAX_SCHEDULER_REQUEST_ID_BYTES {
            return Err(ModelSchedulerError::MalformedWire(
                "request_id length out of bounds".to_owned(),
            ));
        }
        if self.recovery_guidance.len() > MAX_SCHEDULER_GUIDANCE_BYTES {
            return Err(ModelSchedulerError::MalformedWire(
                "recovery_guidance exceeds bound".to_owned(),
            ));
        }
        if self.requested_threads == 0 {
            return Err(ModelSchedulerError::MalformedWire(
                "requested_threads must be >= 1".to_owned(),
            ));
        }
        if self.decision_state.is_admitted() {
            if self.granted_threads == 0 {
                return Err(ModelSchedulerError::MalformedWire(
                    "admitted decision must grant >= 1 thread".to_owned(),
                ));
            }
            if self.decision_state == SchedulerDecisionState::AdmittedFull
                && self.granted_threads != self.requested_threads
            {
                return Err(ModelSchedulerError::MalformedWire(
                    "AdmittedFull requires granted_threads == requested_threads".to_owned(),
                ));
            }
            if self.decision_state == SchedulerDecisionState::AdmittedDegradedThreads
                && self.granted_threads >= self.requested_threads
            {
                return Err(ModelSchedulerError::MalformedWire(
                    "AdmittedDegradedThreads requires granted_threads < requested_threads"
                        .to_owned(),
                ));
            }
        } else if self.granted_threads != 0 {
            return Err(ModelSchedulerError::MalformedWire(
                "non-admitted decision must grant 0 threads".to_owned(),
            ));
        }
        if !self.preempted_work.is_empty() && !self.workload_class.is_critical() {
            return Err(ModelSchedulerError::MalformedWire(
                "only CriticalSafetyDetector may preempt active work".to_owned(),
            ));
        }
        for p in &self.preempted_work {
            if p.workload_class.is_critical() {
                return Err(ModelSchedulerError::MalformedWire(
                    "CriticalSafetyDetector cannot be preempted".to_owned(),
                ));
            }
            if p.request_id.is_empty() || p.request_id.len() > MAX_SCHEDULER_REQUEST_ID_BYTES {
                return Err(ModelSchedulerError::MalformedWire(
                    "preempted request_id length out of bounds".to_owned(),
                ));
            }
            if p.reclaimed_threads == 0 || p.reclaimed_memory_bytes == 0 {
                return Err(ModelSchedulerError::MalformedWire(
                    "preempted work record must reclaim non-zero threads and memory".to_owned(),
                ));
            }
        }
        let expected = self.recompute_digest();
        if expected != self.receipt_digest {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "receipt_digest mismatch: expected {expected}, found {}",
                self.receipt_digest
            )));
        }
        Ok(())
    }

    /// Encode this receipt into a framed, SHA-256-checksummed `FSSMMS01` v1 wire envelope.
    pub fn encode_wire(&self) -> Result<Vec<u8>, ModelSchedulerError> {
        self.verify_integrity()?;
        let mut e = CanonicalEncoder::new();
        self.encode_body(&mut e);
        e.digest(self.receipt_digest);
        let payload = e
            .finish_checked()
            .map_err(|err| ModelSchedulerError::MalformedWire(format!("encode failed: {err}")))?;
        let total_len = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| ModelSchedulerError::MalformedWire("wire length overflow".to_owned()))?;
        if total_len > MAX_MODEL_SCHEDULER_WIRE_BYTES {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "wire size {total_len} exceeds ceiling {MAX_MODEL_SCHEDULER_WIRE_BYTES}"
            )));
        }
        let payload_len_u32 = u32::try_from(payload.len()).map_err(|_| {
            ModelSchedulerError::MalformedWire("payload length exceeds u32".to_owned())
        })?;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&MODEL_SCHEDULER_WIRE_MAGIC);
        out.extend_from_slice(&MODEL_SCHEDULER_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&payload_len_u32.to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|err| ModelSchedulerError::MalformedWire(format!("hasher error: {err}")))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Decode and strictly verify a framed `FSSMMS01` v1 wire envelope.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, ModelSchedulerError> {
        if bytes.len() < WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES {
            return Err(ModelSchedulerError::MalformedWire(
                "truncated FSSMMS01 frame".to_owned(),
            ));
        }
        if bytes.len() > MAX_MODEL_SCHEDULER_WIRE_BYTES {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "frame size {} exceeds ceiling {MAX_MODEL_SCHEDULER_WIRE_BYTES}",
                bytes.len()
            )));
        }
        if bytes[..8] != MODEL_SCHEDULER_WIRE_MAGIC {
            return Err(ModelSchedulerError::MalformedWire(
                "invalid FSSMMS01 wire magic".to_owned(),
            ));
        }
        let version =
            u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| {
                ModelSchedulerError::MalformedWire("bad version header".to_owned())
            })?);
        if version != MODEL_SCHEDULER_WIRE_VERSION {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "unsupported FSSMMS01 wire version {version}"
            )));
        }
        let declared_len = u32::from_be_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| ModelSchedulerError::MalformedWire("bad length header".to_owned()))?,
        ) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| ModelSchedulerError::MalformedWire("wire length overflow".to_owned()))?;
        if bytes.len() != expected_total {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "frame length mismatch: declared total {expected_total}, actual {}",
                bytes.len()
            )));
        }
        let body_end = WIRE_HEADER_BYTES + declared_len;
        let mut hasher = Sha256Hasher::new();
        hasher.update(&bytes[..body_end]);
        let computed = hasher
            .finalize()
            .map_err(|err| ModelSchedulerError::MalformedWire(format!("hasher error: {err}")))?;
        if bytes[body_end..] != computed {
            return Err(ModelSchedulerError::MalformedWire(
                "FSSMMS01 trailer SHA-256 checksum mismatch".to_owned(),
            ));
        }

        let mut d = CanonicalDecoder::new(&bytes[WIRE_HEADER_BYTES..body_end]);
        let map_dec = |err| ModelSchedulerError::MalformedWire(format!("canonical decode: {err}"));
        let format_version = d.u32().map_err(map_dec)?;
        let request_id = d.text().map_err(map_dec)?.to_owned();
        let workload_class = ModelWorkloadClass::from_tag(d.u8().map_err(map_dec)?)?;
        let contract_basis_digest = d.digest().map_err(map_dec)?;
        let policy_digest = d.digest().map_err(map_dec)?;
        let model_generation_digest = d.digest().map_err(map_dec)?;
        let kernel_generation_digest = d.digest().map_err(map_dec)?;
        let authority_generation = d.u64().map_err(map_dec)?;
        let timestamp = TimestampNs(d.i128().map_err(map_dec)?);
        let effective_thermal_state = ThermalState::from_tag(d.u8().map_err(map_dec)?)?;
        let resource_pressure = resource_pressure_from_tag(d.u8().map_err(map_dec)?)?;
        let decision_state = SchedulerDecisionState::from_tag(d.u8().map_err(map_dec)?)?;
        let degradation_reason = SchedulerDegradationReason::from_tag(d.u8().map_err(map_dec)?)?;
        let requested_threads = usize::try_from(d.u64().map_err(map_dec)?).map_err(|_| {
            ModelSchedulerError::MalformedWire("requested_threads overflow".to_owned())
        })?;
        let granted_threads = usize::try_from(d.u64().map_err(map_dec)?).map_err(|_| {
            ModelSchedulerError::MalformedWire("granted_threads overflow".to_owned())
        })?;
        let hard_floor_protected = d.bool().map_err(map_dec)?;
        let preempted_count = usize::try_from(d.u64().map_err(map_dec)?).map_err(|_| {
            ModelSchedulerError::MalformedWire("preempted_count overflow".to_owned())
        })?;
        if preempted_count > MAX_SCHEDULER_ACTIVE_INVOCATIONS {
            return Err(ModelSchedulerError::MalformedWire(format!(
                "preempted_count {preempted_count} exceeds {MAX_SCHEDULER_ACTIVE_INVOCATIONS}"
            )));
        }
        let mut preempted_work = Vec::with_capacity(preempted_count);
        for _ in 0..preempted_count {
            let p_req = d.text().map_err(map_dec)?.to_owned();
            let p_class = ModelWorkloadClass::from_tag(d.u8().map_err(map_dec)?)?;
            let reclaimed_threads = usize::try_from(d.u64().map_err(map_dec)?).map_err(|_| {
                ModelSchedulerError::MalformedWire("reclaimed_threads overflow".to_owned())
            })?;
            let reclaimed_memory_bytes = d.u64().map_err(map_dec)?;
            preempted_work.push(PreemptedWorkRecord {
                request_id: p_req,
                workload_class: p_class,
                reclaimed_threads,
                reclaimed_memory_bytes,
            });
        }
        let active_threads_after = usize::try_from(d.u64().map_err(map_dec)?).map_err(|_| {
            ModelSchedulerError::MalformedWire("active_threads_after overflow".to_owned())
        })?;
        let active_memory_bytes_after = d.u64().map_err(map_dec)?;
        let window_invocations_used = d.u32().map_err(map_dec)?;
        let critical_floor_invocations_used = d.u32().map_err(map_dec)?;
        let recovery_guidance = d.text().map_err(map_dec)?.to_owned();
        let receipt_digest = d.digest().map_err(map_dec)?;
        d.ensure_finished().map_err(map_dec)?;

        let receipt = Self {
            format_version,
            request_id,
            workload_class,
            contract_basis_digest,
            policy_digest,
            model_generation_digest,
            kernel_generation_digest,
            authority_generation,
            timestamp,
            effective_thermal_state,
            resource_pressure,
            decision_state,
            degradation_reason,
            requested_threads,
            granted_threads,
            hard_floor_protected,
            preempted_work,
            active_threads_after,
            active_memory_bytes_after,
            window_invocations_used,
            critical_floor_invocations_used,
            recovery_guidance,
            receipt_digest,
        };
        receipt.verify_integrity()?;
        Ok(receipt)
    }
}

/// Pure snapshot of scheduler state consumed by the independent reference oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerStateSnapshot {
    /// Current active authority generation.
    pub active_authority_generation: u64,
    /// Current hysteresis-filtered thermal state.
    pub effective_thermal_state: ThermalState,
    /// Timestamp when the current thermal state was entered.
    pub thermal_entered_at: TimestampNs,
    /// Start timestamp of the current invocation quota window.
    pub window_started_at: TimestampNs,
    /// Total admissions counted in the current window.
    pub window_invocations_used: u32,
    /// Critical-class admissions counted in the current window.
    pub critical_floor_invocations_used: u32,
    /// Active jobs ordered deterministically by `request_id`.
    pub active_jobs: Vec<ActiveScheduledWork>,
    /// Quarantined model generations.
    pub quarantined_models: BTreeSet<ContentDigest>,
}

/// Expected decision summary returned by [`oracle_evaluate_admission`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleAdmissionExpectation {
    /// Expected post-hysteresis thermal state.
    pub effective_thermal_state: ThermalState,
    /// Expected terminal decision state.
    pub decision_state: SchedulerDecisionState,
    /// Expected degradation/refusal reason.
    pub degradation_reason: SchedulerDegradationReason,
    /// Expected granted threads (`0` when not admitted).
    pub granted_threads: usize,
    /// Whether the critical hard floor protected this admission.
    pub hard_floor_protected: bool,
    /// Ordered IDs of lower-priority active jobs preempted.
    pub preempted_request_ids: Vec<String>,
}

/// Independent stateless reference oracle for `FSS-150` admission semantics.
///
/// Computes the exact expected thermal transition, pressure throttling, hard-floor enforcement,
/// and lower-priority preemption set from pure inputs so differential tests can certify
/// [`ThermalPressureModelScheduler`] against a simple, transparent specification.
#[must_use]
pub fn oracle_evaluate_admission(
    policy: &HardFloorPolicy,
    snapshot: &SchedulerStateSnapshot,
    sample: &SchedulerPressureSample,
    request: &ModelWorkRequest,
    cx_cancelled: bool,
) -> OracleAdmissionExpectation {
    let (thermal, _) = policy.thermal_hysteresis.next_state(
        snapshot.effective_thermal_state,
        snapshot.thermal_entered_at,
        sample.timestamp,
        sample.cpu_temp_mc,
    );

    if cx_cancelled || request.cancelled_before_admit {
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: SchedulerDecisionState::Cancelled,
            degradation_reason: SchedulerDegradationReason::CooperativeCancellation,
            granted_threads: 0,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    if request.required_authority_generation != snapshot.active_authority_generation {
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: SchedulerDecisionState::RefusedQuarantinedOrStale,
            degradation_reason: SchedulerDegradationReason::AuthorityGenerationStale,
            granted_threads: 0,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    if request.quarantined_model
        || snapshot
            .quarantined_models
            .contains(&request.model_generation_digest)
    {
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: SchedulerDecisionState::RefusedQuarantinedOrStale,
            degradation_reason: SchedulerDegradationReason::ModelGenerationQuarantined,
            granted_threads: 0,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    let window_elapsed = sample
        .timestamp
        .0
        .saturating_sub(snapshot.window_started_at.0);
    let (win_total, win_crit) = if window_elapsed >= policy.window_ns {
        (0_u32, 0_u32)
    } else {
        (
            snapshot.window_invocations_used,
            snapshot.critical_floor_invocations_used,
        )
    };

    let active_threads: usize = snapshot.active_jobs.iter().map(|j| j.granted_threads).sum();
    let active_mem: u64 = snapshot
        .active_jobs
        .iter()
        .fold(0_u64, |acc, j| acc.saturating_add(j.reserved_memory_bytes));
    let active_count = snapshot.active_jobs.len();

    let under_critical =
        thermal == ThermalState::Critical || sample.resource_pressure == ResourcePressure::Critical;
    let critical_reason = if thermal == ThermalState::Critical {
        SchedulerDegradationReason::ThermalCriticalHardFloorOnly
    } else {
        SchedulerDegradationReason::ResourcePressureCriticalHardFloorOnly
    };

    // Non-critical classes are shed immediately under Hot/Critical thermal or Constrained/Critical pressure.
    if !request.workload_class.is_critical() {
        if under_critical {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::DeferredByPressure,
                degradation_reason: critical_reason,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }
        if thermal == ThermalState::Hot {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::DeferredByPressure,
                degradation_reason: SchedulerDegradationReason::ThermalHotShedLowerClasses,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }
        if sample.resource_pressure == ResourcePressure::Constrained {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::DeferredByPressure,
                degradation_reason: SchedulerDegradationReason::ResourcePressureConstrained,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }
        if request.workload_class == ModelWorkloadClass::BackgroundEnrichment {
            if thermal == ThermalState::Warm {
                return OracleAdmissionExpectation {
                    effective_thermal_state: thermal,
                    decision_state: SchedulerDecisionState::DeferredByPressure,
                    degradation_reason: SchedulerDegradationReason::ThermalWarmThrottle,
                    granted_threads: 0,
                    hard_floor_protected: false,
                    preempted_request_ids: Vec::new(),
                };
            }
            if sample.resource_pressure == ResourcePressure::Elevated {
                return OracleAdmissionExpectation {
                    effective_thermal_state: thermal,
                    decision_state: SchedulerDecisionState::DeferredByPressure,
                    degradation_reason: SchedulerDegradationReason::ResourcePressureElevated,
                    granted_threads: 0,
                    hard_floor_protected: false,
                    preempted_request_ids: Vec::new(),
                };
            }
            if sample.is_power_capped() {
                return OracleAdmissionExpectation {
                    effective_thermal_state: thermal,
                    decision_state: SchedulerDecisionState::DeferredByPressure,
                    degradation_reason: SchedulerDegradationReason::PowerCapThrottle,
                    granted_threads: 0,
                    hard_floor_protected: false,
                    preempted_request_ids: Vec::new(),
                };
            }
        }

        // Per-class memory ceiling check.
        let class_mem_cap = match request.workload_class {
            ModelWorkloadClass::StandardAnalytics => policy.standard_max_memory_bytes,
            ModelWorkloadClass::BackgroundEnrichment => policy.background_max_memory_bytes,
            ModelWorkloadClass::CriticalSafetyDetector => u64::MAX,
        };
        if request.estimated_memory_bytes > class_mem_cap {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::RefusedBudgetOrCapacity,
                degradation_reason: SchedulerDegradationReason::ConcurrencyCeilingReached,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }

        // Reserve critical invocation slots in the current window.
        let critical_floor_remaining = policy
            .critical_min_invocations_per_window
            .saturating_sub(win_crit);
        let non_critical_window_cap = policy
            .max_window_invocations_total
            .saturating_sub(critical_floor_remaining);
        if win_total >= non_critical_window_cap {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::RefusedBudgetOrCapacity,
                degradation_reason: SchedulerDegradationReason::WindowQuotaExhausted,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }

        // Reserve critical memory headroom so non-critical work never starves critical safety.
        let projected_mem = sample
            .memory_used_bytes
            .max(active_mem)
            .saturating_add(request.estimated_memory_bytes);
        let non_critical_mem_ceiling = sample
            .memory_limit_bytes
            .saturating_sub(policy.critical_reserved_memory_bytes);
        if projected_mem > non_critical_mem_ceiling {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::DeferredByPressure,
                degradation_reason:
                    SchedulerDegradationReason::MemoryHeadroomReservedForCriticalFloor,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }

        // Reserve critical thread floor and active slot when pressure is non-nominal.
        let max_non_critical_threads = if thermal >= ThermalState::Warm
            || sample.resource_pressure >= ResourcePressure::Elevated
            || sample.is_power_capped()
        {
            policy
                .max_total_threads
                .get()
                .saturating_sub(policy.critical_min_threads.get())
        } else {
            policy.max_total_threads.get()
        };
        let avail_threads = max_non_critical_threads.saturating_sub(active_threads);
        if active_count >= policy.max_active_invocations || avail_threads == 0 {
            return OracleAdmissionExpectation {
                effective_thermal_state: thermal,
                decision_state: SchedulerDecisionState::RefusedBudgetOrCapacity,
                degradation_reason: SchedulerDegradationReason::ConcurrencyCeilingReached,
                granted_threads: 0,
                hard_floor_protected: false,
                preempted_request_ids: Vec::new(),
            };
        }

        // Apply thermal/pressure/power throttling to StandardAnalytics.
        let mut target = request.requested_threads.get().min(avail_threads);
        let mut reason = SchedulerDegradationReason::None;
        if thermal == ThermalState::Warm {
            target = target.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::ThermalWarmThrottle;
        } else if sample.resource_pressure == ResourcePressure::Elevated {
            target = target.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::ResourcePressureElevated;
        } else if sample.is_power_capped() {
            target = target.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::PowerCapThrottle;
        }

        let decision = if target < request.requested_threads.get() {
            if reason == SchedulerDegradationReason::None {
                reason = SchedulerDegradationReason::ConcurrencyCeilingReached;
            }
            SchedulerDecisionState::AdmittedDegradedThreads
        } else {
            SchedulerDecisionState::AdmittedFull
        };
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: decision,
            degradation_reason: reason,
            granted_threads: target,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    // --- CriticalSafetyDetector path with hard floors & deterministic preemption ---
    let hard_floor_quota_active = win_crit < policy.critical_min_invocations_per_window;
    if !hard_floor_quota_active && win_total >= policy.max_window_invocations_total {
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: SchedulerDecisionState::RefusedBudgetOrCapacity,
            degradation_reason: SchedulerDegradationReason::WindowQuotaExhausted,
            granted_threads: 0,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    // Target threads for CriticalSafetyDetector: always at least critical_min_threads (clamped by
    // requested_threads only when caller itself asked for fewer? No: requested_threads is the
    // caller's ceiling; under Critical/Hot we clamp down to critical_min_threads, never below
    // min(requested_threads, critical_min_threads)!).
    let floor_threads = request
        .requested_threads
        .get()
        .min(policy.critical_min_threads.get())
        .max(1);
    let desired_threads = if under_critical {
        floor_threads
    } else if thermal == ThermalState::Hot
        || sample.resource_pressure == ResourcePressure::Constrained
    {
        let half = (request.requested_threads.get() / 2).max(floor_threads);
        half.min(request.requested_threads.get())
    } else {
        request
            .requested_threads
            .get()
            .min(policy.max_total_threads.get())
    };

    // Determine whether preemption of lower-priority active jobs is required to satisfy
    // threads, memory, or concurrency slots for this critical request.
    let mut preempted_ids = Vec::new();
    let mut cur_threads = active_threads;
    let mut cur_active_mem = active_mem;
    let mut cur_count = active_count;
    let external_mem = sample.memory_used_bytes.saturating_sub(active_mem);

    let needs_more = |c_threads: usize, c_mem: u64, c_count: usize| -> bool {
        let free_threads = policy.max_total_threads.get().saturating_sub(c_threads);
        let projected_mem = external_mem
            .saturating_add(c_mem)
            .saturating_add(request.estimated_memory_bytes);
        free_threads < floor_threads
            || c_count >= policy.max_active_invocations
            || projected_mem > sample.memory_limit_bytes
    };

    if needs_more(cur_threads, cur_active_mem, cur_count) {
        // Preempt BackgroundEnrichment first, then StandardAnalytics, tie-broken by request_id.
        let mut victims: Vec<&ActiveScheduledWork> = snapshot
            .active_jobs
            .iter()
            .filter(|j| !j.workload_class.is_critical())
            .collect();
        victims.sort_by(|a, b| {
            b.workload_class
                .cmp(&a.workload_class)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        for v in victims {
            if !needs_more(cur_threads, cur_active_mem, cur_count) {
                break;
            }
            preempted_ids.push(v.request_id.clone());
            cur_threads = cur_threads.saturating_sub(v.granted_threads);
            cur_active_mem = cur_active_mem.saturating_sub(v.reserved_memory_bytes);
            cur_count = cur_count.saturating_sub(1);
        }
    }

    let free_threads = policy.max_total_threads.get().saturating_sub(cur_threads);
    let projected_mem = external_mem
        .saturating_add(cur_active_mem)
        .saturating_add(request.estimated_memory_bytes);
    if free_threads < floor_threads
        || cur_count >= policy.max_active_invocations
        || projected_mem > sample.memory_limit_bytes
    {
        return OracleAdmissionExpectation {
            effective_thermal_state: thermal,
            decision_state: SchedulerDecisionState::RefusedBudgetOrCapacity,
            degradation_reason: SchedulerDegradationReason::ConcurrencyCeilingReached,
            granted_threads: 0,
            hard_floor_protected: false,
            preempted_request_ids: Vec::new(),
        };
    }

    let granted = desired_threads.min(free_threads).max(floor_threads);
    let hard_floor_protected =
        under_critical || !preempted_ids.is_empty() || hard_floor_quota_active;
    let (decision_state, degradation_reason) = if under_critical {
        (
            SchedulerDecisionState::AdmittedViaHardFloor,
            critical_reason,
        )
    } else if !preempted_ids.is_empty() {
        (
            SchedulerDecisionState::AdmittedViaHardFloor,
            if thermal == ThermalState::Hot {
                SchedulerDegradationReason::ThermalHotShedLowerClasses
            } else if sample.resource_pressure == ResourcePressure::Constrained {
                SchedulerDegradationReason::ResourcePressureConstrained
            } else {
                SchedulerDegradationReason::ConcurrencyCeilingReached
            },
        )
    } else if granted < request.requested_threads.get() {
        let reason = if thermal == ThermalState::Hot {
            SchedulerDegradationReason::ThermalHotShedLowerClasses
        } else if sample.resource_pressure == ResourcePressure::Constrained {
            SchedulerDegradationReason::ResourcePressureConstrained
        } else if thermal == ThermalState::Warm {
            SchedulerDegradationReason::ThermalWarmThrottle
        } else if sample.resource_pressure == ResourcePressure::Elevated {
            SchedulerDegradationReason::ResourcePressureElevated
        } else if sample.is_power_capped() {
            SchedulerDegradationReason::PowerCapThrottle
        } else {
            SchedulerDegradationReason::ConcurrencyCeilingReached
        };
        (SchedulerDecisionState::AdmittedDegradedThreads, reason)
    } else {
        (
            SchedulerDecisionState::AdmittedFull,
            SchedulerDegradationReason::None,
        )
    };

    OracleAdmissionExpectation {
        effective_thermal_state: thermal,
        decision_state,
        degradation_reason,
        granted_threads: granted,
        hard_floor_protected,
        preempted_request_ids: preempted_ids,
    }
}

/// Deterministic CPU thermal/pressure-aware model scheduler with hard floors (`FSS-150`).
#[derive(Clone, Debug)]
pub struct ThermalPressureModelScheduler {
    policy: HardFloorPolicy,
    policy_digest: ContentDigest,
    active_authority_generation: u64,
    last_timestamp: TimestampNs,
    effective_thermal_state: ThermalState,
    thermal_entered_at: TimestampNs,
    window_started_at: TimestampNs,
    window_invocations_used: u32,
    critical_floor_invocations_used: u32,
    active_jobs: BTreeMap<String, ActiveScheduledWork>,
    idempotent_receipts: BTreeMap<String, (ContentDigest, ModelSchedulerReceipt)>,
    quarantined_models: BTreeSet<ContentDigest>,
}

impl ThermalPressureModelScheduler {
    /// Construct a validated scheduler anchored at `initial_timestamp` and `authority_generation`.
    pub fn new(
        policy: HardFloorPolicy,
        authority_generation: u64,
        initial_timestamp: TimestampNs,
    ) -> Result<Self, ModelSchedulerError> {
        policy.validate()?;
        let policy_digest = policy.digest();
        Ok(Self {
            policy,
            policy_digest,
            active_authority_generation: authority_generation,
            last_timestamp: initial_timestamp,
            effective_thermal_state: ThermalState::Nominal,
            thermal_entered_at: initial_timestamp,
            window_started_at: initial_timestamp,
            window_invocations_used: 0,
            critical_floor_invocations_used: 0,
            active_jobs: BTreeMap::new(),
            idempotent_receipts: BTreeMap::new(),
            quarantined_models: BTreeSet::new(),
        })
    }

    /// Governing immutable hard-floor policy.
    #[must_use]
    pub const fn policy(&self) -> &HardFloorPolicy {
        &self.policy
    }

    /// Canonical digest of the governing hard-floor policy.
    #[must_use]
    pub const fn policy_digest(&self) -> ContentDigest {
        self.policy_digest
    }

    /// Current hysteresis-filtered thermal state.
    #[must_use]
    pub const fn effective_thermal_state(&self) -> ThermalState {
        self.effective_thermal_state
    }

    /// Current active authority generation.
    #[must_use]
    pub const fn active_authority_generation(&self) -> u64 {
        self.active_authority_generation
    }

    /// Total CPU threads currently occupied by active model invocations.
    #[must_use]
    pub fn active_threads(&self) -> usize {
        self.active_jobs.values().map(|j| j.granted_threads).sum()
    }

    /// Total memory bytes currently reserved by active model invocations.
    #[must_use]
    pub fn active_memory_bytes(&self) -> u64 {
        self.active_jobs
            .values()
            .fold(0_u64, |acc, j| acc.saturating_add(j.reserved_memory_bytes))
    }

    /// Number of currently active admitted invocations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_jobs.len()
    }

    /// Advance the active authority generation monotonically (revoking older caller anchors).
    pub fn update_authority_generation(
        &mut self,
        next_generation: u64,
    ) -> Result<(), ModelSchedulerError> {
        if next_generation < self.active_authority_generation {
            return Err(ModelSchedulerError::AuthorityGenerationRegression {
                current: self.active_authority_generation,
                requested: next_generation,
            });
        }
        self.active_authority_generation = next_generation;
        Ok(())
    }

    /// Quarantine a model generation after an observed panic/fault so future requests fail closed.
    pub fn quarantine_model(&mut self, model_generation: ContentDigest) {
        self.quarantined_models.insert(model_generation);
    }

    /// Export a pure state snapshot for independent oracle verification.
    #[must_use]
    pub fn snapshot(&self) -> SchedulerStateSnapshot {
        SchedulerStateSnapshot {
            active_authority_generation: self.active_authority_generation,
            effective_thermal_state: self.effective_thermal_state,
            thermal_entered_at: self.thermal_entered_at,
            window_started_at: self.window_started_at,
            window_invocations_used: self.window_invocations_used,
            critical_floor_invocations_used: self.critical_floor_invocations_used,
            active_jobs: self.active_jobs.values().cloned().collect(),
            quarantined_models: self.quarantined_models.clone(),
        }
    }

    /// Evaluate and commit one bounded scheduling decision, returning a sealed `FSSMMS01` receipt.
    pub fn admit(
        &mut self,
        sample: &SchedulerPressureSample,
        request: &ModelWorkRequest,
        cx: &ScalarExecCx,
    ) -> Result<ModelSchedulerReceipt, ModelSchedulerError> {
        sample.validate()?;
        request.validate()?;
        if sample.timestamp.0 < self.last_timestamp.0 {
            return Err(ModelSchedulerError::TimestampRegression {
                previous: self.last_timestamp,
                observed: sample.timestamp,
            });
        }

        let req_fp = request.semantic_fingerprint();
        if let Some((prior_fp, prior_receipt)) = self.idempotent_receipts.get(&request.request_id) {
            if *prior_fp == req_fp {
                return Ok(prior_receipt.clone());
            }
            return Err(ModelSchedulerError::DuplicateRequestConflict {
                request_id: request.request_id.clone(),
            });
        }
        if self.idempotent_receipts.len() >= MAX_SCHEDULER_IDEMPOTENCY_ENTRIES {
            return Err(ModelSchedulerError::IdempotencyCacheFull {
                capacity: MAX_SCHEDULER_IDEMPOTENCY_ENTRIES,
            });
        }

        let cx_cancelled = cx.checkpoint("model-scheduler:admit").is_err();

        // Commit monotonic clock, thermal hysteresis state, and window rotation.
        let (next_thermal, next_entered_at) = self.policy.thermal_hysteresis.next_state(
            self.effective_thermal_state,
            self.thermal_entered_at,
            sample.timestamp,
            sample.cpu_temp_mc,
        );
        self.last_timestamp = sample.timestamp;
        self.effective_thermal_state = next_thermal;
        self.thermal_entered_at = next_entered_at;

        if sample.timestamp.0.saturating_sub(self.window_started_at.0) >= self.policy.window_ns {
            self.window_started_at = sample.timestamp;
            self.window_invocations_used = 0;
            self.critical_floor_invocations_used = 0;
        }

        // Independent stateful admission path (never delegates to `oracle_evaluate_admission`).
        let (
            decision_state,
            degradation_reason,
            granted_threads,
            hard_floor_protected,
            preempted_work,
        ) = self.evaluate_and_apply_stateful(sample, request, next_thermal, cx_cancelled);

        let recovery_guidance = build_recovery_guidance(
            decision_state,
            degradation_reason,
            next_thermal,
            granted_threads,
        );

        let mut receipt = ModelSchedulerReceipt {
            format_version: MODEL_SCHEDULER_WIRE_VERSION,
            request_id: request.request_id.clone(),
            workload_class: request.workload_class,
            contract_basis_digest: self.policy.contract_basis_digest,
            policy_digest: self.policy_digest,
            model_generation_digest: request.model_generation_digest,
            kernel_generation_digest: request.kernel_generation_digest,
            authority_generation: self.active_authority_generation,
            timestamp: sample.timestamp,
            effective_thermal_state: next_thermal,
            resource_pressure: sample.resource_pressure,
            decision_state,
            degradation_reason,
            requested_threads: request.requested_threads.get(),
            granted_threads,
            hard_floor_protected,
            preempted_work,
            active_threads_after: self.active_threads(),
            active_memory_bytes_after: self.active_memory_bytes(),
            window_invocations_used: self.window_invocations_used,
            critical_floor_invocations_used: self.critical_floor_invocations_used,
            recovery_guidance,
            receipt_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
        };
        receipt.receipt_digest = receipt.recompute_digest();
        receipt.verify_integrity()?;

        if receipt.decision_state.is_admitted() {
            self.idempotent_receipts
                .insert(request.request_id.clone(), (req_fp, receipt.clone()));
        }
        Ok(receipt)
    }

    fn evaluate_and_apply_stateful(
        &mut self,
        sample: &SchedulerPressureSample,
        request: &ModelWorkRequest,
        thermal: ThermalState,
        cx_cancelled: bool,
    ) -> (
        SchedulerDecisionState,
        SchedulerDegradationReason,
        usize,
        bool,
        Vec<PreemptedWorkRecord>,
    ) {
        if cx_cancelled || request.cancelled_before_admit {
            return (
                SchedulerDecisionState::Cancelled,
                SchedulerDegradationReason::CooperativeCancellation,
                0,
                false,
                Vec::new(),
            );
        }
        if request.required_authority_generation != self.active_authority_generation {
            return (
                SchedulerDecisionState::RefusedQuarantinedOrStale,
                SchedulerDegradationReason::AuthorityGenerationStale,
                0,
                false,
                Vec::new(),
            );
        }
        if request.quarantined_model
            || self
                .quarantined_models
                .contains(&request.model_generation_digest)
        {
            return (
                SchedulerDecisionState::RefusedQuarantinedOrStale,
                SchedulerDegradationReason::ModelGenerationQuarantined,
                0,
                false,
                Vec::new(),
            );
        }

        match request.workload_class {
            ModelWorkloadClass::CriticalSafetyDetector => {
                self.admit_critical_stateful(sample, request, thermal)
            }
            ModelWorkloadClass::StandardAnalytics | ModelWorkloadClass::BackgroundEnrichment => {
                self.admit_non_critical_stateful(sample, request, thermal)
            }
        }
    }

    fn admit_non_critical_stateful(
        &mut self,
        sample: &SchedulerPressureSample,
        request: &ModelWorkRequest,
        thermal: ThermalState,
    ) -> (
        SchedulerDecisionState,
        SchedulerDegradationReason,
        usize,
        bool,
        Vec<PreemptedWorkRecord>,
    ) {
        if thermal == ThermalState::Critical {
            return (
                SchedulerDecisionState::DeferredByPressure,
                SchedulerDegradationReason::ThermalCriticalHardFloorOnly,
                0,
                false,
                Vec::new(),
            );
        }
        if sample.resource_pressure == ResourcePressure::Critical {
            return (
                SchedulerDecisionState::DeferredByPressure,
                SchedulerDegradationReason::ResourcePressureCriticalHardFloorOnly,
                0,
                false,
                Vec::new(),
            );
        }
        if thermal == ThermalState::Hot {
            return (
                SchedulerDecisionState::DeferredByPressure,
                SchedulerDegradationReason::ThermalHotShedLowerClasses,
                0,
                false,
                Vec::new(),
            );
        }
        if sample.resource_pressure == ResourcePressure::Constrained {
            return (
                SchedulerDecisionState::DeferredByPressure,
                SchedulerDegradationReason::ResourcePressureConstrained,
                0,
                false,
                Vec::new(),
            );
        }
        if request.workload_class == ModelWorkloadClass::BackgroundEnrichment {
            if thermal == ThermalState::Warm {
                return (
                    SchedulerDecisionState::DeferredByPressure,
                    SchedulerDegradationReason::ThermalWarmThrottle,
                    0,
                    false,
                    Vec::new(),
                );
            }
            if sample.resource_pressure == ResourcePressure::Elevated {
                return (
                    SchedulerDecisionState::DeferredByPressure,
                    SchedulerDegradationReason::ResourcePressureElevated,
                    0,
                    false,
                    Vec::new(),
                );
            }
            if sample.is_power_capped() {
                return (
                    SchedulerDecisionState::DeferredByPressure,
                    SchedulerDegradationReason::PowerCapThrottle,
                    0,
                    false,
                    Vec::new(),
                );
            }
        }

        let class_cap = if request.workload_class == ModelWorkloadClass::StandardAnalytics {
            self.policy.standard_max_memory_bytes
        } else {
            self.policy.background_max_memory_bytes
        };
        if request.estimated_memory_bytes > class_cap {
            return (
                SchedulerDecisionState::RefusedBudgetOrCapacity,
                SchedulerDegradationReason::ConcurrencyCeilingReached,
                0,
                false,
                Vec::new(),
            );
        }

        let reserved_critical_slots = self
            .policy
            .critical_min_invocations_per_window
            .saturating_sub(self.critical_floor_invocations_used);
        let non_critical_window_limit = self
            .policy
            .max_window_invocations_total
            .saturating_sub(reserved_critical_slots);
        if self.window_invocations_used >= non_critical_window_limit {
            return (
                SchedulerDecisionState::RefusedBudgetOrCapacity,
                SchedulerDegradationReason::WindowQuotaExhausted,
                0,
                false,
                Vec::new(),
            );
        }

        let live_mem = sample.memory_used_bytes.max(self.active_memory_bytes());
        let allowed_mem = sample
            .memory_limit_bytes
            .saturating_sub(self.policy.critical_reserved_memory_bytes);
        if live_mem.saturating_add(request.estimated_memory_bytes) > allowed_mem {
            return (
                SchedulerDecisionState::DeferredByPressure,
                SchedulerDegradationReason::MemoryHeadroomReservedForCriticalFloor,
                0,
                false,
                Vec::new(),
            );
        }

        let pool_cap = if thermal >= ThermalState::Warm
            || sample.resource_pressure >= ResourcePressure::Elevated
            || sample.is_power_capped()
        {
            self.policy
                .max_total_threads
                .get()
                .saturating_sub(self.policy.critical_min_threads.get())
        } else {
            self.policy.max_total_threads.get()
        };
        let free_threads = pool_cap.saturating_sub(self.active_threads());
        if self.active_jobs.len() >= self.policy.max_active_invocations || free_threads == 0 {
            return (
                SchedulerDecisionState::RefusedBudgetOrCapacity,
                SchedulerDegradationReason::ConcurrencyCeilingReached,
                0,
                false,
                Vec::new(),
            );
        }

        let mut granted = request.requested_threads.get().min(free_threads);
        let mut reason = SchedulerDegradationReason::None;
        if thermal == ThermalState::Warm {
            granted = granted.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::ThermalWarmThrottle;
        } else if sample.resource_pressure == ResourcePressure::Elevated {
            granted = granted.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::ResourcePressureElevated;
        } else if sample.is_power_capped() {
            granted = granted.min((request.requested_threads.get() / 2).max(1));
            reason = SchedulerDegradationReason::PowerCapThrottle;
        }

        let state = if granted < request.requested_threads.get() {
            if reason == SchedulerDegradationReason::None {
                reason = SchedulerDegradationReason::ConcurrencyCeilingReached;
            }
            SchedulerDecisionState::AdmittedDegradedThreads
        } else {
            SchedulerDecisionState::AdmittedFull
        };

        self.active_jobs.insert(
            request.request_id.clone(),
            ActiveScheduledWork {
                request_id: request.request_id.clone(),
                workload_class: request.workload_class,
                granted_threads: granted,
                reserved_memory_bytes: request.estimated_memory_bytes,
                model_generation_digest: request.model_generation_digest,
                admitted_at: sample.timestamp,
            },
        );
        self.window_invocations_used = self.window_invocations_used.saturating_add(1);
        (state, reason, granted, false, Vec::new())
    }

    fn admit_critical_stateful(
        &mut self,
        sample: &SchedulerPressureSample,
        request: &ModelWorkRequest,
        thermal: ThermalState,
    ) -> (
        SchedulerDecisionState,
        SchedulerDegradationReason,
        usize,
        bool,
        Vec<PreemptedWorkRecord>,
    ) {
        let floor_quota_active =
            self.critical_floor_invocations_used < self.policy.critical_min_invocations_per_window;
        if !floor_quota_active
            && self.window_invocations_used >= self.policy.max_window_invocations_total
        {
            return (
                SchedulerDecisionState::RefusedBudgetOrCapacity,
                SchedulerDegradationReason::WindowQuotaExhausted,
                0,
                false,
                Vec::new(),
            );
        }

        let under_critical = thermal == ThermalState::Critical
            || sample.resource_pressure == ResourcePressure::Critical;
        let floor_threads = request
            .requested_threads
            .get()
            .min(self.policy.critical_min_threads.get())
            .max(1);
        let desired_threads = if under_critical {
            floor_threads
        } else if thermal == ThermalState::Hot
            || sample.resource_pressure == ResourcePressure::Constrained
        {
            (request.requested_threads.get() / 2)
                .max(floor_threads)
                .min(request.requested_threads.get())
        } else {
            request
                .requested_threads
                .get()
                .min(self.policy.max_total_threads.get())
        };

        let active_mem = self.active_memory_bytes();
        let external_mem = sample.memory_used_bytes.saturating_sub(active_mem);

        // Select canonical preemption candidates ONLY if lower-priority jobs block the hard floor.
        let mut plan_threads = self.active_threads();
        let mut plan_mem = active_mem;
        let mut plan_count = self.active_jobs.len();
        let mut victim_ids = Vec::new();

        let blocked = |t: usize, m: u64, c: usize| -> bool {
            let free_t = self.policy.max_total_threads.get().saturating_sub(t);
            let proj_m = external_mem
                .saturating_add(m)
                .saturating_add(request.estimated_memory_bytes);
            free_t < floor_threads
                || c >= self.policy.max_active_invocations
                || proj_m > sample.memory_limit_bytes
        };

        if blocked(plan_threads, plan_mem, plan_count) {
            let mut candidates: Vec<(ModelWorkloadClass, String, usize, u64)> = self
                .active_jobs
                .values()
                .filter(|j| !j.workload_class.is_critical())
                .map(|j| {
                    (
                        j.workload_class,
                        j.request_id.clone(),
                        j.granted_threads,
                        j.reserved_memory_bytes,
                    )
                })
                .collect();
            candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            for (_, id, t, m) in candidates {
                if !blocked(plan_threads, plan_mem, plan_count) {
                    break;
                }
                victim_ids.push(id);
                plan_threads = plan_threads.saturating_sub(t);
                plan_mem = plan_mem.saturating_sub(m);
                plan_count = plan_count.saturating_sub(1);
            }
        }

        // Refuse cleanly BEFORE mutating active_jobs if even full preemption cannot fit the floor!
        if blocked(plan_threads, plan_mem, plan_count) {
            return (
                SchedulerDecisionState::RefusedBudgetOrCapacity,
                SchedulerDegradationReason::ConcurrencyCeilingReached,
                0,
                false,
                Vec::new(),
            );
        }

        let mut preempted_work = Vec::with_capacity(victim_ids.len());
        for vid in &victim_ids {
            if let Some(removed) = self.active_jobs.remove(vid) {
                preempted_work.push(PreemptedWorkRecord {
                    request_id: removed.request_id,
                    workload_class: removed.workload_class,
                    reclaimed_threads: removed.granted_threads,
                    reclaimed_memory_bytes: removed.reserved_memory_bytes,
                });
            }
        }

        let free_threads = self
            .policy
            .max_total_threads
            .get()
            .saturating_sub(self.active_threads());
        let granted = desired_threads.min(free_threads).max(floor_threads);
        let hard_floor_protected =
            under_critical || !preempted_work.is_empty() || floor_quota_active;

        let (state, reason) = if under_critical {
            (
                SchedulerDecisionState::AdmittedViaHardFloor,
                if thermal == ThermalState::Critical {
                    SchedulerDegradationReason::ThermalCriticalHardFloorOnly
                } else {
                    SchedulerDegradationReason::ResourcePressureCriticalHardFloorOnly
                },
            )
        } else if !preempted_work.is_empty() {
            (
                SchedulerDecisionState::AdmittedViaHardFloor,
                if thermal == ThermalState::Hot {
                    SchedulerDegradationReason::ThermalHotShedLowerClasses
                } else if sample.resource_pressure == ResourcePressure::Constrained {
                    SchedulerDegradationReason::ResourcePressureConstrained
                } else {
                    SchedulerDegradationReason::ConcurrencyCeilingReached
                },
            )
        } else if granted < request.requested_threads.get() {
            let r = if thermal == ThermalState::Hot {
                SchedulerDegradationReason::ThermalHotShedLowerClasses
            } else if sample.resource_pressure == ResourcePressure::Constrained {
                SchedulerDegradationReason::ResourcePressureConstrained
            } else if thermal == ThermalState::Warm {
                SchedulerDegradationReason::ThermalWarmThrottle
            } else if sample.resource_pressure == ResourcePressure::Elevated {
                SchedulerDegradationReason::ResourcePressureElevated
            } else if sample.is_power_capped() {
                SchedulerDegradationReason::PowerCapThrottle
            } else {
                SchedulerDegradationReason::ConcurrencyCeilingReached
            };
            (SchedulerDecisionState::AdmittedDegradedThreads, r)
        } else {
            (
                SchedulerDecisionState::AdmittedFull,
                SchedulerDegradationReason::None,
            )
        };

        self.active_jobs.insert(
            request.request_id.clone(),
            ActiveScheduledWork {
                request_id: request.request_id.clone(),
                workload_class: request.workload_class,
                granted_threads: granted,
                reserved_memory_bytes: request.estimated_memory_bytes,
                model_generation_digest: request.model_generation_digest,
                admitted_at: sample.timestamp,
            },
        );
        self.window_invocations_used = self.window_invocations_used.saturating_add(1);
        self.critical_floor_invocations_used =
            self.critical_floor_invocations_used.saturating_add(1);
        (state, reason, granted, hard_floor_protected, preempted_work)
    }

    /// Mark an active admitted invocation completed and release its threads and memory cleanly.
    pub fn complete(
        &mut self,
        request_id: &str,
    ) -> Result<ActiveScheduledWork, ModelSchedulerError> {
        self.active_jobs.remove(request_id).ok_or_else(|| {
            ModelSchedulerError::UnknownActiveRequest {
                request_id: request_id.to_owned(),
            }
        })
    }
}

const fn resource_pressure_tag(pressure: ResourcePressure) -> u8 {
    match pressure {
        ResourcePressure::Nominal => 0,
        ResourcePressure::Elevated => 1,
        ResourcePressure::Constrained => 2,
        ResourcePressure::Critical => 3,
    }
}

fn resource_pressure_from_tag(tag: u8) -> Result<ResourcePressure, ModelSchedulerError> {
    match tag {
        0 => Ok(ResourcePressure::Nominal),
        1 => Ok(ResourcePressure::Elevated),
        2 => Ok(ResourcePressure::Constrained),
        3 => Ok(ResourcePressure::Critical),
        other => Err(ModelSchedulerError::MalformedWire(format!(
            "unknown ResourcePressure tag {other}"
        ))),
    }
}

fn build_recovery_guidance(
    decision: SchedulerDecisionState,
    reason: SchedulerDegradationReason,
    thermal: ThermalState,
    granted_threads: usize,
) -> String {
    match decision {
        SchedulerDecisionState::AdmittedFull => {
            format!("proceed with {granted_threads} threads; release reservation upon completion")
        }
        SchedulerDecisionState::AdmittedDegradedThreads => format!(
            "proceed with degraded {granted_threads} threads ({}; thermal={}); outputs remain bit-exact",
            reason.as_str(),
            thermal.as_str()
        ),
        SchedulerDecisionState::AdmittedViaHardFloor => format!(
            "critical hard-floor admission with {granted_threads} threads ({}; thermal={}); shed lower classes until cool-down",
            reason.as_str(),
            thermal.as_str()
        ),
        SchedulerDecisionState::DeferredByPressure => format!(
            "retry after thermal/resource pressure subsides ({}; thermal={}); do not promote deferral to negative evidence",
            reason.as_str(),
            thermal.as_str()
        ),
        SchedulerDecisionState::RefusedBudgetOrCapacity => format!(
            "retry in next quota window or after active work completes ({})",
            reason.as_str()
        ),
        SchedulerDecisionState::RefusedQuarantinedOrStale => format!(
            "refresh authority generation or roll back quarantined model generation ({})",
            reason.as_str()
        ),
        SchedulerDecisionState::Cancelled => {
            "cancelled prior to admission; zero resources reserved; safe to abandon or re-plan"
                .to_owned()
        }
    }
}
