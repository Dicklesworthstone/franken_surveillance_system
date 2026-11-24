#![forbid(unsafe_code)]
//! Per-camera fair-share budget scheduler and priority queue (`FairShareScheduler`).
//!
//! Enforces shared epoch budgets across `fss_core::BudgetVector`, work units, MACs, and memory
//! while guaranteeing anti-starvation fairness:
//! 1. **Pass 1 (Guaranteed Fair-Share Floor):** Every participating camera receives up to its
//!    `min_guaranteed_frames_per_epoch` slots first in `(priority, stream_order, sensor_id)`
//!    order, prioritizing sentinel sweeps within each camera's floor.
//! 2. **Pass 2 (Priority-Weighted Burst Round-Robin):** Remaining epoch capacity is allocated
//!    across priority tiers (`ActiveInvestigation` → `HighConsequenceZone` → `CorroboratedTrack`
//!    → `Standard`) round-robin up to `max_burst_frames_per_epoch`.
//! 3. **Pass 3 (Explicit Decline Accounting):** Every unadmitted candidate emits a canonical
//!    [`MarginalWorkDeclinedReceipt`] with [`DeclineReason`] and [`ResourcePressure`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, ResourcePressure as CoreResourcePressure,
    SensorId,
};

use super::ModelPoolError;
use super::receipt::{MarginalWorkDeclinedReceipt, StageDecision};

/// Priority tier assigned to a camera stream for fair-share budget arbitration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CameraPriorityTier {
    /// Camera participating in an active investigation case (highest priority).
    ActiveInvestigation = 0,
    /// Camera covering a high-consequence perimeter or entry zone.
    HighConsequenceZone = 1,
    /// Camera contributing to a corroborated multi-sensor track.
    CorroboratedTrack = 2,
    /// Standard background monitoring stream.
    Standard = 3,
}

impl CameraPriorityTier {
    /// Stable lowercase schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveInvestigation => "active_investigation",
            Self::HighConsequenceZone => "high_consequence_zone",
            Self::CorroboratedTrack => "corroborated_track",
            Self::Standard => "standard",
        }
    }

    /// Numeric priority rank (`0` is highest priority).
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl CanonicalEncode for CameraPriorityTier {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(self.rank());
        e.text(self.as_str());
    }
}

/// Coarse pool resource-pressure level used to make budget throttling explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ResourcePressure {
    /// Utilization below 50% across all tracked dimensions.
    Normal = 0,
    /// Utilization in `[50%, 80%)` on at least one dimension.
    Elevated = 1,
    /// Utilization in `[80%, 95%)` on at least one dimension.
    High = 2,
    /// Utilization at or above 95% or at least one dimension exhausted.
    Critical = 3,
}

impl ResourcePressure {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Maps pool pressure onto the canonical `fss_core::ResourcePressure` scale.
    #[must_use]
    pub const fn to_core_pressure(self) -> CoreResourcePressure {
        match self {
            Self::Normal => CoreResourcePressure::Nominal,
            Self::Elevated => CoreResourcePressure::Elevated,
            Self::High => CoreResourcePressure::Constrained,
            Self::Critical => CoreResourcePressure::Critical,
        }
    }

    /// Classifies integer utilization parts-per-million (`0..=1_000_000+`).
    #[must_use]
    pub const fn from_utilization_ppm(ppm: u32) -> Self {
        if ppm >= 950_000 {
            Self::Critical
        } else if ppm >= 800_000 {
            Self::High
        } else if ppm >= 500_000 {
            Self::Elevated
        } else {
            Self::Normal
        }
    }
}

impl CanonicalEncode for ResourcePressure {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(*self as u8);
        e.text(self.as_str());
    }
}

/// Exact budget dimension that caused a candidate Stage-2 inference to be declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DeclineReason {
    /// Shared epoch work-unit budget was exhausted.
    PoolBudgetExhausted = 0,
    /// Per-camera `max_burst_frames_per_epoch` ceiling prevented further burst admission.
    CameraBurstCapReached = 1,
    /// Shared `BudgetVector::model_calls` limit was exhausted.
    ModelCallsExhausted = 2,
    /// Shared epoch MAC budget was exhausted.
    MacBudgetExhausted = 3,
    /// Shared pool scratch/working memory ceiling was exceeded.
    MemoryBudgetExhausted = 4,
}

impl DeclineReason {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PoolBudgetExhausted => "pool_budget_exhausted",
            Self::CameraBurstCapReached => "camera_burst_cap_reached",
            Self::ModelCallsExhausted => "model_calls_exhausted",
            Self::MacBudgetExhausted => "mac_budget_exhausted",
            Self::MemoryBudgetExhausted => "memory_budget_exhausted",
        }
    }

    /// Compact canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

impl CanonicalEncode for DeclineReason {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(self.tag());
        e.text(self.as_str());
    }
}

/// Per-camera priority and fair-share admission quotas within one scheduling epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CameraQuotaConfig {
    /// Priority tier for burst arbitration after guaranteed fair-share floors are satisfied.
    pub priority: CameraPriorityTier,
    /// Minimum guaranteed Stage-2 inference slots reserved for this camera per epoch.
    pub min_guaranteed_frames_per_epoch: u32,
    /// Maximum Stage-2 inference slots this camera may consume in one epoch (anti-flood cap).
    pub max_burst_frames_per_epoch: u32,
}

impl Default for CameraQuotaConfig {
    fn default() -> Self {
        Self {
            priority: CameraPriorityTier::Standard,
            min_guaranteed_frames_per_epoch: 1,
            max_burst_frames_per_epoch: 8,
        }
    }
}

impl CameraQuotaConfig {
    /// Validates `0 < max_burst_frames_per_epoch` and `min_guaranteed <= max_burst`.
    pub fn validate(self) -> Result<(), ModelPoolError> {
        if self.max_burst_frames_per_epoch == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "max_burst_frames_per_epoch must be positive",
            ));
        }
        if self.min_guaranteed_frames_per_epoch > self.max_burst_frames_per_epoch {
            return Err(ModelPoolError::InvalidConfig(
                "min_guaranteed_frames_per_epoch cannot exceed max_burst_frames_per_epoch",
            ));
        }
        Ok(())
    }
}

/// Complete bounded resource budget configuration for one inference pool epoch.
#[derive(Clone, Debug, PartialEq)]
pub struct PoolBudgetConfig {
    /// Multi-dimensional `fss_core::BudgetVector` ceiling (`model_calls`, `bytes`, etc.).
    pub budget_vector: BudgetVector,
    /// Maximum logical Stage-2 work units permitted in one epoch.
    pub max_work_units_per_epoch: u64,
    /// Maximum Stage-2 multiply-accumulate operations permitted in one epoch.
    pub max_macs_per_epoch: u64,
    /// Maximum cumulative working-memory bytes admitted for one epoch.
    pub max_memory_bytes: usize,
    /// Estimated logical work units per Stage-2 inference for deterministic pre-admission.
    pub estimated_work_units_per_inference: u64,
    /// Estimated MACs per Stage-2 inference for deterministic pre-admission.
    pub estimated_macs_per_inference: u64,
    /// Estimated transient scratch bytes per Stage-2 inference.
    pub estimated_bytes_per_inference: usize,
    /// Default per-camera quota applied to streams without an explicit override.
    pub default_camera_quota: CameraQuotaConfig,
    /// Per-camera quota overrides indexed by [`SensorId`].
    pub camera_overrides: BTreeMap<SensorId, CameraQuotaConfig>,
}

impl Default for PoolBudgetConfig {
    fn default() -> Self {
        let budget_vector = BudgetVector::builder()
            .model_calls(256)
            .bytes(64 * 1024 * 1024)
            .cpu_millis(10_000)
            .build()
            .unwrap_or(BudgetVector::ZERO);
        Self {
            budget_vector,
            max_work_units_per_epoch: 100_000_000,
            max_macs_per_epoch: 10_000_000_000,
            max_memory_bytes: 256 * 1024 * 1024,
            estimated_work_units_per_inference: 40_000,
            estimated_macs_per_inference: 4_096,
            estimated_bytes_per_inference: 65_536,
            default_camera_quota: CameraQuotaConfig::default(),
            camera_overrides: BTreeMap::new(),
        }
    }
}

impl PoolBudgetConfig {
    /// Validates all budget dimensions and camera quota bounds before scheduling.
    pub fn validate(&self) -> Result<(), ModelPoolError> {
        self.budget_vector.validate()?;
        if self.max_work_units_per_epoch == 0
            || self.max_macs_per_epoch == 0
            || self.max_memory_bytes == 0
            || self.estimated_work_units_per_inference == 0
        {
            return Err(ModelPoolError::InvalidConfig(
                "epoch budget limits and work estimate must be positive",
            ));
        }
        self.default_camera_quota.validate()?;
        for quota in self.camera_overrides.values() {
            quota.validate()?;
        }
        Ok(())
    }

    /// Resolves the effective [`CameraQuotaConfig`] for a specific sensor.
    #[must_use]
    pub fn quota_for(&self, sensor_id: &SensorId) -> CameraQuotaConfig {
        self.camera_overrides
            .get(sensor_id)
            .copied()
            .unwrap_or(self.default_camera_quota)
    }
}

/// One Stage-1-selected frame competing for Stage-2 ML budget admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledCandidate {
    /// Index of this candidate in the caller's canonical frame array.
    pub canonical_index: usize,
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Priority tier assigned to this stream.
    pub priority: CameraPriorityTier,
    /// Stage-1 trigger reason (`MotionTriggered` or `SentinelSweep`).
    pub stage_decision: StageDecision,
    /// Requested logical work units for Stage-2 inference.
    pub requested_work_units: u64,
    /// Requested MAC allowance for Stage-2 inference.
    pub requested_macs: u64,
    /// Requested transient memory bytes for Stage-2 inference.
    pub requested_bytes: usize,
}

/// Complete deterministic outcome of one fair-share budget arbitration pass.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochScheduleOutcome {
    /// Admitted `canonical_index` entries sorted strictly in ascending canonical order.
    pub admitted_indices: Vec<usize>,
    /// Declined candidates keyed by `canonical_index`.
    pub declined: BTreeMap<usize, MarginalWorkDeclinedReceipt>,
    /// Total logical work units reserved by admitted candidates.
    pub work_units_reserved: u64,
    /// Total MACs reserved by admitted candidates.
    pub macs_reserved: u64,
    /// Total `BudgetVector::model_calls` reserved.
    pub model_calls_reserved: u32,
    /// Total transient byte budget reserved.
    pub memory_bytes_reserved: usize,
    /// Peak epoch resource pressure level.
    pub pressure: ResourcePressure,
}

/// Deterministic two-pass fair-share budget scheduler preventing noisy-camera starvation.
#[derive(Clone, Debug)]
pub struct FairShareScheduler {
    config: PoolBudgetConfig,
}

impl FairShareScheduler {
    /// Validates configuration and constructs a new scheduler.
    pub fn new(config: PoolBudgetConfig) -> Result<Self, ModelPoolError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Returns the immutable budget configuration.
    #[must_use]
    pub const fn config(&self) -> &PoolBudgetConfig {
        &self.config
    }

    /// Arbitrates Stage-2 ML admission across all candidate frames in one epoch.
    pub fn schedule_epoch(
        &self,
        candidates: &[ScheduledCandidate],
    ) -> Result<EpochScheduleOutcome, ModelPoolError> {
        let mut by_camera: BTreeMap<(u8, u32, SensorId), Vec<&ScheduledCandidate>> =
            BTreeMap::new();
        for cand in candidates {
            let quota = self.config.quota_for(&cand.sensor_id);
            let effective_priority = cand.priority.min(quota.priority);
            by_camera
                .entry((
                    effective_priority.rank(),
                    cand.stream_order,
                    cand.sensor_id.clone(),
                ))
                .or_default()
                .push(cand);
        }
        for queue in by_camera.values_mut() {
            queue.sort_by(|a, b| {
                u8::from(a.stage_decision != StageDecision::SentinelSweep)
                    .cmp(&u8::from(b.stage_decision != StageDecision::SentinelSweep))
                    .then_with(|| a.frame_sequence.cmp(&b.frame_sequence))
                    .then_with(|| a.canonical_index.cmp(&b.canonical_index))
            });
        }

        let mut ledger = BudgetLedger::new(&self.config);
        let mut admitted_set: BTreeSet<usize> = BTreeSet::new();
        let mut admitted_per_camera: BTreeMap<SensorId, u32> = BTreeMap::new();
        let mut next_cursor: BTreeMap<(u8, u32, SensorId), usize> = BTreeMap::new();

        // Pass 1: Guaranteed fair-share floor round-robin across all participating cameras.
        let max_guarantee = by_camera
            .keys()
            .map(|(_, _, sensor)| {
                self.config
                    .quota_for(sensor)
                    .min_guaranteed_frames_per_epoch
            })
            .max()
            .unwrap_or(0);
        for round in 0..max_guarantee {
            for (cam_key, queue) in &by_camera {
                if round
                    >= self
                        .config
                        .quota_for(&cam_key.2)
                        .min_guaranteed_frames_per_epoch
                {
                    continue;
                }
                let cursor = next_cursor.entry(cam_key.clone()).or_insert(0);
                if *cursor < queue.len() && ledger.try_reserve(queue[*cursor]).is_ok() {
                    admitted_set.insert(queue[*cursor].canonical_index);
                    *admitted_per_camera.entry(cam_key.2.clone()).or_insert(0) += 1;
                    *cursor += 1;
                }
            }
        }

        // Pass 2: Priority-ordered round-robin burst allocation up to max_burst_frames_per_epoch.
        loop {
            let mut progress = false;
            for (cam_key, queue) in &by_camera {
                let cap = self.config.quota_for(&cam_key.2).max_burst_frames_per_epoch;
                let count = admitted_per_camera.get(&cam_key.2).copied().unwrap_or(0);
                if count >= cap {
                    continue;
                }
                let cursor = next_cursor.entry(cam_key.clone()).or_insert(0);
                if *cursor < queue.len() && ledger.try_reserve(queue[*cursor]).is_ok() {
                    admitted_set.insert(queue[*cursor].canonical_index);
                    *admitted_per_camera.entry(cam_key.2.clone()).or_insert(0) += 1;
                    *cursor += 1;
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }

        // Pass 3: Canonical decline receipts for every candidate not admitted in Pass 1 or Pass 2.
        let mut declined = BTreeMap::new();
        let mut remaining: Vec<&ScheduledCandidate> = candidates
            .iter()
            .filter(|c| !admitted_set.contains(&c.canonical_index))
            .collect();
        remaining.sort_by(|a, b| {
            a.stream_order
                .cmp(&b.stream_order)
                .then_with(|| a.frame_sequence.cmp(&b.frame_sequence))
                .then_with(|| a.sensor_id.cmp(&b.sensor_id))
        });

        let mut peak_pressure = ledger.pressure();
        for cand in remaining {
            let quota = self.config.quota_for(&cand.sensor_id);
            let cam_count = admitted_per_camera
                .get(&cand.sensor_id)
                .copied()
                .unwrap_or(0);
            let decline_reason = if cam_count >= quota.max_burst_frames_per_epoch {
                DeclineReason::CameraBurstCapReached
            } else {
                ledger
                    .first_blocking_reason(cand)
                    .unwrap_or(DeclineReason::PoolBudgetExhausted)
            };
            let decline_pressure = match decline_reason {
                DeclineReason::CameraBurstCapReached => {
                    ledger.pressure().max(ResourcePressure::Elevated)
                }
                DeclineReason::PoolBudgetExhausted
                | DeclineReason::ModelCallsExhausted
                | DeclineReason::MacBudgetExhausted
                | DeclineReason::MemoryBudgetExhausted => ResourcePressure::Critical,
            };
            peak_pressure = peak_pressure.max(decline_pressure);
            declined.insert(
                cand.canonical_index,
                MarginalWorkDeclinedReceipt::seal(
                    cand.stream_order,
                    cand.frame_sequence,
                    cand.sensor_id.clone(),
                    cand.priority,
                    cand.requested_work_units,
                    ledger.remaining_work_units(),
                    decline_pressure,
                    decline_reason,
                ),
            );
        }

        Ok(EpochScheduleOutcome {
            admitted_indices: admitted_set.into_iter().collect(),
            declined,
            work_units_reserved: ledger.work_units_used,
            macs_reserved: ledger.macs_used,
            model_calls_reserved: ledger.model_calls_used,
            memory_bytes_reserved: ledger.memory_bytes_used,
            pressure: peak_pressure,
        })
    }
}

struct BudgetLedger {
    max_work_units: u64,
    max_macs: u64,
    max_model_calls: u32,
    max_memory_bytes: usize,
    max_budget_bytes: u64,
    work_units_used: u64,
    macs_used: u64,
    model_calls_used: u32,
    memory_bytes_used: usize,
}

impl BudgetLedger {
    fn new(config: &PoolBudgetConfig) -> Self {
        Self {
            max_work_units: config.max_work_units_per_epoch,
            max_macs: config.max_macs_per_epoch,
            max_model_calls: config.budget_vector.model_calls,
            max_memory_bytes: config.max_memory_bytes,
            max_budget_bytes: config.budget_vector.bytes,
            work_units_used: 0,
            macs_used: 0,
            model_calls_used: 0,
            memory_bytes_used: 0,
        }
    }

    fn remaining_work_units(&self) -> u64 {
        self.max_work_units.saturating_sub(self.work_units_used)
    }

    fn first_blocking_reason(&self, cand: &ScheduledCandidate) -> Option<DeclineReason> {
        if self
            .model_calls_used
            .checked_add(1)
            .is_none_or(|n| n > self.max_model_calls)
        {
            return Some(DeclineReason::ModelCallsExhausted);
        }
        if self
            .work_units_used
            .checked_add(cand.requested_work_units)
            .is_none_or(|n| n > self.max_work_units)
        {
            return Some(DeclineReason::PoolBudgetExhausted);
        }
        if self
            .macs_used
            .checked_add(cand.requested_macs)
            .is_none_or(|n| n > self.max_macs)
        {
            return Some(DeclineReason::MacBudgetExhausted);
        }
        let next_bytes = self.memory_bytes_used.checked_add(cand.requested_bytes);
        if next_bytes.is_none_or(|n| {
            n > self.max_memory_bytes
                || (self.max_budget_bytes > 0 && (n as u64) > self.max_budget_bytes)
        }) {
            return Some(DeclineReason::MemoryBudgetExhausted);
        }
        None
    }

    fn try_reserve(&mut self, cand: &ScheduledCandidate) -> Result<(), DeclineReason> {
        if let Some(reason) = self.first_blocking_reason(cand) {
            return Err(reason);
        }
        self.model_calls_used += 1;
        self.work_units_used += cand.requested_work_units;
        self.macs_used += cand.requested_macs;
        self.memory_bytes_used += cand.requested_bytes;
        Ok(())
    }

    fn pressure(&self) -> ResourcePressure {
        let ratio = |used: u128, max: u128| -> u32 {
            if max == 0 {
                return 1_000_000;
            }
            u32::try_from((used.saturating_mul(1_000_000) / max).min(1_000_000))
                .unwrap_or(1_000_000)
        };
        let max_ppm = ratio(
            u128::from(self.work_units_used),
            u128::from(self.max_work_units),
        )
        .max(ratio(u128::from(self.macs_used), u128::from(self.max_macs)))
        .max(ratio(
            u128::from(self.model_calls_used),
            u128::from(self.max_model_calls),
        ))
        .max(ratio(
            self.memory_bytes_used as u128,
            self.max_memory_bytes as u128,
        ));
        ResourcePressure::from_utilization_ppm(max_ppm)
    }
}
