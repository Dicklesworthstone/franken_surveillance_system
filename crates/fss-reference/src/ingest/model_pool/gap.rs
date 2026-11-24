#![forbid(unsafe_code)]
//! Explicit unsampled gap ledger and marginal-work decline receipts for the multi-stream ML pool.
//!
//! Every frame that does not execute Stage-2 ML inference (whether quiescently skipped, declined
//! under budget pressure, or cancelled) is recorded here with `absence_certifiable = false` so no
//! downstream consumer can ever confuse skipped or throttled work with evidence of absence.

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ResourcePressure as CoreResourcePressure, SensorId,
};

use super::scheduler::{CameraPriorityTier, DeclineReason, ResourcePressure};

/// Canonical digest domain for explicit unsampled frame gap records and ledgers.
pub const UNSAMPLED_GAP_DOMAIN: &str = "fss.model_pool.unsampled_gap.v1";

/// Canonical digest domain for explicit marginal-work decline receipts under budget pressure.
pub const MARGINAL_WORK_DECLINED_DOMAIN: &str = "fss.model_pool.marginal_work_declined.v1";

/// Explicit reason a source frame did not execute Stage-2 ML inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum UnsampledReason {
    /// Non-keyframe skipped while the stream remained quiescent.
    QuiescentNonKeyframe = 0,
    /// Frame declined because epoch, memory, MAC, model-call, or burst quota was exhausted.
    BudgetThrottled = 1,
    /// Quiescent keyframe skipped between periodic sentinel sweep intervals.
    SentinelIntervalSkip = 2,
    /// Optional sensor-health screen flagged visual degradation on this frame.
    SensorHealthDegraded = 3,
    /// Cooperative cancellation stopped execution before Stage-2 ML ran.
    Cancelled = 4,
}

impl UnsampledReason {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuiescentNonKeyframe => "quiescent_non_keyframe",
            Self::BudgetThrottled => "budget_throttled",
            Self::SentinelIntervalSkip => "sentinel_interval_skip",
            Self::SensorHealthDegraded => "sensor_health_degraded",
            Self::Cancelled => "cancelled",
        }
    }

    /// Compact canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

impl CanonicalEncode for UnsampledReason {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(self.tag());
        e.text(self.as_str());
    }
}

/// One explicit record of a frame that bypassed Stage-2 ML inference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsampledGapRecord {
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Conservative source capture interval.
    pub capture_interval: CaptureInterval,
    /// Immutable source payload digest.
    pub source_digest: ContentDigest,
    /// Whether this frame was marked as a codec keyframe.
    pub is_keyframe: bool,
    /// Typed reason ML inference did not execute.
    pub reason: UnsampledReason,
    /// Always `false`: unsampled frames can never certify physical absence.
    pub absence_certifiable: bool,
}

impl UnsampledGapRecord {
    /// Constructs a canonical unsampled gap record with `absence_certifiable = false`.
    #[must_use]
    pub const fn new(
        stream_order: u32,
        frame_sequence: u64,
        sensor_id: SensorId,
        capture_interval: CaptureInterval,
        source_digest: ContentDigest,
        is_keyframe: bool,
        reason: UnsampledReason,
    ) -> Self {
        Self {
            stream_order,
            frame_sequence,
            sensor_id,
            capture_interval,
            source_digest,
            is_keyframe,
            reason,
            absence_certifiable: false,
        }
    }

    /// Domain-separated canonical SHA-256 digest of this unsampled gap record.
    #[must_use]
    pub fn record_digest(&self) -> ContentDigest {
        self.canonical_digest(UNSAMPLED_GAP_DOMAIN)
    }
}

impl CanonicalEncode for UnsampledGapRecord {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u32(self.stream_order);
        e.u64(self.frame_sequence);
        self.sensor_id.encode_canonical(e);
        self.capture_interval.encode_canonical(e);
        e.digest(self.source_digest);
        e.bool(self.is_keyframe);
        self.reason.encode_canonical(e);
        e.bool(self.absence_certifiable);
    }
}

/// Canonical ledger of every frame skipped or budget-declined during an epoch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnsampledGapLedger {
    /// Ordered unsampled records sorted by `(stream_order, frame_sequence, sensor_id)`.
    pub records: Vec<UnsampledGapRecord>,
    /// Count of [`UnsampledReason::QuiescentNonKeyframe`] entries.
    pub quiescent_non_keyframe_count: u64,
    /// Count of [`UnsampledReason::BudgetThrottled`] entries.
    pub budget_throttled_count: u64,
    /// Count of [`UnsampledReason::SentinelIntervalSkip`] entries.
    pub sentinel_interval_skip_count: u64,
    /// Count of [`UnsampledReason::SensorHealthDegraded`] entries.
    pub sensor_health_degraded_count: u64,
    /// Count of [`UnsampledReason::Cancelled`] entries.
    pub cancelled_count: u64,
}

impl UnsampledGapLedger {
    /// Appends one unsampled gap record and increments its typed counter.
    pub fn push(&mut self, record: UnsampledGapRecord) {
        match record.reason {
            UnsampledReason::QuiescentNonKeyframe => self.quiescent_non_keyframe_count += 1,
            UnsampledReason::BudgetThrottled => self.budget_throttled_count += 1,
            UnsampledReason::SentinelIntervalSkip => self.sentinel_interval_skip_count += 1,
            UnsampledReason::SensorHealthDegraded => self.sensor_health_degraded_count += 1,
            UnsampledReason::Cancelled => self.cancelled_count += 1,
        }
        self.records.push(record);
    }

    /// Canonically sorts all entries by `(stream_order, frame_sequence, sensor_id)`.
    pub fn sort_canonical(&mut self) {
        self.records.sort_by(|a, b| {
            a.stream_order
                .cmp(&b.stream_order)
                .then_with(|| a.frame_sequence.cmp(&b.frame_sequence))
                .then_with(|| a.sensor_id.cmp(&b.sensor_id))
        });
    }

    /// Total number of unsampled frames recorded in this ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` when zero unsampled gaps were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Domain-separated canonical SHA-256 digest over the sorted gap ledger.
    #[must_use]
    pub fn ledger_digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(UNSAMPLED_GAP_DOMAIN);
        e.text("ledger");
        e.u64(self.records.len() as u64);
        e.u64(self.quiescent_non_keyframe_count);
        e.u64(self.budget_throttled_count);
        e.u64(self.sentinel_interval_skip_count);
        e.u64(self.sensor_health_degraded_count);
        e.u64(self.cancelled_count);
        for record in &self.records {
            e.digest(record.record_digest());
        }
        ContentDigest::sha256(&e.finish())
    }
}

/// Explicit receipt emitted whenever marginal Stage-2 ML work is declined under budget pressure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginalWorkDeclinedReceipt {
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Priority tier of the declined camera.
    pub priority: CameraPriorityTier,
    /// Work units requested by the declined frame.
    pub requested_work_units: u64,
    /// Work units remaining in the shared epoch budget at the moment of decline.
    pub remaining_work_units: u64,
    /// Pool resource pressure at the moment of decline.
    pub pressure: ResourcePressure,
    /// Mapped core resource pressure level.
    pub core_pressure: CoreResourcePressure,
    /// Exact budget constraint that forced the decline.
    pub decline_reason: DeclineReason,
    /// Corresponding unsampled gap classification (always [`UnsampledReason::BudgetThrottled`]).
    pub unsampled_reason: UnsampledReason,
    /// Domain-separated canonical SHA-256 digest of this decline receipt.
    pub receipt_digest: ContentDigest,
}

impl MarginalWorkDeclinedReceipt {
    /// Constructs and seals a canonical marginal-work decline receipt.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn seal(
        stream_order: u32,
        frame_sequence: u64,
        sensor_id: SensorId,
        priority: CameraPriorityTier,
        requested_work_units: u64,
        remaining_work_units: u64,
        pressure: ResourcePressure,
        decline_reason: DeclineReason,
    ) -> Self {
        let core_pressure = pressure.to_core_pressure();
        let unsampled_reason = UnsampledReason::BudgetThrottled;
        let mut e = CanonicalEncoder::new();
        e.text(MARGINAL_WORK_DECLINED_DOMAIN);
        e.u32(stream_order);
        e.u64(frame_sequence);
        sensor_id.encode_canonical(&mut e);
        priority.encode_canonical(&mut e);
        e.u64(requested_work_units);
        e.u64(remaining_work_units);
        pressure.encode_canonical(&mut e);
        core_pressure.encode_canonical(&mut e);
        decline_reason.encode_canonical(&mut e);
        unsampled_reason.encode_canonical(&mut e);
        let receipt_digest = ContentDigest::sha256(&e.finish());
        Self {
            stream_order,
            frame_sequence,
            sensor_id,
            priority,
            requested_work_units,
            remaining_work_units,
            pressure,
            core_pressure,
            decline_reason,
            unsampled_reason,
            receipt_digest,
        }
    }
}
