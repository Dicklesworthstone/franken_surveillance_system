#![forbid(unsafe_code)]
//! Registered media pressure degradation ladder (`FSS-121`, bead `fss-x4a.12.20`).
//!
//! Deterministically sheds derived media work under memory, queue, decode, thermal, or disk
//! pressure according to a fixed, ordered rung ladder while protecting raw source custody
//! recording until every derived workload has already been shed (`INV-010`, `INV-043`,
//! `DEP-INV-009`).
//!
//! Core invariants:
//! - Rungs strictly order shedding: non-essential renditions -> live preview -> non-critical
//!   analytics -> pause derived cognition -> emergency source backpressure (with mandatory
//!   coverage-gap witness, never silent drop!).
//! - Escalation reacts immediately to protect source custody; recovery steps down by at most
//!   one rung per evaluation after `min_recovery_hold_ns` hysteresis to prevent oscillation.
//! - Active alert corroboration protects critical corroboration analytics across rungs 1..=3.
//! - Zero `unsafe`, zero global locks/singletons, sans-IO, canonical signed/digested receipts,
//!   and cooperative cancellation before committing transitions.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::buffer_accounting::{BufferPressureTier, MAX_OWNER_ID_BYTES};

/// Registered digest domain for canonical media pressure ladder decision receipts
/// (`SCHEMA-DOMAIN-TENSOR-MEDIA-PRESSURE-LADDER-001`).
pub const MEDIA_PRESSURE_LADDER_RECEIPT_DOMAIN: &str =
    "fss.tensor.media_pressure_ladder_receipt.v1";

/// Canonical binary format version for [`MediaPressureDecisionReceipt`].
pub const MEDIA_PRESSURE_LADDER_FORMAT_VERSION: u32 = 1;

/// Ordered media degradation rungs; higher rungs shed progressively more derived work.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MediaDegradationRung {
    /// Rung 0: full source custody, preview, analytics, and secondary renditions.
    Rung0Nominal = 0,
    /// Rung 1: shed optional thumbnails and non-essential transcode renditions.
    Rung1ShedNonEssentialRenditions = 1,
    /// Rung 2: decimate live preview fan-out frame rate (`preview_stride = 2`).
    Rung2ThrottleLivePreview = 2,
    /// Rung 3: reduce non-critical analytics cadence (`analytics_stride = 4`); protect corroboration.
    Rung3ReduceAnalyticsCadence = 3,
    /// Rung 4: pause derived cognition/preview while protecting 100% of raw source custody.
    Rung4PauseDerivedCognition = 4,
    /// Rung 5: emergency source backpressure with mandatory explicit coverage-gap witness.
    Rung5EmergencySourceBackpressure = 5,
}

impl MediaDegradationRung {
    /// Numeric rung level (`0..=5`).
    #[must_use]
    pub const fn level(self) -> u8 {
        self as u8
    }

    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rung0Nominal => "rung_0_nominal",
            Self::Rung1ShedNonEssentialRenditions => "rung_1_shed_non_essential_renditions",
            Self::Rung2ThrottleLivePreview => "rung_2_throttle_live_preview",
            Self::Rung3ReduceAnalyticsCadence => "rung_3_reduce_analytics_cadence",
            Self::Rung4PauseDerivedCognition => "rung_4_pause_derived_cognition",
            Self::Rung5EmergencySourceBackpressure => "rung_5_emergency_source_backpressure",
        }
    }

    /// Steps down by exactly one rung toward nominal (never underflowing past `Rung0Nominal`).
    #[must_use]
    pub const fn step_down_one(self) -> Self {
        match self {
            Self::Rung0Nominal | Self::Rung1ShedNonEssentialRenditions => Self::Rung0Nominal,
            Self::Rung2ThrottleLivePreview => Self::Rung1ShedNonEssentialRenditions,
            Self::Rung3ReduceAnalyticsCadence => Self::Rung2ThrottleLivePreview,
            Self::Rung4PauseDerivedCognition => Self::Rung3ReduceAnalyticsCadence,
            Self::Rung5EmergencySourceBackpressure => Self::Rung4PauseDerivedCognition,
        }
    }

    /// Preview frame cadence stride enforced at this rung (`0` means live preview paused).
    #[must_use]
    pub const fn preview_stride(self) -> u8 {
        match self {
            Self::Rung0Nominal | Self::Rung1ShedNonEssentialRenditions => 1,
            Self::Rung2ThrottleLivePreview | Self::Rung3ReduceAnalyticsCadence => 2,
            Self::Rung4PauseDerivedCognition | Self::Rung5EmergencySourceBackpressure => 0,
        }
    }

    /// Non-critical analytics cadence stride (`0` means derived analytics paused).
    #[must_use]
    pub const fn analytics_stride(self) -> u8 {
        match self {
            Self::Rung0Nominal
            | Self::Rung1ShedNonEssentialRenditions
            | Self::Rung2ThrottleLivePreview => 1,
            Self::Rung3ReduceAnalyticsCadence => 4,
            Self::Rung4PauseDerivedCognition | Self::Rung5EmergencySourceBackpressure => 0,
        }
    }

    /// Whether raw source custody recording remains 100% protected without backpressure.
    #[must_use]
    pub const fn source_custody_protected(self) -> bool {
        !matches!(self, Self::Rung5EmergencySourceBackpressure)
    }

    /// Whether explicit coverage-gap witness emission is mandatory (never silent loss).
    #[must_use]
    pub const fn coverage_gap_witness_required(self) -> bool {
        matches!(
            self,
            Self::Rung4PauseDerivedCognition | Self::Rung5EmergencySourceBackpressure
        )
    }

    /// Deterministic operator/agent recovery guidance for this rung.
    #[must_use]
    pub const fn recovery_guidance(self) -> &'static str {
        match self {
            Self::Rung0Nominal => "none",
            Self::Rung1ShedNonEssentialRenditions => {
                "monitor buffer and queue pressure; non-essential renditions will resume after hold window"
            }
            Self::Rung2ThrottleLivePreview => {
                "release idle preview leases or reduce concurrent live streams to restore full preview cadence"
            }
            Self::Rung3ReduceAnalyticsCadence => {
                "reclaim frame pool buffers and inspect decoder latency; corroborated alerts remain protected"
            }
            Self::Rung4PauseDerivedCognition => {
                "derived cognition is explicitly paused while source custody stays intact; emit coverage witness and relieve host pressure"
            }
            Self::Rung5EmergencySourceBackpressure => {
                "source backpressure active: emit mandatory coverage-gap witness, reclaim storage/disk pressure, and inspect ingest health immediately"
            }
        }
    }
}

impl CanonicalEncode for MediaDegradationRung {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.level());
    }
}

impl CanonicalDecode for MediaDegradationRung {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            0 => Ok(Self::Rung0Nominal),
            1 => Ok(Self::Rung1ShedNonEssentialRenditions),
            2 => Ok(Self::Rung2ThrottleLivePreview),
            3 => Ok(Self::Rung3ReduceAnalyticsCadence),
            4 => Ok(Self::Rung4PauseDerivedCognition),
            5 => Ok(Self::Rung5EmergencySourceBackpressure),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Explicit policy governing escalation thresholds and recovery hysteresis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaPressurePolicy {
    /// Clean non-empty pipeline/camera identifier.
    pub pipeline_id: String,
    /// Queue depth (bps of 10_000) triggering Rung 1.
    pub queue_rung1_bps: u16,
    /// Queue depth (bps of 10_000) triggering Rung 2.
    pub queue_rung2_bps: u16,
    /// Queue depth (bps of 10_000) triggering Rung 3.
    pub queue_rung3_bps: u16,
    /// Decode drop rate (bps of 10_000) triggering Rung 3.
    pub decode_drop_rung3_bps: u16,
    /// Disk pressure (bps of 10_000) triggering Rung 4 (pause derived) and Rung 5 (source backpressure).
    pub disk_rung4_bps: u16,
    /// Disk pressure (bps of 10_000) triggering emergency Rung 5 source backpressure.
    pub disk_rung5_bps: u16,
    /// Minimum stable duration in nanoseconds before stepping down one rung.
    pub min_recovery_hold_ns: i128,
}

impl MediaPressurePolicy {
    /// Bounded production-safe default thresholds for `pipeline_id`.
    #[must_use]
    pub fn bounded_default(pipeline_id: impl Into<String>) -> Self {
        Self {
            pipeline_id: pipeline_id.into(),
            queue_rung1_bps: 5_000,
            queue_rung2_bps: 7_000,
            queue_rung3_bps: 8_500,
            decode_drop_rung3_bps: 1_500,
            disk_rung4_bps: 8_500,
            disk_rung5_bps: 9_500,
            min_recovery_hold_ns: 5_000_000_000,
        }
    }

    /// Fails closed on empty/malformed IDs, inverted thresholds, or non-positive hold window.
    pub fn validate(&self) -> Result<(), MediaPressureError> {
        if self.pipeline_id.is_empty()
            || self.pipeline_id.len() > MAX_OWNER_ID_BYTES
            || self
                .pipeline_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(MediaPressureError::InvalidPolicy);
        }
        if self.queue_rung1_bps == 0
            || self.queue_rung1_bps >= self.queue_rung2_bps
            || self.queue_rung2_bps >= self.queue_rung3_bps
            || self.queue_rung3_bps > 10_000
            || self.decode_drop_rung3_bps == 0
            || self.decode_drop_rung3_bps > 10_000
            || self.disk_rung4_bps == 0
            || self.disk_rung4_bps >= self.disk_rung5_bps
            || self.disk_rung5_bps > 10_000
            || self.min_recovery_hold_ns <= 0
        {
            return Err(MediaPressureError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Deterministic snapshot of current host/pipeline resource pressure signals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaPressureSignals {
    /// Exact memory pressure tier from `BufferAccountant` / `FramePool`.
    pub buffer_pressure: BufferPressureTier,
    /// Bounded ingest/decode queue fill in basis points (`0..=10_000`).
    pub queue_depth_bps: u16,
    /// Recent decode drop/skip ratio in basis points (`0..=10_000`).
    pub decode_drop_rate_bps: u16,
    /// Whether the CPU/thermal scheduler (`FSS-150`) reports active thermal throttling.
    pub thermal_throttled: bool,
    /// Storage ring/disk fullness in basis points (`0..=10_000`).
    pub disk_pressure_bps: u16,
    /// Whether an active high-priority security alert requires corroboration analytics.
    pub active_alert_corroboration: bool,
    /// Pinned active pipeline generation (`!= 0`).
    pub generation: Generation,
    /// Monotonic caller-supplied observation timestamp.
    pub observed_at_ns: TimestampNs,
}

/// Typed fail-closed refusal for media pressure ladder operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediaPressureError {
    /// Policy identifiers, thresholds, or hysteresis hold window are invalid.
    InvalidPolicy,
    /// Input bps exceeded 10_000 or generation was zero.
    InvalidSignals(&'static str),
    /// Observation timestamp regressed earlier than the previous committed transition.
    ClockRegression {
        /// Previous committed timestamp.
        previous_ns: i128,
        /// Rejected regressed timestamp.
        observed_ns: i128,
    },
    /// Evaluation attempted against a retired or mismatched generation.
    StaleGeneration {
        /// Active generation pinned by controller.
        expected: Generation,
        /// Stale generation presented.
        actual: Generation,
    },
    /// Cooperative cancellation observed before committing a transition.
    Cancelled,
}

impl fmt::Display for MediaPressureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid media pressure ladder policy"),
            Self::InvalidSignals(why) => write!(f, "invalid media pressure signals: {why}"),
            Self::ClockRegression {
                previous_ns,
                observed_ns,
            } => write!(
                f,
                "media pressure observation clock regressed ({observed_ns} < {previous_ns})"
            ),
            Self::StaleGeneration { expected, actual } => write!(
                f,
                "stale media pressure generation: expected {}, got {}",
                expected.0, actual.0
            ),
            Self::Cancelled => write!(f, "media pressure evaluation cancelled"),
        }
    }
}

impl std::error::Error for MediaPressureError {}

/// Canonical, content-addressed receipt recording one media pressure degradation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaPressureDecisionReceipt {
    /// Format version (`MEDIA_PRESSURE_LADDER_FORMAT_VERSION`).
    pub format_version: u32,
    /// Owning pipeline identifier.
    pub pipeline_id: String,
    /// Monotonic evaluation sequence number.
    pub evaluation_seq: u64,
    /// Active generation bound to this decision.
    pub generation: Generation,
    /// Observation timestamp.
    pub observed_at_ns: TimestampNs,
    /// Rung active prior to this evaluation.
    pub previous_rung: MediaDegradationRung,
    /// Raw instantaneous target rung demanded by current signals.
    pub raw_target_rung: MediaDegradationRung,
    /// Effective rung committed after applying escalation / recovery hysteresis rules.
    pub effective_rung: MediaDegradationRung,
    /// Effective live preview stride (`0` = paused).
    pub preview_stride: u8,
    /// Effective non-critical analytics stride (`0` = paused).
    pub analytics_stride: u8,
    /// Whether corroboration analytics remain protected for an active alert.
    pub alert_corroboration_protected: bool,
    /// Whether raw source custody recording remains 100% protected.
    pub source_custody_protected: bool,
    /// Whether callers MUST emit an explicit coverage-gap / degraded-cognition witness.
    pub coverage_gap_witness_required: bool,
    /// Whether recovery step-down was intentionally deferred by hysteresis hold.
    pub recovery_held_by_hysteresis: bool,
    /// Sorted machine-readable trigger codes explaining this rung.
    pub trigger_codes: Vec<String>,
    /// Deterministic recovery guidance.
    pub recovery_guidance: String,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl MediaPressureDecisionReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(MEDIA_PRESSURE_LADDER_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.pipeline_id);
        encoder.u64(self.evaluation_seq);
        encoder.u64(self.generation.0);
        encoder.i128(self.observed_at_ns.0);
        self.previous_rung.encode_canonical(&mut encoder);
        self.raw_target_rung.encode_canonical(&mut encoder);
        self.effective_rung.encode_canonical(&mut encoder);
        encoder.u8(self.preview_stride);
        encoder.u8(self.analytics_stride);
        encoder.u8(u8::from(self.alert_corroboration_protected));
        encoder.u8(u8::from(self.source_custody_protected));
        encoder.u8(u8::from(self.coverage_gap_witness_required));
        encoder.u8(u8::from(self.recovery_held_by_hysteresis));
        encoder.u64(self.trigger_codes.len() as u64);
        for code in &self.trigger_codes {
            encoder.text(code);
        }
        encoder.text(&self.recovery_guidance);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for MediaPressureDecisionReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.pipeline_id);
        encoder.u64(self.evaluation_seq);
        encoder.u64(self.generation.0);
        encoder.i128(self.observed_at_ns.0);
        self.previous_rung.encode_canonical(encoder);
        self.raw_target_rung.encode_canonical(encoder);
        self.effective_rung.encode_canonical(encoder);
        encoder.u8(self.preview_stride);
        encoder.u8(self.analytics_stride);
        encoder.u8(u8::from(self.alert_corroboration_protected));
        encoder.u8(u8::from(self.source_custody_protected));
        encoder.u8(u8::from(self.coverage_gap_witness_required));
        encoder.u8(u8::from(self.recovery_held_by_hysteresis));
        encoder.u64(self.trigger_codes.len() as u64);
        for code in &self.trigger_codes {
            encoder.text(code);
        }
        encoder.text(&self.recovery_guidance);
        encoder.digest(self.receipt_digest);
    }
}

fn decode_bool_u8(decoder: &mut CanonicalDecoder<'_>) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl CanonicalDecode for MediaPressureDecisionReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != MEDIA_PRESSURE_LADDER_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let pipeline_id = decoder.text()?.to_owned();
        if pipeline_id.is_empty()
            || pipeline_id.len() > MAX_OWNER_ID_BYTES
            || pipeline_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let evaluation_seq = decoder.u64()?;
        let generation = Generation(decoder.u64()?);
        if evaluation_seq == 0 || generation.0 == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        let observed_at_ns = TimestampNs(decoder.i128()?);
        let previous_rung = MediaDegradationRung::decode_canonical(decoder)?;
        let raw_target_rung = MediaDegradationRung::decode_canonical(decoder)?;
        let effective_rung = MediaDegradationRung::decode_canonical(decoder)?;
        let preview_stride = decoder.u8()?;
        let analytics_stride = decoder.u8()?;
        let alert_corroboration_protected = decode_bool_u8(decoder)?;
        let source_custody_protected = decode_bool_u8(decoder)?;
        let coverage_gap_witness_required = decode_bool_u8(decoder)?;
        let recovery_held_by_hysteresis = decode_bool_u8(decoder)?;
        let trigger_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if trigger_count > 32 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut trigger_codes = Vec::with_capacity(trigger_count);
        for _ in 0..trigger_count {
            trigger_codes.push(decoder.text()?.to_owned());
        }
        let recovery_guidance = decoder.text()?.to_owned();
        let receipt_digest = decoder.digest()?;

        // Enforce structural rung invariants even against forged SHA-256 payloads.
        if preview_stride != effective_rung.preview_stride()
            || analytics_stride != effective_rung.analytics_stride()
            || source_custody_protected != effective_rung.source_custody_protected()
            || coverage_gap_witness_required != effective_rung.coverage_gap_witness_required()
            || !trigger_codes.windows(2).all(|w| w[0] < w[1])
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            pipeline_id,
            evaluation_seq,
            generation,
            observed_at_ns,
            previous_rung,
            raw_target_rung,
            effective_rung,
            preview_stride,
            analytics_stride,
            alert_corroboration_protected,
            source_custody_protected,
            coverage_gap_witness_required,
            recovery_held_by_hysteresis,
            trigger_codes,
            recovery_guidance,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

/// Deterministic stateful controller driving the registered media pressure degradation ladder.
#[derive(Clone, Debug)]
pub struct MediaPressureController {
    policy: MediaPressurePolicy,
    active_generation: Generation,
    current_rung: MediaDegradationRung,
    last_observed_ns: Option<TimestampNs>,
    last_escalation_or_step_ns: Option<TimestampNs>,
    evaluation_seq: u64,
}

impl MediaPressureController {
    /// Creates a new controller pinned to `initial_generation` starting at `Rung0Nominal`.
    pub fn new(
        policy: MediaPressurePolicy,
        initial_generation: Generation,
    ) -> Result<Self, MediaPressureError> {
        policy.validate()?;
        if initial_generation.0 == 0 {
            return Err(MediaPressureError::InvalidSignals("generation_zero"));
        }
        Ok(Self {
            policy,
            active_generation: initial_generation,
            current_rung: MediaDegradationRung::Rung0Nominal,
            last_observed_ns: None,
            last_escalation_or_step_ns: None,
            evaluation_seq: 0,
        })
    }

    /// Advances the active generation monotonically (rejecting zero or regressed generations).
    pub fn advance_generation(
        &mut self,
        next_generation: Generation,
    ) -> Result<(), MediaPressureError> {
        if next_generation.0 <= self.active_generation.0 {
            return Err(MediaPressureError::StaleGeneration {
                expected: self.active_generation,
                actual: next_generation,
            });
        }
        self.active_generation = next_generation;
        Ok(())
    }

    /// Current committed degradation rung.
    #[must_use]
    pub const fn current_rung(&self) -> MediaDegradationRung {
        self.current_rung
    }

    /// Active pinned generation.
    #[must_use]
    pub const fn active_generation(&self) -> Generation {
        self.active_generation
    }

    /// Evaluates one deterministic pressure observation and commits the next ladder state.
    pub fn evaluate(
        &mut self,
        signals: MediaPressureSignals,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<MediaPressureDecisionReceipt, MediaPressureError> {
        if is_cancelled() {
            return Err(MediaPressureError::Cancelled);
        }
        if signals.generation.0 == 0 {
            return Err(MediaPressureError::InvalidSignals("generation_zero"));
        }
        if signals.generation != self.active_generation {
            return Err(MediaPressureError::StaleGeneration {
                expected: self.active_generation,
                actual: signals.generation,
            });
        }
        if signals.queue_depth_bps > 10_000
            || signals.decode_drop_rate_bps > 10_000
            || signals.disk_pressure_bps > 10_000
        {
            return Err(MediaPressureError::InvalidSignals("bps_exceeds_10000"));
        }
        if let Some(prev) = self.last_observed_ns
            && signals.observed_at_ns.0 < prev.0
        {
            return Err(MediaPressureError::ClockRegression {
                previous_ns: prev.0,
                observed_ns: signals.observed_at_ns.0,
            });
        }

        let mut triggers: Vec<String> = Vec::new();
        let mut raw_target = MediaDegradationRung::Rung0Nominal;

        if signals.disk_pressure_bps >= self.policy.disk_rung5_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung5EmergencySourceBackpressure);
            triggers.push("TRIG-DISK-EMERGENCY-BACKPRESSURE".to_owned());
        } else if signals.disk_pressure_bps >= self.policy.disk_rung4_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung4PauseDerivedCognition);
            triggers.push("TRIG-DISK-PAUSE-DERIVED".to_owned());
        }

        match signals.buffer_pressure {
            BufferPressureTier::Normal => {}
            BufferPressureTier::Elevated => {
                raw_target = raw_target.max(MediaDegradationRung::Rung1ShedNonEssentialRenditions);
                triggers.push("TRIG-BUFFER-ELEVATED".to_owned());
            }
            BufferPressureTier::Critical => {
                raw_target = raw_target.max(MediaDegradationRung::Rung3ReduceAnalyticsCadence);
                triggers.push("TRIG-BUFFER-CRITICAL".to_owned());
            }
            BufferPressureTier::Exhausted => {
                raw_target = raw_target.max(MediaDegradationRung::Rung4PauseDerivedCognition);
                triggers.push("TRIG-BUFFER-EXHAUSTED".to_owned());
            }
        }

        if signals.queue_depth_bps >= self.policy.queue_rung3_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung3ReduceAnalyticsCadence);
            triggers.push("TRIG-QUEUE-RUNG3".to_owned());
        } else if signals.queue_depth_bps >= self.policy.queue_rung2_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung2ThrottleLivePreview);
            triggers.push("TRIG-QUEUE-RUNG2".to_owned());
        } else if signals.queue_depth_bps >= self.policy.queue_rung1_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung1ShedNonEssentialRenditions);
            triggers.push("TRIG-QUEUE-RUNG1".to_owned());
        }

        if signals.decode_drop_rate_bps >= self.policy.decode_drop_rung3_bps {
            raw_target = raw_target.max(MediaDegradationRung::Rung3ReduceAnalyticsCadence);
            triggers.push("TRIG-DECODE-DROP-RATE".to_owned());
        }

        if signals.thermal_throttled {
            raw_target = raw_target.max(MediaDegradationRung::Rung2ThrottleLivePreview);
            triggers.push("TRIG-THERMAL-THROTTLED".to_owned());
        }

        triggers.sort();
        triggers.dedup();

        // Final cooperative cancellation check before committing transition.
        if is_cancelled() {
            return Err(MediaPressureError::Cancelled);
        }

        let previous_rung = self.current_rung;
        let mut recovery_held_by_hysteresis = false;
        let effective_rung = if raw_target > previous_rung {
            // Immediate escalation to protect source custody.
            self.last_escalation_or_step_ns = Some(signals.observed_at_ns);
            raw_target
        } else if raw_target < previous_rung {
            let elapsed = self.last_escalation_or_step_ns.map_or(i128::MAX, |ts| {
                signals.observed_at_ns.0.saturating_sub(ts.0)
            });
            if elapsed >= self.policy.min_recovery_hold_ns {
                self.last_escalation_or_step_ns = Some(signals.observed_at_ns);
                previous_rung.step_down_one()
            } else {
                recovery_held_by_hysteresis = true;
                previous_rung
            }
        } else {
            previous_rung
        };

        self.current_rung = effective_rung;
        self.last_observed_ns = Some(signals.observed_at_ns);
        self.evaluation_seq = self.evaluation_seq.saturating_add(1);

        let alert_corroboration_protected = signals.active_alert_corroboration
            && effective_rung <= MediaDegradationRung::Rung3ReduceAnalyticsCadence;

        let mut receipt = MediaPressureDecisionReceipt {
            format_version: MEDIA_PRESSURE_LADDER_FORMAT_VERSION,
            pipeline_id: self.policy.pipeline_id.clone(),
            evaluation_seq: self.evaluation_seq,
            generation: self.active_generation,
            observed_at_ns: signals.observed_at_ns,
            previous_rung,
            raw_target_rung: raw_target,
            effective_rung,
            preview_stride: effective_rung.preview_stride(),
            analytics_stride: effective_rung.analytics_stride(),
            alert_corroboration_protected,
            source_custody_protected: effective_rung.source_custody_protected(),
            coverage_gap_witness_required: effective_rung.coverage_gap_witness_required(),
            recovery_held_by_hysteresis,
            trigger_codes: triggers,
            recovery_guidance: effective_rung.recovery_guidance().to_owned(),
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }
}
