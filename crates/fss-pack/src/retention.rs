#![forbid(unsafe_code)]
//! Hold-safe automated per-sensor retention ring, watermark degradation ladder, and
//! tombstone-first deletion ordering (`COMPREHENSIVE_PLAN §13.6`).
//!
//! # Core Safety Invariants
//!
//! 1. **Hold / Obligation / Active-Event Blocker**: No candidate carrying any legal hold
//!    (`held_by`), active obligation (`active_obligation_ids`), or active event
//!    (`active_event_ids`) is EVER selected for eviction.
//! 2. **Watermark Degradation Ladder**: Under `Elevated` (`75–85%`), `Constrained` (`85–95%`),
//!    or `Critical` (`>= 95%`), derived proxies (`is_derived_proxy == true`) are ALWAYS shed
//!    before unheld original source windows, and compaction is flagged for acceleration.
//! 3. **Quota-Pinned Refusal**: Under `Critical` capacity when all remaining space above
//!    watermark is pinned, planning returns [`RetentionPlanOutcome::QuotaPinned`] with
//!    [`ERR_STORAGE_QUOTA_PINNED_001`] and NEVER silently overwrites held/event evidence.
//! 4. **Content-Address Dedup Safety**: Digests still referenced by any retained (live or
//!    pinned) candidate are excluded from [`RetentionEvictionBatch::reclaimable_digests`].
//! 5. **Deletion Ordering**: Physical pack compaction/unlink refuses to reclaim any object
//!    unless a verified [`TombstoneCommitProof`] witnesses committed deletion tombstones.

mod planner;
mod tombstone_log;

use std::collections::BTreeMap;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};

use crate::error::PackError;

pub use planner::{TombstoneCommitProof, plan_retention};
pub use tombstone_log::{
    OBJECT_TOMBSTONE_MAGIC, OBJECT_TOMBSTONE_RECORD_LEN, OBJECT_TOMBSTONE_VERSION,
    ObjectTombstoneLog,
};

/// Stable error identifier emitted when critical capacity is entirely pinned by holds/obligations/events.
pub const ERR_STORAGE_QUOTA_PINNED_001: &str = "ERR-STORAGE-QUOTA-PINNED-001";
/// Stable error identifier for reads targeting permanently tombstoned/deleted evidence.
pub const ERR_EVIDENCE_DELETED_001: &str = "ERR-EVIDENCE-DELETED-001";

/// Canonical digest domain for [`RetentionEvictionBatch::batch_digest`].
pub const PACK_RETENTION_EVICTION_BATCH_DOMAIN: &str = "fss.pack.retention_eviction_batch.v1";
/// Canonical digest domain for [`TombstoneCommitProof::proof_digest`].
pub const PACK_TOMBSTONE_COMMIT_PROOF_DOMAIN: &str = "fss.pack.tombstone_commit_proof.v1";

/// Default soft capacity watermark percentage (`75%`, entering `Elevated`).
pub const DEFAULT_WATERMARK_SOFT_PCT: u8 = 75;
/// Default hard capacity watermark percentage (`95%`, entering `Critical`).
pub const DEFAULT_WATERMARK_HARD_PCT: u8 = 95;

/// Per-sensor hot retention window and local byte cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorRetentionPolicy {
    /// Target sensor identifier.
    pub sensor_id: String,
    /// Minimum hot-ring retention duration in nanoseconds before unheld windows expire by age.
    pub retain_hot_ns: u64,
    /// Maximum local ring bytes allocated to this sensor before evicting oldest unheld windows.
    pub max_sensor_bytes: u64,
}

impl SensorRetentionPolicy {
    /// Constructs and validates a [`SensorRetentionPolicy`].
    pub fn new(
        sensor_id: impl Into<String>,
        retain_hot_ns: u64,
        max_sensor_bytes: u64,
    ) -> Result<Self, PackError> {
        let policy = Self {
            sensor_id: sensor_id.into(),
            retain_hot_ns,
            max_sensor_bytes,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates all per-sensor retention invariants.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.sensor_id.is_empty() {
            return Err(PackError::RetentionPolicyViolation {
                detail: "sensor_id must not be empty".to_owned(),
            });
        }
        if self.max_sensor_bytes == 0 {
            return Err(PackError::RetentionPolicyViolation {
                detail: format!("max_sensor_bytes for '{}' must be >= 1", self.sensor_id),
            });
        }
        Ok(())
    }
}

/// Deployment-wide retention ring policy and capacity watermarks (`COMPREHENSIVE_PLAN §13.6`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionRingConfig {
    /// Default hot retention duration (ns) applied to sensors without an explicit override.
    pub retain_hot_ns: u64,
    /// Default per-sensor byte cap applied to sensors without an explicit override.
    pub max_sensor_bytes: u64,
    /// Hard deployment-wide local ring byte cap.
    pub max_total_deployment_bytes: u64,
    /// Soft capacity watermark percentage (default `75%`, entering `Elevated`).
    pub watermark_soft_pct: u8,
    /// Hard capacity watermark percentage (default `95%`, entering `Critical`).
    pub watermark_hard_pct: u8,
    /// Optional per-sensor retention overrides keyed by `sensor_id`.
    pub sensor_policies: BTreeMap<String, SensorRetentionPolicy>,
}

impl RetentionRingConfig {
    /// Creates a validated [`RetentionRingConfig`] with the specified bounds and watermarks.
    pub fn new(
        retain_hot_ns: u64,
        max_sensor_bytes: u64,
        max_total_deployment_bytes: u64,
        watermark_soft_pct: u8,
        watermark_hard_pct: u8,
    ) -> Result<Self, PackError> {
        let cfg = Self {
            retain_hot_ns,
            max_sensor_bytes,
            max_total_deployment_bytes,
            watermark_soft_pct,
            watermark_hard_pct,
            sensor_policies: BTreeMap::new(),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Registers a validated per-sensor policy override.
    pub fn with_sensor_policy(mut self, policy: SensorRetentionPolicy) -> Result<Self, PackError> {
        policy.validate()?;
        self.sensor_policies
            .insert(policy.sensor_id.clone(), policy);
        Ok(self)
    }

    /// Validates all retention ring configuration bounds and watermark ordering.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.max_sensor_bytes == 0 {
            return Err(PackError::RetentionPolicyViolation {
                detail: "max_sensor_bytes must be >= 1".to_owned(),
            });
        }
        if self.max_total_deployment_bytes == 0 {
            return Err(PackError::RetentionPolicyViolation {
                detail: "max_total_deployment_bytes must be >= 1".to_owned(),
            });
        }
        if self.watermark_soft_pct == 0
            || self.watermark_hard_pct > 100
            || self.watermark_soft_pct >= self.watermark_hard_pct
        {
            return Err(PackError::RetentionPolicyViolation {
                detail: format!(
                    "watermarks must satisfy 1 <= soft ({}) < hard ({}) <= 100",
                    self.watermark_soft_pct, self.watermark_hard_pct
                ),
            });
        }
        for policy in self.sensor_policies.values() {
            policy.validate()?;
        }
        Ok(())
    }

    /// Returns the midpoint percentage separating `Elevated` from `Constrained` (default `85%`).
    #[must_use]
    pub const fn constrained_pct(&self) -> u8 {
        self.watermark_soft_pct + (self.watermark_hard_pct - self.watermark_soft_pct) / 2
    }

    /// Returns the effective `(retain_hot_ns, max_sensor_bytes)` for `sensor_id`.
    #[must_use]
    pub fn policy_for_sensor(&self, sensor_id: &str) -> (u64, u64) {
        self.sensor_policies
            .get(sensor_id)
            .map_or((self.retain_hot_ns, self.max_sensor_bytes), |p| {
                (p.retain_hot_ns, p.max_sensor_bytes)
            })
    }

    /// Classifies `used_bytes` against `max_total_deployment_bytes` using exact `u128` arithmetic.
    #[must_use]
    pub fn classify_pressure(&self, used_bytes: u64) -> CapacityPressure {
        let used_x100 = u128::from(used_bytes) * 100;
        let cap = u128::from(self.max_total_deployment_bytes);
        if used_x100 >= cap * u128::from(self.watermark_hard_pct) {
            CapacityPressure::Critical
        } else if used_x100 >= cap * u128::from(self.constrained_pct()) {
            CapacityPressure::Constrained
        } else if used_x100 >= cap * u128::from(self.watermark_soft_pct) {
            CapacityPressure::Elevated
        } else {
            CapacityPressure::Nominal
        }
    }

    /// Returns the target byte ceiling corresponding to `watermark_soft_pct`.
    #[must_use]
    pub fn soft_target_bytes(&self) -> u64 {
        let raw = (u128::from(self.max_total_deployment_bytes)
            * u128::from(self.watermark_soft_pct))
            / 100;
        u64::try_from(raw).unwrap_or(self.max_total_deployment_bytes)
    }
}

/// Capacity watermark degradation ladder (`COMPREHENSIVE_PLAN §13.6`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapacityPressure {
    /// Below soft watermark (`< 75%` by default): normal operation.
    Nominal,
    /// Between soft and constrained watermarks (`75–85%`): shed derived proxies and accelerate compaction.
    Elevated,
    /// Between constrained and hard watermarks (`85–95%`): shed proxies first, then oldest unheld source.
    Constrained,
    /// At or above hard watermark (`>= 95%`): aggressive unheld eviction or `ERR-STORAGE-QUOTA-PINNED-001`.
    Critical,
}

impl CapacityPressure {
    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::Constrained => "constrained",
            Self::Critical => "critical",
        }
    }

    /// Encodes as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Nominal => 1,
            Self::Elevated => 2,
            Self::Constrained => 3,
            Self::Critical => 4,
        }
    }

    /// Returns true when derived proxies must be shed before evicting unheld source windows.
    #[must_use]
    pub const fn should_shed_proxies_first(self) -> bool {
        !matches!(self, Self::Nominal)
    }

    /// Returns true when online packfile compaction should be accelerated.
    #[must_use]
    pub const fn should_accelerate_compaction(self) -> bool {
        !matches!(self, Self::Nominal)
    }
}

/// Retained import or segment window evaluated by the retention ring planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionCandidate {
    /// Stable unique import or root identifier.
    pub import_id: String,
    /// Owning sensor identifier.
    pub sensor_id: String,
    /// End timestamp of the captured window on the declared clock basis.
    pub capture_end_ns: TimestampNs,
    /// Accounted byte size of this window/artifact in the local ring.
    pub byte_size: u64,
    /// Content-addressed SHA-256 object digests belonging to this window.
    pub object_digests: Vec<ContentDigest>,
    /// True if this record is a regenerable derived proxy/summary (shed first under pressure).
    pub is_derived_proxy: bool,
    /// Active legal/insurance/operator hold identifiers pinning this window.
    pub held_by: Vec<String>,
    /// Active durable obligation identifiers pinning this window.
    pub active_obligation_ids: Vec<String>,
    /// Active corroborated/open event identifiers pinning this window.
    pub active_event_ids: Vec<String>,
}

/// Alias matching import-record naming conventions.
pub type RetentionImportRecord = RetentionCandidate;

impl RetentionCandidate {
    /// Returns `true` if ANY legal hold, active obligation, or active event pins this record.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        !self.held_by.is_empty()
            || !self.active_obligation_ids.is_empty()
            || !self.active_event_ids.is_empty()
    }

    /// Validates structural fields and SHA-256 digest algorithms.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.import_id.is_empty() {
            return Err(PackError::RetentionPolicyViolation {
                detail: "retention candidate import_id must not be empty".to_owned(),
            });
        }
        if self.sensor_id.is_empty() {
            return Err(PackError::RetentionPolicyViolation {
                detail: format!("candidate '{}' sensor_id must not be empty", self.import_id),
            });
        }
        for digest in &self.object_digests {
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(PackError::UnsupportedDigestAlgorithm(digest.algorithm()));
            }
        }
        Ok(())
    }
}

/// Deterministic cause explaining why an unheld candidate was selected for eviction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvictionReason {
    /// Exceeded the sensor's `retain_hot_ns` hot retention window.
    ExpiredHotWindow,
    /// Exceeded the sensor's `max_sensor_bytes` quota.
    SensorQuotaExceeded,
    /// Shed as a derived proxy under `Elevated`/`Constrained`/`Critical` deployment pressure.
    DeploymentPressureProxyShed,
    /// Evicted as oldest unheld source under `Constrained`/`Critical` deployment pressure.
    DeploymentQuotaExceeded,
}

impl EvictionReason {
    /// Encodes as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::ExpiredHotWindow => 1,
            Self::SensorQuotaExceeded => 2,
            Self::DeploymentPressureProxyShed => 3,
            Self::DeploymentQuotaExceeded => 4,
        }
    }

    /// Returns the canonical string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExpiredHotWindow => "expired_hot_window",
            Self::SensorQuotaExceeded => "sensor_quota_exceeded",
            Self::DeploymentPressureProxyShed => "deployment_pressure_proxy_shed",
            Self::DeploymentQuotaExceeded => "deployment_quota_exceeded",
        }
    }
}

/// Planned deletion tombstone record for one evicted unheld candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionTombstone {
    /// Evicted import/root identifier.
    pub import_id: String,
    /// Owning sensor identifier.
    pub sensor_id: String,
    /// Whether the evicted candidate was a derived proxy.
    pub is_derived_proxy: bool,
    /// Accounted byte size evicted.
    pub byte_size: u64,
    /// Canonically sorted, deduplicated object digests associated with this import.
    pub object_digests: Vec<ContentDigest>,
    /// Deterministic eviction reason.
    pub reason: EvictionReason,
    /// Canonical SHA-256 digest witnessing the deletion rationale for catalog/log tombstoning.
    pub reason_digest: ContentDigest,
    /// Caller-supplied evaluation timestamp.
    pub evicted_at_ns: TimestampNs,
}

impl DeletionTombstone {
    /// Returns the stable machine error code (`ERR-EVIDENCE-DELETED-001`) governing reads of this record.
    #[must_use]
    pub const fn deleted_error_id(&self) -> &'static str {
        ERR_EVIDENCE_DELETED_001
    }
}

impl CanonicalEncode for DeletionTombstone {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.import_id);
        encoder.text(&self.sensor_id);
        encoder.bool(self.is_derived_proxy);
        encoder.u64(self.byte_size);
        encoder.u64(self.object_digests.len() as u64);
        for digest in &self.object_digests {
            encoder.digest(*digest);
        }
        encoder.tag(self.reason.to_tag());
        encoder.digest(self.reason_digest);
        self.evicted_at_ns.encode_canonical(encoder);
    }
}

/// Deterministic eviction plan produced by [`plan_retention`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionEvictionBatch {
    /// Evaluation timestamp provided by caller (no ambient clock).
    pub evaluated_at_ns: TimestampNs,
    /// Capacity pressure observed before eviction.
    pub pressure_before: CapacityPressure,
    /// Projected capacity pressure after eviction.
    pub pressure_after: CapacityPressure,
    /// Total tracked ring bytes before eviction.
    pub total_bytes_before: u64,
    /// Total tracked ring bytes remaining after eviction.
    pub total_bytes_after: u64,
    /// Total bytes pinned by active holds, obligations, or events.
    pub pinned_bytes: u64,
    /// Total ring bytes marked for eviction in this batch.
    pub reclaimable_bytes: u64,
    /// Count of derived proxies shed in this batch.
    pub proxies_shed_count: u64,
    /// Count of unheld source windows evicted in this batch.
    pub sources_evicted_count: u64,
    /// True if compaction should run aggressively due to non-nominal capacity pressure.
    pub accelerate_compaction: bool,
    /// Ordered deletion tombstones to commit BEFORE physical compaction/unlink.
    pub tombstones: Vec<DeletionTombstone>,
    /// Sorted, deduplicated digests safe to reclaim physically (strictly disjoint from all
    /// digests still referenced by any retained or pinned candidate).
    pub reclaimable_digests: Vec<ContentDigest>,
}

impl RetentionEvictionBatch {
    /// Computes the canonical SHA-256 batch digest under [`PACK_RETENTION_EVICTION_BATCH_DOMAIN`].
    #[must_use]
    pub fn batch_digest(&self) -> ContentDigest {
        self.canonical_digest(PACK_RETENTION_EVICTION_BATCH_DOMAIN)
    }
}

impl CanonicalEncode for RetentionEvictionBatch {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.evaluated_at_ns.encode_canonical(encoder);
        encoder.tag(self.pressure_before.to_tag());
        encoder.tag(self.pressure_after.to_tag());
        encoder.u64(self.total_bytes_before);
        encoder.u64(self.total_bytes_after);
        encoder.u64(self.pinned_bytes);
        encoder.u64(self.reclaimable_bytes);
        encoder.u64(self.proxies_shed_count);
        encoder.u64(self.sources_evicted_count);
        encoder.bool(self.accelerate_compaction);
        encoder.u64(self.tombstones.len() as u64);
        for tomb in &self.tombstones {
            tomb.encode_canonical(encoder);
        }
        encoder.u64(self.reclaimable_digests.len() as u64);
        for digest in &self.reclaimable_digests {
            encoder.digest(*digest);
        }
    }
}

/// Outcome of evaluating the hold-safe automated retention ring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionPlanOutcome {
    /// Ring is within policy; no unheld eviction is required.
    NoAction {
        /// Current deployment capacity pressure classification.
        pressure: CapacityPressure,
        /// Total tracked bytes.
        total_bytes: u64,
        /// Bytes pinned by holds, obligations, or active events.
        pinned_bytes: u64,
    },
    /// Eviction batch planned; commit tombstones first to obtain a [`TombstoneCommitProof`].
    Evict(RetentionEvictionBatch),
    /// Capacity is `Critical` and all remaining space above watermark is pinned by active holds,
    /// obligations, or events (`ERR-STORAGE-QUOTA-PINNED-001`). Never overwrites pinned evidence.
    QuotaPinned {
        /// Stable machine error identifier ([`ERR_STORAGE_QUOTA_PINNED_001`]).
        error_id: &'static str,
        /// Current pressure classification (always [`CapacityPressure::Critical`]).
        pressure: CapacityPressure,
        /// Total bytes pinned by active holds, obligations, and events.
        pinned_bytes: u64,
        /// Configured total deployment byte cap.
        cap_bytes: u64,
        /// Optional partial eviction batch for any unheld items that can still be shed.
        partial_eviction: Option<RetentionEvictionBatch>,
    },
}
