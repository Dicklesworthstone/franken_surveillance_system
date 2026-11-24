#![forbid(unsafe_code)]
//! Materialized row and delta summary structures for [`crate::ProjectionSnapshot`].

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EffectState, EventId, EventKind, EventState,
    ObligationId, ObligationState, OperationId, SensorId, StreamId, TimestampNs,
};

/// Materialized summary of the latest revision of an event lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedEventSummary {
    /// Stable event lineage identity.
    pub event_id: EventId,
    /// Latest committed 1-based revision number.
    pub revision: u64,
    /// Current lifecycle state.
    pub state: EventState,
    /// Coarse event classification.
    pub kind: EventKind,
    /// Canonically sorted, deduplicated zone identifiers.
    pub zones: Vec<String>,
    /// Canonically sorted, deduplicated sensor identifiers.
    pub sensor_ids: Vec<SensorId>,
    /// Conservative event capture interval.
    pub interval: CaptureInterval,
    /// Content digest of the event publication root.
    pub event_root: ContentDigest,
    /// Content digest of this exact revision payload.
    pub revision_digest: ContentDigest,
    /// Authority commit sequence that published this revision.
    pub committed_sequence: u64,
    /// True when the event has independent corroboration.
    pub corroborated: bool,
    /// True when an unretired sensor-tamper report is open on this event lineage.
    pub tamper_open: bool,
    /// Exact payload byte size of the latest revision.
    pub payload_bytes: u64,
}

/// Materialized reference to one immutable historical revision of an event lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedRevisionRef {
    /// Owning event lineage identity.
    pub event_id: EventId,
    /// 1-based revision number.
    pub revision: u64,
    /// Lifecycle state recorded in this revision.
    pub state: EventState,
    /// Publication root digest for this revision.
    pub event_root: ContentDigest,
    /// Exact payload digest of this revision.
    pub revision_digest: ContentDigest,
    /// Digest of the immediately superseded revision (`None` for revision `1`).
    pub supersedes: Option<ContentDigest>,
    /// Authority commit sequence that published this revision.
    pub committed_sequence: u64,
    /// Exact payload byte size.
    pub payload_bytes: u64,
}

/// Epistemic coverage status of a `(sensor_id, zone_id)` pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CoverageStatus {
    /// Continuous retained witness certifies coverage over the window.
    Covered,
    /// Previous coverage witness is stale and requires revalidation.
    Stale,
    /// Declared sensor/zone domain was not observable or experienced a gap.
    NotObservable,
}

impl CoverageStatus {
    /// Canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Stale => "stale",
            Self::NotObservable => "not_observable",
        }
    }

    /// Encodes as a 1-byte canonical tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Covered => 1,
            Self::Stale => 2,
            Self::NotObservable => 3,
        }
    }

    /// Decodes from a 1-byte canonical tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Covered),
            2 => Some(Self::Stale),
            3 => Some(Self::NotObservable),
            _ => None,
        }
    }
}

/// Materialized latest coverage state for one `(SensorId, zone_id)` pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedCoverageState {
    /// Sensor providing or failing to provide coverage.
    pub sensor_id: SensorId,
    /// Zone identifier covered by this entry.
    pub zone_id: String,
    /// Digest of the latest committed coverage witness.
    pub latest_witness_digest: ContentDigest,
    /// Monotonic object generation of this witness lineage.
    pub generation: u64,
    /// Time interval covered or witnessed by this record.
    pub window: CaptureInterval,
    /// Explicit epistemic status (`Covered`, `Stale`, or `NotObservable`).
    pub status: CoverageStatus,
    /// Number of active declared coverage gaps.
    pub active_gaps: u32,
    /// Number of unresolved sensor health conflicts affecting this coverage.
    pub health_conflicts: u32,
    /// Authority commit sequence that last updated this state.
    pub committed_sequence: u64,
}

/// Unified ingress adapter family across all supported footage import protocols.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FootageAdapterKind {
    /// Native RTSP camera stream import.
    Rtsp,
    /// Native HTTP/HTTPS camera or clip import.
    Http,
    /// Local or archive file import.
    File,
    /// TUTK/IOTC camera stream or recording import.
    Tutk,
}

impl FootageAdapterKind {
    /// Canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtsp => "rtsp",
            Self::Http => "http",
            Self::File => "file",
            Self::Tutk => "tutk",
        }
    }

    /// Encodes as a 1-byte canonical tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Rtsp => 1,
            Self::Http => 2,
            Self::File => 3,
            Self::Tutk => 4,
        }
    }

    /// Decodes from a 1-byte canonical tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Rtsp),
            2 => Some(Self::Http),
            3 => Some(Self::File),
            4 => Some(Self::Tutk),
            _ => None,
        }
    }
}

/// Materialized metadata for one unified footage import (RTSP, HTTP, File, or TUTK).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedFootageImport {
    /// Stable content-derived import identity.
    pub import_id: ContentDigest,
    /// Ingress adapter protocol family.
    pub adapter_kind: FootageAdapterKind,
    /// Sensor that originated the footage.
    pub sensor_id: SensorId,
    /// Logical stream generation identity.
    pub stream_id: StreamId,
    /// Conservative source-native capture interval covered by this import.
    pub capture_interval: CaptureInterval,
    /// Digest of the canonical import manifest.
    pub manifest_digest: ContentDigest,
    /// Number of immutable sensor capsules in this import.
    pub capsule_count: u64,
    /// Total source payload bytes represented.
    pub total_bytes: u64,
    /// Admitted adapter identifier string.
    pub adapter_id: String,
    /// Immutable adapter generation string.
    pub adapter_generation: String,
    /// True once the import reached completion generation.
    pub completed: bool,
    /// Authority commit sequence that last updated this import.
    pub committed_sequence: u64,
}

/// Materialized evidence retention hold entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedHold {
    /// Stable hold identifier.
    pub hold_id: String,
    /// Declared scope protected by this hold.
    pub scope: String,
    /// Content digest of the protected target root/import.
    pub target_digest: ContentDigest,
    /// True while the hold actively blocks deletion; false after explicit release.
    pub active: bool,
    /// Authority commit sequence that last updated this hold.
    pub committed_sequence: u64,
}

/// Materialized per-sensor privacy mask policy generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedPrivacyMask {
    /// Sensor to which the privacy mask applies.
    pub sensor_id: SensorId,
    /// Monotonic policy generation.
    pub generation: u64,
    /// Digest of the approved privacy mask policy object.
    pub policy_digest: ContentDigest,
    /// Authority commit sequence that committed this generation.
    pub committed_sequence: u64,
}

/// Materialized terminal-proof obligation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedObligation {
    /// Stable obligation identifier.
    pub obligation_id: ObligationId,
    /// Owning effect operation identifier.
    pub operation_id: OperationId,
    /// Terminal predicate description.
    pub terminal_predicate: String,
    /// Current obligation lifecycle state.
    pub state: ObligationState,
    /// Proof digest when terminal.
    pub proof_digest: Option<ContentDigest>,
    /// Authority commit sequence that last updated this obligation.
    pub committed_sequence: u64,
}

/// Materialized unresolved indeterminate external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedIndeterminateEffect {
    /// Effect operation identifier whose outcome remains unresolved.
    pub operation_id: OperationId,
    /// Associated obligation identifier, if any.
    pub obligation_id: Option<ObligationId>,
    /// Recorded effect state (`Indeterminate` while active here).
    pub effect_state: EffectState,
    /// Explicit bounded explanation for the unresolved state.
    pub reason: String,
    /// Digest of the canonical effect record.
    pub record_digest: ContentDigest,
    /// Authority commit sequence that recorded this state.
    pub committed_sequence: u64,
}

/// Observed liveness classification for a configured sensor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SensorLivenessStatus {
    /// Sensor responded cleanly within its expected watchdog window.
    Online,
    /// Sensor responded with degraded health, packet loss, or drift.
    Degraded,
    /// Sensor failed to respond past its watchdog threshold.
    Offline,
    /// Liveness has not been established.
    Unknown,
}

impl SensorLivenessStatus {
    /// Canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }

    /// Encodes as a 1-byte canonical tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Online => 1,
            Self::Degraded => 2,
            Self::Offline => 3,
            Self::Unknown => 4,
        }
    }

    /// Decodes from a 1-byte canonical tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Online),
            2 => Some(Self::Degraded),
            3 => Some(Self::Offline),
            4 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Materialized latest liveness record for one sensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedSensorLiveness {
    /// Sensor identity.
    pub sensor_id: SensorId,
    /// Observed liveness classification.
    pub state: SensorLivenessStatus,
    /// Last timestamp at which the sensor produced an observation or heartbeat.
    pub last_seen_ns: TimestampNs,
    /// Timestamp at which this liveness evaluation was recorded.
    pub observed_at_ns: TimestampNs,
    /// Monotonic liveness record generation.
    pub generation: u64,
    /// Content digest of the canonical liveness payload.
    pub record_digest: ContentDigest,
    /// Authority commit sequence that published this record.
    pub committed_sequence: u64,
}

/// Canonical directed typed edge key in the incremental Z-set graph table (`ALG-ZSET-001`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GraphEdgeKey {
    /// Semantic edge relation (e.g. `"event_sensor"`, `"event_zone"`, `"sensor_covers_zone"`).
    pub relation: String,
    /// Source node identity.
    pub source: String,
    /// Target node identity.
    pub target: String,
}

impl GraphEdgeKey {
    /// Creates a new canonical directed graph edge key.
    #[must_use]
    pub fn new(
        relation: impl Into<String>,
        source: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            relation: relation.into(),
            source: source.into(),
            target: target.into(),
        }
    }
}

/// One non-zero incremental Z-set edge multiplicity change emitted at a commit sequence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ZSetEdgeDelta {
    /// Directed edge key whose multiplicity changed.
    pub key: GraphEdgeKey,
    /// Signed non-zero multiplicity delta (`+1` insert, `-1` retract, etc.).
    pub weight: i64,
    /// Monotonic authority commit sequence that produced this delta.
    pub commit_sequence: u64,
}

/// Compact per-commit summary indexed for `O(delta)` `follow_since` streaming.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowCommitSummary {
    /// Monotonic authority commit sequence.
    pub commit_sequence: u64,
    /// Committed canonical batch identifier.
    pub batch_id: BatchId,
    /// Authority state root committed by this batch.
    pub authority_root: ContentDigest,
    /// Sorted deduplicated delta families touched by this commit.
    pub families: Vec<String>,
    /// Sorted deduplicated event IDs created, updated, tampered, or tombstoned.
    pub changed_events: Vec<EventId>,
    /// Sorted deduplicated sensor IDs touched by coverage, liveness, privacy, or footage deltas.
    pub changed_sensors: Vec<SensorId>,
    /// Sorted deduplicated footage import IDs created, completed, or tombstoned.
    pub changed_imports: Vec<ContentDigest>,
    /// Sorted deduplicated obligation IDs created or transitioned.
    pub changed_obligations: Vec<ObligationId>,
    /// Consolidated non-zero Z-set graph edge deltas emitted by this commit (`ALG-ZSET-001`).
    pub zset_deltas: Vec<ZSetEdgeDelta>,
}

impl FollowCommitSummary {
    /// Converts this commit's Z-set edge deltas into an [`fss_graph_algorithms::zset::ZSetDeltaBatch`]
    /// suitable for feeding directly into `ALG-ZSET-001`.
    #[must_use]
    pub fn to_zset_delta_batch(&self) -> fss_graph_algorithms::zset::ZSetDeltaBatch {
        let mut arc_deltas = Vec::with_capacity(self.zset_deltas.len());
        let mut node_deltas = Vec::new();
        for delta in &self.zset_deltas {
            let tail = format!("{}:{}", delta.key.relation, delta.key.source);
            let head = delta.key.target.clone();
            node_deltas.push((tail.clone(), delta.weight));
            node_deltas.push((head.clone(), delta.weight));
            arc_deltas.push(((tail, head), delta.weight));
        }
        fss_graph_algorithms::zset::ZSetDeltaBatch {
            commit_sequence: self.commit_sequence,
            node_deltas,
            arc_deltas,
        }
    }
}
