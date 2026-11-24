#![forbid(unsafe_code)]
//! Canonical schema types for anchor-pinned materialized MVCC projections and scrub receipts.

mod query;
mod records;

use std::collections::BTreeMap;

use fss_core::{CanonicalEncode, ContentDigest, EventState, LedgerAnchor, TimestampNs};
use fss_ledger::{
    LEDGER_ORACLE_HISTORY_DOMAIN, genesis_history_root_v2, successor_history_root_v2,
};

use crate::error::ProjectionError;

pub use query::{
    EventQueryFilter, EventQueryPage, FollowDeltaPage, FootageQueryFilter, FootageQueryPage,
    FootageRangeCursor,
};
pub use records::{
    CoverageStatus, FollowCommitSummary, FootageAdapterKind, GraphEdgeKey, ProjectedCoverageState,
    ProjectedEventSummary, ProjectedFootageImport, ProjectedHold, ProjectedIndeterminateEffect,
    ProjectedObligation, ProjectedPrivacyMask, ProjectedRevisionRef, ProjectedSensorLiveness,
    SensorLivenessStatus, ZSetEdgeDelta,
};

/// Canonical digest domain for [`DoctorScrubReceipt::receipt_digest`].
pub const PROJECTION_SCRUB_RECEIPT_DOMAIN: &str = "fss.projection.scrub_receipt.v1";
/// Canonical digest domain embedded inside verified `mvcc.snap` binary snapshots.
pub const PROJECTION_SNAPSHOT_DOMAIN: &str = "fss.projection.snapshot.v1";
/// Canonical digest domain for [`crate::ProjectionSnapshot::state_digest`].
pub const PROJECTION_STATE_DIGEST_DOMAIN: &str = "fss.projection.state_digest.v1";
/// Canonical digest domain for deterministic flat-combining coalesced batch identities.
pub const PROJECTION_COALESCED_BATCH_DOMAIN: &str = "fss.projection.coalesced_batch.v1";

/// Delta family for immutable event hypotheses/revisions.
pub const FAMILY_EVENT_REVISION: &str = "event_revision";
/// Delta family for sensor tamper reports/retirements attached to event lineages.
pub const FAMILY_SENSOR_TAMPER_STATUS: &str = "sensor_tamper_status";
/// Delta family for retained coverage witnesses.
pub const FAMILY_COVERAGE_WITNESS: &str = "coverage_witness";
/// Delta family for file-backed footage imports.
pub const FAMILY_FILE_IMPORT: &str = "file_import";
/// Unified delta family for RTSP, HTTP, File, and TUTK footage imports.
pub const FAMILY_FOOTAGE_IMPORT: &str = "footage_import";
/// Delta family for RTSP footage imports.
pub const FAMILY_RTSP_IMPORT: &str = "rtsp_import";
/// Delta family for HTTP footage imports.
pub const FAMILY_HTTP_IMPORT: &str = "http_import";
/// Delta family for TUTK footage imports.
pub const FAMILY_TUTK_IMPORT: &str = "tutk_import";
/// Delta family for evidence retention holds and releases.
pub const FAMILY_EVIDENCE_HOLD: &str = "evidence_hold";
/// Delta family for per-sensor privacy mask policy generations.
pub const FAMILY_PRIVACY_MASK_POLICY: &str = "privacy_mask_policy";
/// Delta family for durable effect obligations.
pub const FAMILY_OBLIGATION: &str = "obligation";
/// Delta family for alert effect lifecycle outcomes.
pub const FAMILY_ALERT_EFFECT_OUTCOME: &str = "alert_effect_outcome";
/// Delta family for general effect lifecycle outcomes.
pub const FAMILY_EFFECT_OUTCOME: &str = "effect_outcome";
/// Delta family for retained sensor liveness observations.
pub const FAMILY_SENSOR_LIVENESS: &str = "sensor_liveness";
/// Delta family for deletion tombstones.
pub const FAMILY_DELETION_TOMBSTONE: &str = "deletion_tombstone";
/// Delta family for explicit Z-set graph edge deltas feeding `ALG-ZSET-001`.
pub const FAMILY_GRAPH_EDGE: &str = "graph_edge";

/// Maximum permitted parts-per-million fraction (`100% = 1_000_000`).
pub const MAX_VERIFIED_FRACTION_PPM: u32 = 1_000_000;

/// Canonical ledger history-root chaining mode used by [`crate::MvccProjectionStore`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum HistoryChainMode {
    /// v2 segmented Radix-Merkle epoch ledger (`fss.ledger.epoch_history.v2`).
    #[default]
    V2MerkleEpoch,
    /// v1 reference oracle / single-file durable ledger (`fss.ledger_oracle_history.v1`).
    V1LedgerOracle,
}

impl HistoryChainMode {
    /// Encodes the history chain mode as a 1-byte canonical tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::V2MerkleEpoch => 1,
            Self::V1LedgerOracle => 2,
        }
    }

    /// Decodes a 1-byte canonical tag into a [`HistoryChainMode`].
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::V2MerkleEpoch),
            2 => Some(Self::V1LedgerOracle),
            _ => None,
        }
    }

    /// Computes the genesis history root for `genesis`.
    pub fn genesis_root(self, genesis: &LedgerAnchor) -> Result<ContentDigest, ProjectionError> {
        match self {
            Self::V2MerkleEpoch => Ok(genesis_history_root_v2(genesis)?),
            Self::V1LedgerOracle => {
                let mut encoder = fss_core::CanonicalEncoder::new();
                encoder.text("fss.canonical.v1");
                encoder.text(LEDGER_ORACLE_HISTORY_DOMAIN);
                encoder.tag(0);
                genesis.encode_canonical(&mut encoder);
                let bytes = encoder.finish_checked()?;
                Ok(ContentDigest::sha256(&bytes))
            }
        }
    }

    /// Computes the successor history root for committing `batch_digest` at `sequence`.
    pub fn successor_root(
        self,
        previous: ContentDigest,
        sequence: u64,
        batch_digest: ContentDigest,
        new_anchor: &LedgerAnchor,
    ) -> Result<ContentDigest, ProjectionError> {
        match self {
            Self::V2MerkleEpoch => Ok(successor_history_root_v2(
                previous,
                sequence,
                batch_digest,
                new_anchor,
            )?),
            Self::V1LedgerOracle => {
                let mut encoder = fss_core::CanonicalEncoder::new();
                encoder.text("fss.canonical.v1");
                encoder.text(LEDGER_ORACLE_HISTORY_DOMAIN);
                encoder.tag(1);
                encoder.digest(previous);
                encoder.u64(sequence);
                encoder.digest(batch_digest);
                new_anchor.encode_canonical(&mut encoder);
                let bytes = encoder.finish_checked()?;
                Ok(ContentDigest::sha256(&bytes))
            }
        }
    }
}

/// Exact canonical anchor pinning one materialized MVCC projection state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectionAnchor {
    /// Monotonic committed ledger sequence (`0` at genesis).
    pub commit_sequence: u64,
    /// Canonical authority state root (`LedgerAnchor::state_root`).
    pub authority_root: ContentDigest,
    /// Append-only ledger history-chain root through `commit_sequence`.
    pub history_root: ContentDigest,
    /// Content digest of the high-water `EvidenceDeltaBatch` (or genesis state root at sequence `0`).
    pub high_water_digest: ContentDigest,
}

impl ProjectionAnchor {
    /// Constructs the canonical genesis projection anchor for `genesis_anchor`.
    pub fn genesis(
        genesis_anchor: &LedgerAnchor,
        mode: HistoryChainMode,
    ) -> Result<Self, ProjectionError> {
        Ok(Self {
            commit_sequence: genesis_anchor.commit_sequence,
            authority_root: genesis_anchor.state_root,
            history_root: mode.genesis_root(genesis_anchor)?,
            high_water_digest: genesis_anchor.state_root,
        })
    }
}

/// Explicit integrity verdict reported by a doctor scrub pass.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScrubVerdict {
    /// All verified ranges, objects, and packs passed cryptographic verification.
    Clean,
    /// Verification completed with bounded partial coverage or non-fatal warnings.
    Degraded,
    /// Cryptographic corruption or missing canonical artifact was detected.
    Failed,
}

impl ScrubVerdict {
    /// Returns the canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }

    /// Encodes as a 1-byte canonical tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::Degraded => 2,
            Self::Failed => 3,
        }
    }

    /// Decodes from a 1-byte canonical tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Clean),
            2 => Some(Self::Degraded),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Timestamped, anchor-bound doctor scrub verification receipt.
///
/// Absence of a [`DoctorScrubReceipt`] is always represented as `None` (`unknown`) — never
/// flattened into `"healthy"` or `"clean"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorScrubReceipt {
    /// Timestamp when the scrub completed on the caller's declared clock basis.
    pub scrubbed_at_ns: TimestampNs,
    /// Exact projection anchor verified by this scrub pass.
    pub anchor: ProjectionAnchor,
    /// First commit sequence verified (inclusive).
    pub first_seq: u64,
    /// Last commit sequence verified (inclusive).
    pub last_seq: u64,
    /// Count of content-addressed objects cryptographically verified.
    pub verified_objects: u64,
    /// Count of sealed/active packfiles verified.
    pub verified_packs: u64,
    /// Verified fraction of the corpus in parts per million (`0..=1_000_000`).
    pub verified_fraction_ppm: u32,
    /// Explicit scrub verdict.
    pub verdict: ScrubVerdict,
}

impl DoctorScrubReceipt {
    /// Validates range and fraction invariants.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.first_seq > self.last_seq {
            return Err(ProjectionError::InvalidScrubReceipt(
                "first_seq exceeds last_seq",
            ));
        }
        if self.last_seq > self.anchor.commit_sequence {
            return Err(ProjectionError::InvalidScrubReceipt(
                "last_seq exceeds anchor commit_sequence",
            ));
        }
        if self.verified_fraction_ppm > MAX_VERIFIED_FRACTION_PPM {
            return Err(ProjectionError::InvalidScrubReceipt(
                "verified_fraction_ppm exceeds 1_000_000",
            ));
        }
        Ok(())
    }

    /// Computes the canonical SHA-256 receipt digest under [`PROJECTION_SCRUB_RECEIPT_DOMAIN`].
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(PROJECTION_SCRUB_RECEIPT_DOMAIN)
    }
}

/// O(1) materialized orientation summary derived from one anchor-pinned [`crate::ProjectionSnapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientSummary {
    /// Exact canonical projection anchor.
    pub anchor: ProjectionAnchor,
    /// Total active events.
    pub total_events: usize,
    /// Event counts partitioned by [`EventState`].
    pub events_by_state: BTreeMap<EventState, usize>,
    /// Number of events carrying an open sensor-tamper report.
    pub tamper_open_events: usize,
    /// Number of `(sensor, zone)` pairs in [`CoverageStatus::Covered`].
    pub covered_zones: usize,
    /// Number of `(sensor, zone)` pairs in [`CoverageStatus::Stale`].
    pub stale_zones: usize,
    /// Number of `(sensor, zone)` pairs in [`CoverageStatus::NotObservable`].
    pub not_observable_zones: usize,
    /// Total unified footage imports indexed across RTSP, HTTP, File, and TUTK.
    pub total_footage_imports: usize,
    /// Footage import counts partitioned by [`FootageAdapterKind`].
    pub footage_by_adapter: BTreeMap<FootageAdapterKind, usize>,
    /// Number of active evidence retention holds.
    pub active_holds: usize,
    /// Number of configured privacy masks.
    pub privacy_masks: usize,
    /// Number of non-terminal obligations (`Pending` or `Indeterminate`).
    pub open_obligations: usize,
    /// Number of unresolved indeterminate external effects.
    pub indeterminate_effects: usize,
    /// Sensor counts partitioned by [`SensorLivenessStatus`].
    pub liveness_by_status: BTreeMap<SensorLivenessStatus, usize>,
    /// Total non-zero directed edges in `graph_edges_zset`.
    pub active_zset_edges: usize,
    /// Latest doctor scrub receipt, or `None` (`unknown` — never falsely healthy).
    pub scrub_receipt: Option<DoctorScrubReceipt>,
}
