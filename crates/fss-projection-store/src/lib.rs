#![forbid(unsafe_code)]
//! Anchor-pinned `O(1)` materialized MVCC read projections and deterministic flat-combining
//! commit coalescer for Franken Surveillance System.
//!
//! # Architecture
//!
//! - **Materialized MVCC Tables (`schema`, `tables`, `snapshot`)**: Structural-sharing
//!   copy-on-write `Arc<BTreeMap<...>>` / `Arc<BTreeSet<...>>` tables maintaining events,
//!   revisions, per-`(sensor, zone)` coverage, unified RTSP/HTTP/File/TUTK footage imports,
//!   evidence holds, privacy masks, obligations, indeterminate effects, sensor liveness,
//!   incremental DBSP Z-set graph edges (`ALG-ZSET-001`), and a chunked commit log for
//!   `O(delta)` `follow_since`.
//! - **Durable Derived Persistence (`wal`, `history`, `store`)**: CRC32C-framed binary WAL
//!   (`mvcc.wal`) paired with atomic SHA-256 verified snapshots (`mvcc.snap`), automatic
//!   corrupt-file quarantine, incremental catch-up, and bit-exact full rebuild from canonical
//!   `EvidenceDeltaBatch` history.
//! - **Deterministic Flat-Combining Commit Coalescer (`combiner`)**: Caller-elected batch
//!   collector with zero background threads that canonically sorts concurrent proposals by
//!   `(sensor_scope, request_digest)` and commits each wave via one `PackStore::append_batch`,
//!   one `MerkleEpochLedger::append_batch`, and one `MvccProjectionStore::apply_delta_batch`.

pub mod agent_index;
pub mod combiner;
pub mod error;
pub mod history;
pub mod payloads;
pub mod schema;
mod schema_codec;
pub mod snapshot;
pub mod store;
pub mod tables;
pub mod wal;

pub use combiner::{
    CoalescedCommitReceipt, CommitCombiner, CommitCombinerConfig, CommitCombinerStats,
    CommitProposal, CommitSink, DEFAULT_MAX_BATCH_PROPOSALS, DEFAULT_MAX_DELTAS_PER_BATCH,
    DEFAULT_MAX_OBJECTS_PER_BATCH, DEFAULT_MAX_PENDING_PROPOSALS, LedgerPackProjectionSink,
    OwnedPackObject, SinkCommitOutcome,
};
pub use error::{CombinerError, ProjectionError, ProjectionIoOperation};
pub use history::{CanonicalBatchSource, SliceBatchSource};
pub use payloads::{
    CoverageWitnessPayload, DeletionTarget, DeletionTombstonePayload, EffectOutcomePayload,
    EventRevisionPayload, EvidenceHoldPayload, FootageImportPayload, GraphEdgeDeltaPayload,
    InMemoryPayloadResolver, NoopPayloadResolver, ObligationPayload, PROJECTION_PAYLOAD_MAGIC,
    PROJECTION_PAYLOAD_VERSION, PackReaderPayloadResolver, PackStorePayloadResolver,
    PayloadResolver, PrivacyMaskPayload, ProjectionRecordPayload, SensorLivenessPayload,
    SensorTamperPayload, is_projected_family,
};
pub use schema::{
    CoverageStatus, DoctorScrubReceipt, EventQueryFilter, EventQueryPage,
    FAMILY_ALERT_EFFECT_OUTCOME, FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE,
    FAMILY_EFFECT_OUTCOME, FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD, FAMILY_FILE_IMPORT,
    FAMILY_FOOTAGE_IMPORT, FAMILY_GRAPH_EDGE, FAMILY_HTTP_IMPORT, FAMILY_OBLIGATION,
    FAMILY_PRIVACY_MASK_POLICY, FAMILY_RTSP_IMPORT, FAMILY_SENSOR_LIVENESS,
    FAMILY_SENSOR_TAMPER_STATUS, FAMILY_TUTK_IMPORT, FollowCommitSummary, FollowDeltaPage,
    FootageAdapterKind, FootageQueryFilter, FootageQueryPage, FootageRangeCursor, GraphEdgeKey,
    HistoryChainMode, MAX_VERIFIED_FRACTION_PPM, OrientSummary, PROJECTION_COALESCED_BATCH_DOMAIN,
    PROJECTION_SCRUB_RECEIPT_DOMAIN, PROJECTION_SNAPSHOT_DOMAIN, PROJECTION_STATE_DIGEST_DOMAIN,
    ProjectedCoverageState, ProjectedEventSummary, ProjectedFootageImport, ProjectedHold,
    ProjectedIndeterminateEffect, ProjectedObligation, ProjectedPrivacyMask, ProjectedRevisionRef,
    ProjectedSensorLiveness, ProjectionAnchor, ScrubVerdict, SensorLivenessStatus, ZSetEdgeDelta,
};
pub use snapshot::{
    MAX_PROJECTION_SNAPSHOT_BYTES, PROJECTION_SNAPSHOT_MAGIC, PROJECTION_SNAPSHOT_VERSION,
    ProjectionSnapshot,
};
pub use store::{
    DEFAULT_MAX_RETAINED_SNAPSHOTS, DEFAULT_SNAPSHOT_STRIDE, MvccProjectionStore,
    ProjectionRebuildReason, ProjectionRecoveryMode, ProjectionRecoveryReport, ProjectionStore,
    ProjectionStoreConfig, replay_from_batches, replay_onto_snapshot,
    replay_valid_prefix_onto_snapshot,
};
pub use tables::{COMMIT_LOG_CHUNK_SIZE, ProjectionCounters, ProjectionTables};
pub use wal::{
    MAX_WAL_FRAME_BODY_BYTES, QUARANTINE_DIRNAME, SNAPSHOT_FILENAME, WAL_FILENAME,
    WAL_FORMAT_VERSION, WAL_FRAME_HEADER_LEN, WAL_FRAME_MAGIC, WAL_FRAME_TRAILER_LEN,
    WalSyncPolicy,
};
