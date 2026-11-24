#![forbid(unsafe_code)]
//! Structural-sharing MVCC materialized tables, secondary indexes, and incremental delta application.
//!
//! All tables are stored in persistent copy-on-write `Arc<BTreeMap<...>>` / `Arc<BTreeSet<...>>`
//! structures with natural domain-aligned chunking/sharding so that cloning a snapshot is `O(1)`
//! and applying one [`EvidenceDeltaBatch`] clones only the touched buckets.

mod apply;
mod indexes;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, EventId, EventState, EvidenceDelta, EvidenceDeltaBatch, ObjectId, ObligationId,
    ObligationState, OperationId, SensorId, StreamId,
};

use crate::error::ProjectionError;
use crate::payloads::{
    DeletionTarget, PayloadResolver, ProjectionRecordPayload, is_projected_family,
};
use crate::schema::{
    CoverageStatus, FAMILY_DELETION_TOMBSTONE, FollowCommitSummary, FootageAdapterKind,
    GraphEdgeKey, ProjectedCoverageState, ProjectedEventSummary, ProjectedFootageImport,
    ProjectedHold, ProjectedIndeterminateEffect, ProjectedObligation, ProjectedPrivacyMask,
    ProjectedRevisionRef, ProjectedSensorLiveness, SensorLivenessStatus, ZSetEdgeDelta,
};
use indexes::apply_zset_edge;

/// Number of consecutive commits stored in one structural-sharing `commit_log_index` chunk.
pub const COMMIT_LOG_CHUNK_SIZE: u64 = 256;

/// Ordered tuple set `(start_ns, end_ns, import_id)` for one `(SensorId, StreamId)`.
pub(crate) type FootageRangeTuples = Arc<BTreeSet<(i128, i128, ContentDigest)>>;
/// Stream-level footage range map for one sensor.
pub(crate) type FootageStreamRangeMap = Arc<BTreeMap<StreamId, FootageRangeTuples>>;
/// Top-level secondary footage range index by `(SensorId, StreamId, start_ns, end_ns, import_id)`.
pub(crate) type FootageRangeIndex = Arc<BTreeMap<SensorId, FootageStreamRangeMap>>;
/// Target-to-multiplicity map for one `(relation, source)` Z-set edge prefix.
pub(crate) type ZSetTargetWeights = Arc<BTreeMap<String, i64>>;
/// Incremental Abelian Z-set graph edge table keyed by `(relation, source) -> target -> weight`.
pub(crate) type ZSetEdgeTable = Arc<BTreeMap<(String, String), ZSetTargetWeights>>;

/// Entity pointer tracked per ledger [`ObjectId`] so `deletion_tombstone` resolves in `O(log N)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObjectEntityRef {
    Event(EventId),
    FootageImport(ContentDigest),
    Coverage(SensorId, String),
    Hold(String),
}

impl CanonicalEncode for ObjectEntityRef {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Event(id) => {
                encoder.u8(1);
                id.encode_canonical(encoder);
            }
            Self::FootageImport(id) => {
                encoder.u8(2);
                encoder.digest(*id);
            }
            Self::Coverage(sensor, zone) => {
                encoder.u8(3);
                sensor.encode_canonical(encoder);
                encoder.text(zone);
            }
            Self::Hold(id) => {
                encoder.u8(4);
                encoder.text(id);
            }
        }
    }
}

impl CanonicalDecode for ObjectEntityRef {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Event(EventId::decode_canonical(decoder)?)),
            2 => Ok(Self::FootageImport(decoder.digest()?)),
            3 => Ok(Self::Coverage(
                SensorId::decode_canonical(decoder)?,
                decoder.text()?.to_owned(),
            )),
            4 => Ok(Self::Hold(decoder.text()?.to_owned())),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Computes a uniform 256-way shard bucket for an [`ObjectId`] so prefix-sharing IDs
/// (e.g. `"obj:..."`) spread evenly across copy-on-write buckets.
#[must_use]
pub(crate) fn object_id_shard(object_id: &ObjectId) -> u8 {
    let mut hash = 0x811C_9DC5_u32;
    for &byte in object_id.as_bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash ^ (hash >> 8) ^ (hash >> 16) ^ (hash >> 24)) as u8
}

/// Incrementally maintained `O(1)` counters used by [`crate::ProjectionSnapshot::orient_summary`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionCounters {
    /// Count of active events with `tamper_open == true`.
    pub tamper_open_events: usize,
    /// Count of `(sensor, zone)` entries in [`CoverageStatus::Covered`].
    pub covered_zones: usize,
    /// Count of `(sensor, zone)` entries in [`CoverageStatus::Stale`].
    pub stale_zones: usize,
    /// Count of `(sensor, zone)` entries in [`CoverageStatus::NotObservable`].
    pub not_observable_zones: usize,
    /// Total indexed footage imports across all 4 adapters.
    pub total_footage_imports: usize,
    /// Counts of indexed footage imports by [`FootageAdapterKind`] (`[Rtsp, Http, File, Tutk]`).
    pub footage_adapter_counts: [usize; 4],
    /// Count of active evidence holds (`active == true`).
    pub active_holds: usize,
    /// Count of non-terminal obligations (`Pending` or `Indeterminate`).
    pub open_obligations: usize,
    /// Counts of sensors by [`SensorLivenessStatus`] (`[Online, Degraded, Offline, Unknown]`).
    pub liveness_counts: [usize; 4],
    /// Count of non-zero directed edges in `graph_edges_zset`.
    pub active_zset_edges: usize,
}

impl ProjectionCounters {
    pub(crate) fn adapter_slot(kind: FootageAdapterKind) -> usize {
        match kind {
            FootageAdapterKind::Rtsp => 0,
            FootageAdapterKind::Http => 1,
            FootageAdapterKind::File => 2,
            FootageAdapterKind::Tutk => 3,
        }
    }

    pub(crate) fn liveness_slot(status: SensorLivenessStatus) -> usize {
        match status {
            SensorLivenessStatus::Online => 0,
            SensorLivenessStatus::Degraded => 1,
            SensorLivenessStatus::Offline => 2,
            SensorLivenessStatus::Unknown => 3,
        }
    }

    pub(crate) fn adjust_coverage(&mut self, status: CoverageStatus, add: bool) {
        let slot = match status {
            CoverageStatus::Covered => &mut self.covered_zones,
            CoverageStatus::Stale => &mut self.stale_zones,
            CoverageStatus::NotObservable => &mut self.not_observable_zones,
        };
        if add {
            *slot = slot.saturating_add(1);
        } else {
            *slot = slot.saturating_sub(1);
        }
    }

    pub(crate) fn is_open_obligation(state: ObligationState) -> bool {
        matches!(
            state,
            ObligationState::Pending | ObligationState::Indeterminate
        )
    }
}

/// Complete set of materialized MVCC read tables with structural-sharing `Arc` handles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionTables {
    /// Latest event summaries keyed by [`EventId`].
    pub(crate) latest_events: Arc<BTreeMap<EventId, ProjectedEventSummary>>,
    /// Secondary event index by `(EventState, EventId)`.
    pub(crate) events_by_state: Arc<BTreeMap<EventState, Arc<BTreeSet<EventId>>>>,
    /// Secondary event index by `(zone_id, EventId)`.
    pub(crate) events_by_zone: Arc<BTreeMap<String, Arc<BTreeSet<EventId>>>>,
    /// Secondary event index by `(interval.earliest.0, EventId)`.
    pub(crate) events_by_start: Arc<BTreeMap<i128, Arc<BTreeSet<EventId>>>>,
    /// Secondary event index by `(interval.latest.0, EventId)`.
    pub(crate) events_by_end: Arc<BTreeMap<i128, Arc<BTreeSet<EventId>>>>,
    /// Immutable historical event revisions keyed by `EventId -> revision -> ref`.
    pub(crate) event_revisions: Arc<BTreeMap<EventId, Arc<BTreeMap<u64, ProjectedRevisionRef>>>>,
    /// Coverage index keyed by `SensorId -> zone_id -> state`.
    pub(crate) coverage_index:
        Arc<BTreeMap<SensorId, Arc<BTreeMap<String, ProjectedCoverageState>>>>,
    /// Secondary coverage lookup by `zone_id -> SensorId`.
    pub(crate) coverage_by_zone: Arc<BTreeMap<String, Arc<BTreeSet<SensorId>>>>,
    /// Unified footage imports (RTSP/HTTP/File/TUTK) sharded by first digest byte.
    pub(crate) footage_imports:
        Arc<BTreeMap<u8, Arc<BTreeMap<ContentDigest, ProjectedFootageImport>>>>,
    /// Secondary footage range index by `(SensorId, StreamId, start_ns, end_ns, import_id)`.
    pub(crate) footage_by_range: FootageRangeIndex,
    /// Evidence retention holds keyed by `hold_id`.
    pub(crate) active_holds: Arc<BTreeMap<String, ProjectedHold>>,
    /// Per-sensor privacy mask policy generations keyed by [`SensorId`].
    pub(crate) privacy_masks: Arc<BTreeMap<SensorId, ProjectedPrivacyMask>>,
    /// Terminal-proof obligations keyed by [`ObligationId`].
    pub(crate) obligations: Arc<BTreeMap<ObligationId, ProjectedObligation>>,
    /// Unresolved indeterminate external effects keyed by [`OperationId`].
    pub(crate) indeterminate_effects: Arc<BTreeMap<OperationId, ProjectedIndeterminateEffect>>,
    /// Latest sensor liveness records keyed by [`SensorId`].
    pub(crate) sensor_liveness: Arc<BTreeMap<SensorId, ProjectedSensorLiveness>>,
    /// Incremental Abelian Z-set graph edges keyed by `(relation, source) -> target -> weight`.
    pub(crate) graph_edges_zset: ZSetEdgeTable,
    /// Chunked commit log index (`seq / 256 -> seq -> summary`) for `O(delta)` `follow_since`.
    pub(crate) commit_log_index: Arc<BTreeMap<u64, Arc<BTreeMap<u64, FollowCommitSummary>>>>,
    /// Sharded ledger `ObjectId -> ObjectEntityRef` map supporting `O(log N)` tombstone retraction.
    pub(crate) object_entity_index: Arc<BTreeMap<u8, Arc<BTreeMap<ObjectId, ObjectEntityRef>>>>,
    /// Pre-maintained `O(1)` summary counters.
    pub(crate) counters: ProjectionCounters,
}

#[derive(Default)]
pub(crate) struct CommitAccumulator {
    pub(crate) families: BTreeSet<String>,
    pub(crate) changed_events: BTreeSet<EventId>,
    pub(crate) changed_sensors: BTreeSet<SensorId>,
    pub(crate) changed_imports: BTreeSet<ContentDigest>,
    pub(crate) changed_obligations: BTreeSet<ObligationId>,
    pub(crate) zset_raw: BTreeMap<GraphEdgeKey, i64>,
}

impl CommitAccumulator {
    pub(crate) fn add_edge_delta(
        &mut self,
        key: GraphEdgeKey,
        delta: i64,
    ) -> Result<(), ProjectionError> {
        if delta == 0 {
            return Ok(());
        }
        let next = match self.zset_raw.get(&key) {
            Some(&cur) => cur
                .checked_add(delta)
                .ok_or(ProjectionError::ArithmeticOverflow("zset_batch_delta"))?,
            None => delta,
        };
        if next == 0 {
            self.zset_raw.remove(&key);
        } else {
            self.zset_raw.insert(key, next);
        }
        Ok(())
    }
}

impl ProjectionTables {
    /// Applies one verified canonical [`EvidenceDeltaBatch`] incrementally onto `self` using
    /// copy-on-write structural sharing and returns the emitted [`FollowCommitSummary`].
    pub fn apply_batch(
        &mut self,
        batch: &EvidenceDeltaBatch,
        payload_resolver: &dyn PayloadResolver,
    ) -> Result<FollowCommitSummary, ProjectionError> {
        let seq = batch.new_anchor.commit_sequence;
        let mut acc = CommitAccumulator::default();

        for delta in &batch.deltas {
            acc.families.insert(delta.family.clone());
            if !is_projected_family(&delta.family) {
                continue;
            }
            let resolved = payload_resolver.resolve_record_for_delta(delta)?;
            let Some((payload, payload_bytes)) = resolved else {
                if delta.family == FAMILY_DELETION_TOMBSTONE {
                    self.apply_deletion(DeletionTarget::Object(delta.object_id.clone()), &mut acc)?;
                    continue;
                }
                return Err(ProjectionError::MissingPayload {
                    digest: delta.payload_digest,
                    family: delta.family.clone(),
                });
            };
            self.apply_payload(delta, seq, payload_bytes, payload, &mut acc)?;
        }

        let mut zset_deltas = Vec::with_capacity(acc.zset_raw.len());
        if !acc.zset_raw.is_empty() {
            let outer = Arc::make_mut(&mut self.graph_edges_zset);
            for (key, weight) in acc.zset_raw {
                apply_zset_edge(outer, &mut self.counters, &key, weight)?;
                zset_deltas.push(ZSetEdgeDelta {
                    key,
                    weight,
                    commit_sequence: seq,
                });
            }
        }

        let summary = FollowCommitSummary {
            commit_sequence: seq,
            batch_id: batch.batch_id.clone(),
            authority_root: batch.new_anchor.state_root,
            families: acc.families.into_iter().collect(),
            changed_events: acc.changed_events.into_iter().collect(),
            changed_sensors: acc.changed_sensors.into_iter().collect(),
            changed_imports: acc.changed_imports.into_iter().collect(),
            changed_obligations: acc.changed_obligations.into_iter().collect(),
            zset_deltas,
        };

        let chunk_id = seq / COMMIT_LOG_CHUNK_SIZE;
        let log_outer = Arc::make_mut(&mut self.commit_log_index);
        let chunk_arc = log_outer
            .entry(chunk_id)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(chunk_arc).insert(seq, summary.clone());

        Ok(summary)
    }

    fn apply_payload(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        payload_bytes: u64,
        payload: ProjectionRecordPayload,
        acc: &mut CommitAccumulator,
    ) -> Result<(), ProjectionError> {
        match payload {
            ProjectionRecordPayload::EventRevision(ev) => {
                self.apply_event_revision(delta, seq, payload_bytes, ev, acc)?;
            }
            ProjectionRecordPayload::SensorTamper(tamper) => {
                self.apply_sensor_tamper(seq, tamper, acc);
            }
            ProjectionRecordPayload::CoverageWitness(cov) => {
                self.apply_coverage(delta, seq, cov, acc)?;
            }
            ProjectionRecordPayload::FootageImport(imp) => {
                self.apply_footage_import(delta, seq, imp, acc)?;
            }
            ProjectionRecordPayload::EvidenceHold(hold) => {
                self.apply_hold(delta, seq, hold);
            }
            ProjectionRecordPayload::PrivacyMask(mask) => {
                self.apply_privacy_mask(delta, seq, mask, acc);
            }
            ProjectionRecordPayload::Obligation(ob) => {
                self.apply_obligation(seq, ob, acc);
            }
            ProjectionRecordPayload::EffectOutcome(eff) => {
                self.apply_effect_outcome(delta, seq, eff);
            }
            ProjectionRecordPayload::SensorLiveness(live) => {
                self.apply_sensor_liveness(delta, seq, live, acc);
            }
            ProjectionRecordPayload::DeletionTombstone(del) => {
                self.apply_deletion(del.target, acc)?;
            }
            ProjectionRecordPayload::GraphEdgeDelta(edges) => {
                for (key, weight) in edges.edge_deltas {
                    acc.add_edge_delta(key, weight)?;
                }
            }
        }
        Ok(())
    }

    /// Rebuilds all derived secondary indexes and O(1) counters deterministically from primary maps
    /// after loading a canonical snapshot.
    pub(crate) fn rebuild_secondary_indexes_and_counters(&mut self) {
        self.events_by_state = Arc::new(BTreeMap::new());
        self.events_by_zone = Arc::new(BTreeMap::new());
        self.events_by_start = Arc::new(BTreeMap::new());
        self.events_by_end = Arc::new(BTreeMap::new());
        self.coverage_by_zone = Arc::new(BTreeMap::new());
        self.footage_by_range = Arc::new(BTreeMap::new());
        self.counters = ProjectionCounters::default();

        let events: Vec<ProjectedEventSummary> = self.latest_events.values().cloned().collect();
        for ev in &events {
            if ev.tamper_open {
                self.counters.tamper_open_events =
                    self.counters.tamper_open_events.saturating_add(1);
            }
            self.insert_event_secondary_indexes(ev);
        }

        let cov_pairs: Vec<(SensorId, String, CoverageStatus)> = self
            .coverage_index
            .values()
            .flat_map(|zones| zones.values())
            .map(|c| (c.sensor_id.clone(), c.zone_id.clone(), c.status))
            .collect();
        let by_zone = Arc::make_mut(&mut self.coverage_by_zone);
        for (sensor_id, zone_id, status) in cov_pairs {
            self.counters.adjust_coverage(status, true);
            Arc::make_mut(
                by_zone
                    .entry(zone_id)
                    .or_insert_with(|| Arc::new(BTreeSet::new())),
            )
            .insert(sensor_id);
        }

        let imports: Vec<ProjectedFootageImport> = self
            .footage_imports
            .values()
            .flat_map(|b| b.values())
            .cloned()
            .collect();
        for imp in &imports {
            self.counters.total_footage_imports =
                self.counters.total_footage_imports.saturating_add(1);
            let slot = ProjectionCounters::adapter_slot(imp.adapter_kind);
            self.counters.footage_adapter_counts[slot] =
                self.counters.footage_adapter_counts[slot].saturating_add(1);
            self.insert_footage_secondary_indexes(imp);
        }

        for hold in self.active_holds.values() {
            if hold.active {
                self.counters.active_holds = self.counters.active_holds.saturating_add(1);
            }
        }
        for ob in self.obligations.values() {
            if ProjectionCounters::is_open_obligation(ob.state) {
                self.counters.open_obligations = self.counters.open_obligations.saturating_add(1);
            }
        }
        for live in self.sensor_liveness.values() {
            let slot = ProjectionCounters::liveness_slot(live.state);
            self.counters.liveness_counts[slot] =
                self.counters.liveness_counts[slot].saturating_add(1);
        }
        for targets in self.graph_edges_zset.values() {
            self.counters.active_zset_edges = self
                .counters
                .active_zset_edges
                .saturating_add(targets.len());
        }
    }
}
