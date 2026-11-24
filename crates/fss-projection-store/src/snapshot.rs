#![forbid(unsafe_code)]
//! Immutable anchor-pinned [`ProjectionSnapshot`], indexed `O(1)`/`O(log N)` query executors,
//! and canonical `state_digest()`.

mod codec;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EventId, ObligationId,
    OperationId, SensorId,
};
use fss_graph_algorithms::zset::{ZSet, ZSetGraphState};

use crate::error::ProjectionError;
use crate::schema::{
    DoctorScrubReceipt, EventQueryFilter, EventQueryPage, FollowDeltaPage, FootageAdapterKind,
    FootageQueryFilter, FootageQueryPage, FootageRangeCursor, GraphEdgeKey, HistoryChainMode,
    OrientSummary, PROJECTION_STATE_DIGEST_DOMAIN, ProjectedCoverageState, ProjectedEventSummary,
    ProjectedFootageImport, ProjectedHold, ProjectedIndeterminateEffect, ProjectedObligation,
    ProjectedPrivacyMask, ProjectedRevisionRef, ProjectedSensorLiveness, ProjectionAnchor,
    SensorLivenessStatus,
};
use crate::tables::{COMMIT_LOG_CHUNK_SIZE, ProjectionTables};
use codec::encode_tables_canonical;

/// Binary magic bytes identifying a verified MVCC projection snapshot file (`mvcc.snap`).
pub const PROJECTION_SNAPSHOT_MAGIC: [u8; 4] = *b"FMVS";
/// Current format version for `mvcc.snap`.
pub const PROJECTION_SNAPSHOT_VERSION: u16 = 1;
/// Maximum `mvcc.snap` byte size admitted during load (512 MiB).
pub const MAX_PROJECTION_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

/// Immutable anchor-pinned MVCC snapshot of all materialized projection tables.
///
/// Cloning via `Arc<ProjectionSnapshot>` is `O(1)` and completely lock-free relative to
/// concurrent commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionSnapshot {
    /// Exact canonical authority/history anchor pinned by this snapshot.
    pub anchor: ProjectionAnchor,
    /// History chain mode used to advance `anchor.history_root`.
    pub history_mode: HistoryChainMode,
    /// Structural-sharing materialized tables.
    pub(crate) tables: ProjectionTables,
    /// Latest verified doctor scrub receipt, or `None` (`unknown`, never falsely healthy).
    pub scrub_receipt: Option<DoctorScrubReceipt>,
}

impl ProjectionSnapshot {
    /// Creates an empty genesis snapshot pinned to `anchor`.
    #[must_use]
    pub fn empty(anchor: ProjectionAnchor, history_mode: HistoryChainMode) -> Self {
        Self {
            anchor,
            history_mode,
            tables: ProjectionTables::default(),
            scrub_receipt: None,
        }
    }

    /// Returns the pinned [`ProjectionAnchor`].
    #[must_use]
    pub const fn anchor(&self) -> ProjectionAnchor {
        self.anchor
    }

    /// Returns the latest [`DoctorScrubReceipt`], or `None` (`unknown`).
    #[must_use]
    pub const fn scrub_receipt(&self) -> Option<&DoctorScrubReceipt> {
        self.scrub_receipt.as_ref()
    }

    /// Looks up the latest event summary by [`EventId`] in `O(log N)`.
    #[must_use]
    pub fn get_event(&self, event_id: &EventId) -> Option<&ProjectedEventSummary> {
        self.tables.latest_events.get(event_id)
    }

    /// Looks up one immutable event revision by `(EventId, revision)` in `O(log N)`.
    #[must_use]
    pub fn get_event_revision(
        &self,
        event_id: &EventId,
        revision: u64,
    ) -> Option<&ProjectedRevisionRef> {
        self.tables
            .event_revisions
            .get(event_id)
            .and_then(|revs| revs.get(&revision))
    }

    /// Looks up coverage state for `(sensor_id, zone_id)` in `O(log N)`.
    #[must_use]
    pub fn get_coverage(
        &self,
        sensor_id: &SensorId,
        zone_id: &str,
    ) -> Option<&ProjectedCoverageState> {
        self.tables
            .coverage_index
            .get(sensor_id)
            .and_then(|zones| zones.get(zone_id))
    }

    /// Looks up a unified footage import by `import_id` in `O(log N)`.
    #[must_use]
    pub fn get_footage_import(&self, import_id: &ContentDigest) -> Option<&ProjectedFootageImport> {
        let shard = import_id.bytes()[0];
        self.tables
            .footage_imports
            .get(&shard)
            .and_then(|bucket| bucket.get(import_id))
    }

    /// Looks up an evidence hold by `hold_id`.
    #[must_use]
    pub fn get_hold(&self, hold_id: &str) -> Option<&ProjectedHold> {
        self.tables.active_holds.get(hold_id)
    }

    /// Iterates latest hold records, including releases, at this immutable authority anchor.
    pub fn holds(&self) -> impl Iterator<Item = &ProjectedHold> {
        self.tables.active_holds.values()
    }

    /// Looks up the latest privacy mask policy for `sensor_id`.
    #[must_use]
    pub fn get_privacy_mask(&self, sensor_id: &SensorId) -> Option<&ProjectedPrivacyMask> {
        self.tables.privacy_masks.get(sensor_id)
    }

    /// Looks up an obligation by [`ObligationId`].
    #[must_use]
    pub fn get_obligation(&self, obligation_id: &ObligationId) -> Option<&ProjectedObligation> {
        self.tables.obligations.get(obligation_id)
    }

    /// Looks up an unresolved indeterminate effect by [`OperationId`].
    #[must_use]
    pub fn get_indeterminate_effect(
        &self,
        operation_id: &OperationId,
    ) -> Option<&ProjectedIndeterminateEffect> {
        self.tables.indeterminate_effects.get(operation_id)
    }

    /// Looks up the latest sensor liveness record for `sensor_id`.
    #[must_use]
    pub fn get_sensor_liveness(&self, sensor_id: &SensorId) -> Option<&ProjectedSensorLiveness> {
        self.tables.sensor_liveness.get(sensor_id)
    }

    /// Looks up the Z-set multiplicity of a directed graph edge (`0` if absent).
    #[must_use]
    pub fn zset_edge_weight(&self, key: &GraphEdgeKey) -> i64 {
        self.tables
            .graph_edges_zset
            .get(&(key.relation.clone(), key.source.clone()))
            .and_then(|targets| targets.get(&key.target))
            .copied()
            .unwrap_or(0)
    }

    /// Exports `graph_edges_zset` into an [`fss_graph_algorithms::zset::ZSetGraphState`]
    /// directly consumable by `ALG-ZSET-001` (`zset_incremental_maintenance`).
    pub fn to_zset_graph_state(&self) -> Result<ZSetGraphState, ProjectionError> {
        let mut nodes = ZSet::new();
        let mut arcs = ZSet::new();
        for ((relation, source), targets) in self.tables.graph_edges_zset.iter() {
            let tail = format!("{relation}:{source}");
            for (target, &weight) in targets.iter() {
                nodes
                    .add_weight(tail.clone(), weight)
                    .map_err(|_| ProjectionError::ArithmeticOverflow("zset_node_weight"))?;
                nodes
                    .add_weight(target.clone(), weight)
                    .map_err(|_| ProjectionError::ArithmeticOverflow("zset_node_weight"))?;
                arcs.add_weight((tail.clone(), target.clone()), weight)
                    .map_err(|_| ProjectionError::ArithmeticOverflow("zset_arc_weight"))?;
            }
        }
        Ok(ZSetGraphState { nodes, arcs })
    }

    /// Projects an `O(1)` [`OrientSummary`] directly from pre-maintained counters and small maps.
    #[must_use]
    pub fn orient_summary(&self) -> OrientSummary {
        let mut events_by_state = BTreeMap::new();
        for (&state, ids) in self.tables.events_by_state.iter() {
            events_by_state.insert(state, ids.len());
        }
        let mut footage_by_adapter = BTreeMap::new();
        for (idx, kind) in [
            FootageAdapterKind::Rtsp,
            FootageAdapterKind::Http,
            FootageAdapterKind::File,
            FootageAdapterKind::Tutk,
        ]
        .into_iter()
        .enumerate()
        {
            let count = self.tables.counters.footage_adapter_counts[idx];
            if count > 0 {
                footage_by_adapter.insert(kind, count);
            }
        }
        let mut liveness_by_status = BTreeMap::new();
        for (idx, status) in [
            SensorLivenessStatus::Online,
            SensorLivenessStatus::Degraded,
            SensorLivenessStatus::Offline,
            SensorLivenessStatus::Unknown,
        ]
        .into_iter()
        .enumerate()
        {
            let count = self.tables.counters.liveness_counts[idx];
            if count > 0 {
                liveness_by_status.insert(status, count);
            }
        }
        OrientSummary {
            anchor: self.anchor,
            total_events: self.tables.latest_events.len(),
            events_by_state,
            tamper_open_events: self.tables.counters.tamper_open_events,
            covered_zones: self.tables.counters.covered_zones,
            stale_zones: self.tables.counters.stale_zones,
            not_observable_zones: self.tables.counters.not_observable_zones,
            total_footage_imports: self.tables.counters.total_footage_imports,
            footage_by_adapter,
            active_holds: self.tables.counters.active_holds,
            privacy_masks: self.tables.privacy_masks.len(),
            open_obligations: self.tables.counters.open_obligations,
            indeterminate_effects: self.tables.indeterminate_effects.len(),
            liveness_by_status,
            active_zset_edges: self.tables.counters.active_zset_edges,
            scrub_receipt: self.scrub_receipt.clone(),
        }
    }

    /// Executes an indexed event query against this immutable snapshot.
    pub fn query_events(&self, filter: &EventQueryFilter, limit: usize) -> EventQueryPage {
        let mut entries = Vec::with_capacity(limit.min(256));
        let mut has_more = false;

        if filter.validate().is_err() || limit == 0 {
            return EventQueryPage {
                anchor: self.anchor,
                entries,
                has_more: false,
                next_cursor: None,
            };
        }

        if let Some(exact_id) = &filter.event_id {
            if let Some(ev) = self.tables.latest_events.get(exact_id)
                && filter.matches(ev)
            {
                entries.push(ev.clone());
            }
            return EventQueryPage {
                anchor: self.anchor,
                next_cursor: entries.last().map(|e| e.event_id.clone()),
                entries,
                has_more: false,
            };
        }

        if let Some(state) = filter.state {
            if let Some(ids) = self.tables.events_by_state.get(&state) {
                collect_event_ids(
                    &self.tables.latest_events,
                    ids,
                    filter,
                    limit,
                    &mut entries,
                    &mut has_more,
                );
            }
        } else if let Some(zone) = &filter.zone {
            if let Some(ids) = self.tables.events_by_zone.get(zone) {
                collect_event_ids(
                    &self.tables.latest_events,
                    ids,
                    filter,
                    limit,
                    &mut entries,
                    &mut has_more,
                );
            }
        } else if filter.from_ns.is_some() || filter.through_ns.is_some() {
            let mut candidates = BTreeSet::new();
            match (filter.from_ns, filter.through_ns) {
                (Some(lo), _) => {
                    for (_, ids) in self.tables.events_by_end.range(lo..) {
                        for id in ids.iter() {
                            candidates.insert(id.clone());
                        }
                    }
                }
                (None, Some(hi)) => {
                    for (_, ids) in self.tables.events_by_start.range(..=hi) {
                        for id in ids.iter() {
                            candidates.insert(id.clone());
                        }
                    }
                }
                (None, None) => {}
            }
            collect_event_ids(
                &self.tables.latest_events,
                &candidates,
                filter,
                limit,
                &mut entries,
                &mut has_more,
            );
        } else {
            let start = match &filter.after_event_id {
                Some(cursor) => Bound::Excluded(cursor.clone()),
                None => Bound::Unbounded,
            };
            for (_, ev) in self.tables.latest_events.range((start, Bound::Unbounded)) {
                if !filter.matches(ev) {
                    continue;
                }
                if entries.len() == limit {
                    has_more = true;
                    break;
                }
                entries.push(ev.clone());
            }
        }

        let next_cursor = if has_more {
            entries.last().map(|e| e.event_id.clone())
        } else {
            None
        };
        EventQueryPage {
            anchor: self.anchor,
            entries,
            has_more,
            next_cursor,
        }
    }

    /// Executes an indexed unified footage query across RTSP, HTTP, File, and TUTK imports.
    pub fn query_footage(&self, filter: &FootageQueryFilter, limit: usize) -> FootageQueryPage {
        let mut entries = Vec::with_capacity(limit.min(256));
        let mut has_more = false;

        if filter.validate().is_err() || limit == 0 {
            return FootageQueryPage {
                anchor: self.anchor,
                entries,
                has_more: false,
                next_cursor: None,
            };
        }

        let sensor_lower = match (&filter.sensor, &filter.after_cursor) {
            (Some(s), _) => Bound::Included(s.clone()),
            (None, Some(c)) => Bound::Included(c.sensor_id.clone()),
            (None, None) => Bound::Unbounded,
        };
        let sensor_upper = match &filter.sensor {
            Some(s) => Bound::Included(s.clone()),
            None => Bound::Unbounded,
        };

        'outer: for (sensor_id, streams) in self
            .tables
            .footage_by_range
            .range((sensor_lower, sensor_upper))
        {
            let cursor_same_sensor = filter
                .after_cursor
                .as_ref()
                .filter(|c| &c.sensor_id == sensor_id);

            let stream_lower = match (&filter.stream, cursor_same_sensor) {
                (Some(st), _) => Bound::Included(st.clone()),
                (None, Some(c)) => Bound::Included(c.stream_id.clone()),
                (None, None) => Bound::Unbounded,
            };
            let stream_upper = match &filter.stream {
                Some(st) => Bound::Included(st.clone()),
                None => Bound::Unbounded,
            };

            for (stream_id, tuples) in streams.range((stream_lower, stream_upper)) {
                let cursor_same_stream = cursor_same_sensor.filter(|c| &c.stream_id == stream_id);
                let tuple_lower = match cursor_same_stream {
                    Some(c) => Bound::Excluded((c.start_ns, c.end_ns, c.import_id)),
                    None => Bound::Unbounded,
                };
                let tuple_upper = match filter.through_ns {
                    Some(hi) => Bound::Included((
                        hi,
                        i128::MAX,
                        ContentDigest::new(DigestAlgorithm::Blake3, [0xFF; 32]),
                    )),
                    None => Bound::Unbounded,
                };

                for &(_, end_ns, import_id) in tuples.range((tuple_lower, tuple_upper)) {
                    if filter.from_ns.is_some_and(|lo| end_ns < lo) {
                        continue;
                    }
                    let Some(imp) = self.get_footage_import(&import_id) else {
                        continue;
                    };
                    if !filter.matches(imp) {
                        continue;
                    }
                    if entries.len() == limit {
                        has_more = true;
                        break 'outer;
                    }
                    entries.push(imp.clone());
                }
            }
        }

        let next_cursor = if has_more {
            entries.last().map(FootageRangeCursor::from_import)
        } else {
            None
        };
        FootageQueryPage {
            anchor: self.anchor,
            entries,
            has_more,
            next_cursor,
        }
    }

    /// Queries coverage state with `O(log N)` direct lookup for `(Some(sensor), Some(zone))`
    /// and indexed scans when either coordinate is wildcarded.
    #[must_use]
    pub fn query_coverage(
        &self,
        sensor: Option<&SensorId>,
        zone: Option<&str>,
    ) -> Vec<ProjectedCoverageState> {
        match (sensor, zone) {
            (Some(s), Some(z)) => self.get_coverage(s, z).cloned().into_iter().collect(),
            (Some(s), None) => self
                .tables
                .coverage_index
                .get(s)
                .map(|zones| zones.values().cloned().collect())
                .unwrap_or_default(),
            (None, Some(z)) => {
                let mut out = Vec::new();
                if let Some(sensors) = self.tables.coverage_by_zone.get(z) {
                    for s in sensors.iter() {
                        if let Some(state) = self.get_coverage(s, z) {
                            out.push(state.clone());
                        }
                    }
                }
                out
            }
            (None, None) => self
                .tables
                .coverage_index
                .values()
                .flat_map(|zones| zones.values().cloned())
                .collect(),
        }
    }

    /// Performs an `O(delta)` indexed range scan of commits strictly after `after_sequence`.
    pub fn follow_since(
        &self,
        after_sequence: u64,
        max_entries: usize,
    ) -> Result<FollowDeltaPage, ProjectionError> {
        if after_sequence > self.anchor.commit_sequence {
            return Err(ProjectionError::SequenceAhead {
                requested: after_sequence,
                head: self.anchor.commit_sequence,
            });
        }
        let mut commits = Vec::with_capacity(max_entries.min(256));
        let mut has_more = false;
        if max_entries > 0 && after_sequence < self.anchor.commit_sequence {
            let start_seq = after_sequence.saturating_add(1);
            let start_chunk = start_seq / COMMIT_LOG_CHUNK_SIZE;
            'scan: for (_, chunk) in self.tables.commit_log_index.range(start_chunk..) {
                for (&seq, summary) in chunk.range(start_seq..) {
                    if seq > self.anchor.commit_sequence {
                        break 'scan;
                    }
                    if commits.len() == max_entries {
                        has_more = true;
                        break 'scan;
                    }
                    commits.push(summary.clone());
                }
            }
        }
        let next_after_sequence = commits
            .last()
            .map_or(after_sequence, |summary| summary.commit_sequence);
        Ok(FollowDeltaPage {
            head_anchor: self.anchor,
            after_sequence,
            commits,
            has_more,
            next_after_sequence,
        })
    }

    /// Computes the canonical deterministic SHA-256 digest of all canonical materialized state
    /// under [`PROJECTION_STATE_DIGEST_DOMAIN`].
    ///
    /// Excludes operational scrub receipts so that an incrementally maintained store, a rebuilt
    /// store, and a full-history replay oracle produce bit-exact digests.
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(PROJECTION_STATE_DIGEST_DOMAIN);
        self.anchor.encode_canonical(&mut encoder);
        encode_tables_canonical(&self.tables, &mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

fn collect_event_ids(
    latest_events: &BTreeMap<EventId, ProjectedEventSummary>,
    ids: &BTreeSet<EventId>,
    filter: &EventQueryFilter,
    limit: usize,
    entries: &mut Vec<ProjectedEventSummary>,
    has_more: &mut bool,
) {
    let start = match &filter.after_event_id {
        Some(cursor) => Bound::Excluded(cursor.clone()),
        None => Bound::Unbounded,
    };
    for id in ids.range((start, Bound::Unbounded)) {
        let Some(ev) = latest_events.get(id) else {
            continue;
        };
        if !filter.matches(ev) {
            continue;
        }
        if entries.len() == limit {
            *has_more = true;
            break;
        }
        entries.push(ev.clone());
    }
}
