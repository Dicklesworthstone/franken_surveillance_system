#![forbid(unsafe_code)]
//! Secondary index maintenance and incremental Abelian Z-set graph edge helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fss_core::EventId;

use crate::error::ProjectionError;
use crate::schema::{GraphEdgeKey, ProjectedEventSummary, ProjectedFootageImport};
use crate::tables::{CommitAccumulator, ProjectionCounters, ProjectionTables};

impl ProjectionTables {
    pub(crate) fn insert_event_secondary_indexes(&mut self, ev: &ProjectedEventSummary) {
        let by_state = Arc::make_mut(&mut self.events_by_state);
        Arc::make_mut(
            by_state
                .entry(ev.state)
                .or_insert_with(|| Arc::new(BTreeSet::new())),
        )
        .insert(ev.event_id.clone());

        let by_zone = Arc::make_mut(&mut self.events_by_zone);
        for zone in &ev.zones {
            Arc::make_mut(
                by_zone
                    .entry(zone.clone())
                    .or_insert_with(|| Arc::new(BTreeSet::new())),
            )
            .insert(ev.event_id.clone());
        }

        let by_start = Arc::make_mut(&mut self.events_by_start);
        Arc::make_mut(
            by_start
                .entry(ev.interval.earliest.0)
                .or_insert_with(|| Arc::new(BTreeSet::new())),
        )
        .insert(ev.event_id.clone());

        let by_end = Arc::make_mut(&mut self.events_by_end);
        Arc::make_mut(
            by_end
                .entry(ev.interval.latest.0)
                .or_insert_with(|| Arc::new(BTreeSet::new())),
        )
        .insert(ev.event_id.clone());
    }

    pub(crate) fn remove_event_secondary_indexes(&mut self, ev: &ProjectedEventSummary) {
        let by_state = Arc::make_mut(&mut self.events_by_state);
        if let Some(set_arc) = by_state.get_mut(&ev.state) {
            let set = Arc::make_mut(set_arc);
            set.remove(&ev.event_id);
            if set.is_empty() {
                by_state.remove(&ev.state);
            }
        }
        let by_zone = Arc::make_mut(&mut self.events_by_zone);
        for zone in &ev.zones {
            if let Some(set_arc) = by_zone.get_mut(zone) {
                let set = Arc::make_mut(set_arc);
                set.remove(&ev.event_id);
                if set.is_empty() {
                    by_zone.remove(zone);
                }
            }
        }
        let by_start = Arc::make_mut(&mut self.events_by_start);
        if let Some(set_arc) = by_start.get_mut(&ev.interval.earliest.0) {
            let set = Arc::make_mut(set_arc);
            set.remove(&ev.event_id);
            if set.is_empty() {
                by_start.remove(&ev.interval.earliest.0);
            }
        }
        let by_end = Arc::make_mut(&mut self.events_by_end);
        if let Some(set_arc) = by_end.get_mut(&ev.interval.latest.0) {
            let set = Arc::make_mut(set_arc);
            set.remove(&ev.event_id);
            if set.is_empty() {
                by_end.remove(&ev.interval.latest.0);
            }
        }
    }

    pub(crate) fn insert_footage_secondary_indexes(&mut self, imp: &ProjectedFootageImport) {
        let range_outer = Arc::make_mut(&mut self.footage_by_range);
        let streams = Arc::make_mut(
            range_outer
                .entry(imp.sensor_id.clone())
                .or_insert_with(|| Arc::new(BTreeMap::new())),
        );
        let tuples = Arc::make_mut(
            streams
                .entry(imp.stream_id.clone())
                .or_insert_with(|| Arc::new(BTreeSet::new())),
        );
        tuples.insert((
            imp.capture_interval.earliest.0,
            imp.capture_interval.latest.0,
            imp.import_id,
        ));
    }

    pub(crate) fn remove_footage_secondary_indexes(&mut self, imp: &ProjectedFootageImport) {
        let range_outer = Arc::make_mut(&mut self.footage_by_range);
        let mut remove_sensor = false;
        if let Some(streams_arc) = range_outer.get_mut(&imp.sensor_id) {
            let streams = Arc::make_mut(streams_arc);
            let mut remove_stream = false;
            if let Some(tuples_arc) = streams.get_mut(&imp.stream_id) {
                let tuples = Arc::make_mut(tuples_arc);
                tuples.remove(&(
                    imp.capture_interval.earliest.0,
                    imp.capture_interval.latest.0,
                    imp.import_id,
                ));
                remove_stream = tuples.is_empty();
            }
            if remove_stream {
                streams.remove(&imp.stream_id);
            }
            remove_sensor = streams.is_empty();
        }
        if remove_sensor {
            range_outer.remove(&imp.sensor_id);
        }
    }
}

pub(crate) fn diff_event_zset_edges(
    event_id: &EventId,
    old: Option<&ProjectedEventSummary>,
    new: Option<&ProjectedEventSummary>,
    acc: &mut CommitAccumulator,
) -> Result<(), ProjectionError> {
    if let Some(prev) = old {
        for sensor in &prev.sensor_ids {
            acc.add_edge_delta(
                GraphEdgeKey::new("event_sensor", event_id.as_str(), sensor.as_str()),
                -1,
            )?;
        }
        for zone in &prev.zones {
            acc.add_edge_delta(
                GraphEdgeKey::new("event_zone", event_id.as_str(), zone.as_str()),
                -1,
            )?;
        }
    }
    if let Some(curr) = new {
        for sensor in &curr.sensor_ids {
            acc.add_edge_delta(
                GraphEdgeKey::new("event_sensor", event_id.as_str(), sensor.as_str()),
                1,
            )?;
        }
        for zone in &curr.zones {
            acc.add_edge_delta(
                GraphEdgeKey::new("event_zone", event_id.as_str(), zone.as_str()),
                1,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn apply_zset_edge(
    outer: &mut BTreeMap<(String, String), Arc<BTreeMap<String, i64>>>,
    counters: &mut ProjectionCounters,
    key: &GraphEdgeKey,
    delta: i64,
) -> Result<(), ProjectionError> {
    if delta == 0 {
        return Ok(());
    }
    let group_key = (key.relation.clone(), key.source.clone());
    let current = outer
        .get(&group_key)
        .and_then(|targets| targets.get(&key.target))
        .copied()
        .unwrap_or(0);
    let next = current
        .checked_add(delta)
        .ok_or(ProjectionError::ArithmeticOverflow(
            "zset_edge_multiplicity",
        ))?;
    if current == 0 && next != 0 {
        counters.active_zset_edges = counters.active_zset_edges.saturating_add(1);
    } else if current != 0 && next == 0 {
        counters.active_zset_edges = counters.active_zset_edges.saturating_sub(1);
    }

    if next == 0 {
        let mut remove_group = false;
        if let Some(targets_arc) = outer.get_mut(&group_key) {
            let targets = Arc::make_mut(targets_arc);
            targets.remove(&key.target);
            remove_group = targets.is_empty();
        }
        if remove_group {
            outer.remove(&group_key);
        }
    } else {
        let targets_arc = outer
            .entry(group_key)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(targets_arc).insert(key.target.clone(), next);
    }
    Ok(())
}
