#![forbid(unsafe_code)]
//! Entity-level copy-on-write delta handlers for [`ProjectionTables`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fss_core::{EffectState, EvidenceDelta, ObjectId};

use crate::error::ProjectionError;
use crate::payloads::{
    CoverageWitnessPayload, DeletionTarget, EffectOutcomePayload, EventRevisionPayload,
    EvidenceHoldPayload, FootageImportPayload, ObligationPayload, PrivacyMaskPayload,
    SensorLivenessPayload, SensorTamperPayload,
};
use crate::schema::{
    CoverageStatus, GraphEdgeKey, ProjectedCoverageState, ProjectedEventSummary,
    ProjectedFootageImport, ProjectedHold, ProjectedIndeterminateEffect, ProjectedObligation,
    ProjectedPrivacyMask, ProjectedRevisionRef, ProjectedSensorLiveness,
};
use crate::tables::indexes::diff_event_zset_edges;
use crate::tables::{
    CommitAccumulator, ObjectEntityRef, ProjectionCounters, ProjectionTables, object_id_shard,
};

impl ProjectionTables {
    pub(crate) fn apply_event_revision(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        payload_bytes: u64,
        mut ev: EventRevisionPayload,
        acc: &mut CommitAccumulator,
    ) -> Result<(), ProjectionError> {
        ev.zones.sort();
        ev.zones.dedup();
        ev.sensor_ids.sort();
        ev.sensor_ids.dedup();

        let event_id = ev.event_id.clone();
        acc.changed_events.insert(event_id.clone());
        for sensor in &ev.sensor_ids {
            acc.changed_sensors.insert(sensor.clone());
        }

        let rev_ref = ProjectedRevisionRef {
            event_id: event_id.clone(),
            revision: ev.revision,
            state: ev.state,
            event_root: ev.event_root,
            revision_digest: delta.payload_digest,
            supersedes: ev.supersedes,
            committed_sequence: seq,
            payload_bytes,
        };
        let rev_outer = Arc::make_mut(&mut self.event_revisions);
        let rev_inner = rev_outer
            .entry(event_id.clone())
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(rev_inner).insert(ev.revision, rev_ref);

        let new_summary = ProjectedEventSummary {
            event_id: event_id.clone(),
            revision: ev.revision,
            state: ev.state,
            kind: ev.kind,
            zones: ev.zones,
            sensor_ids: ev.sensor_ids,
            interval: ev.interval,
            event_root: ev.event_root,
            revision_digest: delta.payload_digest,
            committed_sequence: seq,
            corroborated: ev.corroborated,
            tamper_open: ev.tamper_open,
            payload_bytes,
        };

        let existing = self.latest_events.get(&event_id).cloned();
        if let Some(old) = existing {
            if new_summary.revision < old.revision {
                return Ok(());
            }
            self.remove_event_secondary_indexes(&old);
            if old.tamper_open {
                self.counters.tamper_open_events =
                    self.counters.tamper_open_events.saturating_sub(1);
            }
            diff_event_zset_edges(&event_id, Some(&old), Some(&new_summary), acc)?;
        } else {
            diff_event_zset_edges(&event_id, None, Some(&new_summary), acc)?;
        }

        if new_summary.tamper_open {
            self.counters.tamper_open_events = self.counters.tamper_open_events.saturating_add(1);
        }
        self.insert_event_secondary_indexes(&new_summary);
        Arc::make_mut(&mut self.latest_events).insert(event_id.clone(), new_summary);
        self.record_object_entity(&delta.object_id, ObjectEntityRef::Event(event_id));
        Ok(())
    }

    pub(crate) fn apply_sensor_tamper(
        &mut self,
        seq: u64,
        tamper: SensorTamperPayload,
        acc: &mut CommitAccumulator,
    ) {
        acc.changed_events.insert(tamper.event_id.clone());
        let events = Arc::make_mut(&mut self.latest_events);
        if let Some(ev) = events.get_mut(&tamper.event_id) {
            if ev.tamper_open != tamper.tamper_open {
                if tamper.tamper_open {
                    self.counters.tamper_open_events =
                        self.counters.tamper_open_events.saturating_add(1);
                } else {
                    self.counters.tamper_open_events =
                        self.counters.tamper_open_events.saturating_sub(1);
                }
                ev.tamper_open = tamper.tamper_open;
            }
            ev.committed_sequence = seq;
        }
    }

    pub(crate) fn apply_coverage(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        cov: CoverageWitnessPayload,
        acc: &mut CommitAccumulator,
    ) -> Result<(), ProjectionError> {
        acc.changed_sensors.insert(cov.sensor_id.clone());
        let witness_digest = delta.witness_digest.unwrap_or(delta.payload_digest);
        let new_state = ProjectedCoverageState {
            sensor_id: cov.sensor_id.clone(),
            zone_id: cov.zone_id.clone(),
            latest_witness_digest: witness_digest,
            generation: delta.new_generation,
            window: cov.window,
            status: cov.status,
            active_gaps: cov.active_gaps,
            health_conflicts: cov.health_conflicts,
            committed_sequence: seq,
        };

        let old_status = self
            .coverage_index
            .get(&cov.sensor_id)
            .and_then(|zones| zones.get(&cov.zone_id))
            .map(|existing| existing.status);

        let was_covered = old_status == Some(CoverageStatus::Covered);
        let is_covered = new_state.status == CoverageStatus::Covered;
        if !was_covered && is_covered {
            acc.add_edge_delta(
                GraphEdgeKey::new(
                    "sensor_covers_zone",
                    cov.sensor_id.as_str(),
                    cov.zone_id.as_str(),
                ),
                1,
            )?;
        } else if was_covered && !is_covered {
            acc.add_edge_delta(
                GraphEdgeKey::new(
                    "sensor_covers_zone",
                    cov.sensor_id.as_str(),
                    cov.zone_id.as_str(),
                ),
                -1,
            )?;
        }

        if let Some(prev) = old_status {
            self.counters.adjust_coverage(prev, false);
        }
        self.counters.adjust_coverage(new_state.status, true);

        let cov_outer = Arc::make_mut(&mut self.coverage_index);
        let zone_map = cov_outer
            .entry(cov.sensor_id.clone())
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(zone_map).insert(cov.zone_id.clone(), new_state);

        let by_zone = Arc::make_mut(&mut self.coverage_by_zone);
        let sensors = by_zone
            .entry(cov.zone_id.clone())
            .or_insert_with(|| Arc::new(BTreeSet::new()));
        Arc::make_mut(sensors).insert(cov.sensor_id.clone());

        self.record_object_entity(
            &delta.object_id,
            ObjectEntityRef::Coverage(cov.sensor_id, cov.zone_id),
        );
        Ok(())
    }

    pub(crate) fn apply_footage_import(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        imp: FootageImportPayload,
        acc: &mut CommitAccumulator,
    ) -> Result<(), ProjectionError> {
        acc.changed_imports.insert(imp.import_id);
        acc.changed_sensors.insert(imp.sensor_id.clone());

        let new_entry = ProjectedFootageImport {
            import_id: imp.import_id,
            adapter_kind: imp.adapter_kind,
            sensor_id: imp.sensor_id.clone(),
            stream_id: imp.stream_id.clone(),
            capture_interval: imp.capture_interval,
            manifest_digest: imp.manifest_digest,
            capsule_count: imp.capsule_count,
            total_bytes: imp.total_bytes,
            adapter_id: imp.adapter_id,
            adapter_generation: imp.adapter_generation,
            completed: imp.completed,
            committed_sequence: seq,
        };

        let shard = imp.import_id.bytes()[0];
        let old_entry = self
            .footage_imports
            .get(&shard)
            .and_then(|bucket| bucket.get(&imp.import_id))
            .cloned();

        if let Some(old) = old_entry {
            self.remove_footage_secondary_indexes(&old);
            let old_slot = ProjectionCounters::adapter_slot(old.adapter_kind);
            self.counters.footage_adapter_counts[old_slot] =
                self.counters.footage_adapter_counts[old_slot].saturating_sub(1);
            let new_slot = ProjectionCounters::adapter_slot(new_entry.adapter_kind);
            self.counters.footage_adapter_counts[new_slot] =
                self.counters.footage_adapter_counts[new_slot].saturating_add(1);
            if old.sensor_id != new_entry.sensor_id {
                let id_text = old.import_id.to_text();
                acc.add_edge_delta(
                    GraphEdgeKey::new("footage_sensor", id_text.clone(), old.sensor_id.as_str()),
                    -1,
                )?;
                acc.add_edge_delta(
                    GraphEdgeKey::new("footage_sensor", id_text, new_entry.sensor_id.as_str()),
                    1,
                )?;
            }
        } else {
            self.counters.total_footage_imports =
                self.counters.total_footage_imports.saturating_add(1);
            let new_slot = ProjectionCounters::adapter_slot(new_entry.adapter_kind);
            self.counters.footage_adapter_counts[new_slot] =
                self.counters.footage_adapter_counts[new_slot].saturating_add(1);
            acc.add_edge_delta(
                GraphEdgeKey::new(
                    "footage_sensor",
                    new_entry.import_id.to_text(),
                    new_entry.sensor_id.as_str(),
                ),
                1,
            )?;
        }

        self.insert_footage_secondary_indexes(&new_entry);
        let outer = Arc::make_mut(&mut self.footage_imports);
        let bucket = outer
            .entry(shard)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(bucket).insert(imp.import_id, new_entry);
        self.record_object_entity(
            &delta.object_id,
            ObjectEntityRef::FootageImport(imp.import_id),
        );
        Ok(())
    }

    pub(crate) fn apply_hold(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        hold: EvidenceHoldPayload,
    ) {
        let holds = Arc::make_mut(&mut self.active_holds);
        if let Some(prev) = holds.get(&hold.hold_id)
            && prev.active
        {
            self.counters.active_holds = self.counters.active_holds.saturating_sub(1);
        }
        if hold.active {
            self.counters.active_holds = self.counters.active_holds.saturating_add(1);
        }
        let hold_id = hold.hold_id.clone();
        holds.insert(
            hold_id.clone(),
            ProjectedHold {
                hold_id: hold.hold_id,
                scope: hold.scope,
                target_digest: hold.target_digest,
                active: hold.active,
                committed_sequence: seq,
            },
        );
        self.record_object_entity(&delta.object_id, ObjectEntityRef::Hold(hold_id));
    }

    pub(crate) fn apply_privacy_mask(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        mask: PrivacyMaskPayload,
        acc: &mut CommitAccumulator,
    ) {
        acc.changed_sensors.insert(mask.sensor_id.clone());
        Arc::make_mut(&mut self.privacy_masks).insert(
            mask.sensor_id.clone(),
            ProjectedPrivacyMask {
                sensor_id: mask.sensor_id,
                generation: delta.new_generation,
                policy_digest: mask.policy_digest,
                committed_sequence: seq,
            },
        );
    }

    pub(crate) fn apply_obligation(
        &mut self,
        seq: u64,
        ob: ObligationPayload,
        acc: &mut CommitAccumulator,
    ) {
        acc.changed_obligations.insert(ob.obligation_id.clone());
        let obligations = Arc::make_mut(&mut self.obligations);
        if let Some(prev) = obligations.get(&ob.obligation_id)
            && ProjectionCounters::is_open_obligation(prev.state)
        {
            self.counters.open_obligations = self.counters.open_obligations.saturating_sub(1);
        }
        if ProjectionCounters::is_open_obligation(ob.state) {
            self.counters.open_obligations = self.counters.open_obligations.saturating_add(1);
        }
        obligations.insert(
            ob.obligation_id.clone(),
            ProjectedObligation {
                obligation_id: ob.obligation_id,
                operation_id: ob.operation_id,
                terminal_predicate: ob.terminal_predicate,
                state: ob.state,
                proof_digest: ob.proof_digest,
                committed_sequence: seq,
            },
        );
    }

    pub(crate) fn apply_effect_outcome(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        eff: EffectOutcomePayload,
    ) {
        let map = Arc::make_mut(&mut self.indeterminate_effects);
        if eff.effect_state == EffectState::Indeterminate {
            map.insert(
                eff.operation_id.clone(),
                ProjectedIndeterminateEffect {
                    operation_id: eff.operation_id,
                    obligation_id: eff.obligation_id,
                    effect_state: eff.effect_state,
                    reason: eff.reason,
                    record_digest: delta.payload_digest,
                    committed_sequence: seq,
                },
            );
        } else {
            map.remove(&eff.operation_id);
        }
    }

    pub(crate) fn apply_sensor_liveness(
        &mut self,
        delta: &EvidenceDelta,
        seq: u64,
        live: SensorLivenessPayload,
        acc: &mut CommitAccumulator,
    ) {
        acc.changed_sensors.insert(live.sensor_id.clone());
        let map = Arc::make_mut(&mut self.sensor_liveness);
        if let Some(prev) = map.get(&live.sensor_id) {
            let slot = ProjectionCounters::liveness_slot(prev.state);
            self.counters.liveness_counts[slot] =
                self.counters.liveness_counts[slot].saturating_sub(1);
        }
        let new_slot = ProjectionCounters::liveness_slot(live.state);
        self.counters.liveness_counts[new_slot] =
            self.counters.liveness_counts[new_slot].saturating_add(1);
        map.insert(
            live.sensor_id.clone(),
            ProjectedSensorLiveness {
                sensor_id: live.sensor_id,
                state: live.state,
                last_seen_ns: live.last_seen_ns,
                observed_at_ns: live.observed_at_ns,
                generation: delta.new_generation,
                record_digest: delta.payload_digest,
                committed_sequence: seq,
            },
        );
    }

    pub(crate) fn apply_deletion(
        &mut self,
        target: DeletionTarget,
        acc: &mut CommitAccumulator,
    ) -> Result<(), ProjectionError> {
        let resolved = match target {
            DeletionTarget::Object(obj_id) => {
                let shard = object_id_shard(&obj_id);
                let found = self
                    .object_entity_index
                    .get(&shard)
                    .and_then(|bucket| bucket.get(&obj_id))
                    .cloned();
                if let Some(entity) = found {
                    if let Some(bucket_arc) =
                        Arc::make_mut(&mut self.object_entity_index).get_mut(&shard)
                    {
                        Arc::make_mut(bucket_arc).remove(&obj_id);
                    }
                    Some(entity)
                } else {
                    None
                }
            }
            DeletionTarget::Event(id) => Some(ObjectEntityRef::Event(id)),
            DeletionTarget::FootageImport(id) => Some(ObjectEntityRef::FootageImport(id)),
            DeletionTarget::Coverage { sensor_id, zone_id } => {
                Some(ObjectEntityRef::Coverage(sensor_id, zone_id))
            }
        };

        let Some(entity) = resolved else {
            return Ok(());
        };

        match entity {
            ObjectEntityRef::Event(event_id) => {
                if let Some(old) = Arc::make_mut(&mut self.latest_events).remove(&event_id) {
                    acc.changed_events.insert(event_id.clone());
                    for sensor in &old.sensor_ids {
                        acc.changed_sensors.insert(sensor.clone());
                    }
                    self.remove_event_secondary_indexes(&old);
                    if old.tamper_open {
                        self.counters.tamper_open_events =
                            self.counters.tamper_open_events.saturating_sub(1);
                    }
                    diff_event_zset_edges(&event_id, Some(&old), None, acc)?;
                }
            }
            ObjectEntityRef::FootageImport(import_id) => {
                let shard = import_id.bytes()[0];
                let removed = if let Some(bucket) =
                    Arc::make_mut(&mut self.footage_imports).get_mut(&shard)
                {
                    let inner = Arc::make_mut(bucket);
                    let r = inner.remove(&import_id);
                    if inner.is_empty() {
                        Arc::make_mut(&mut self.footage_imports).remove(&shard);
                    }
                    r
                } else {
                    None
                };
                if let Some(old) = removed {
                    acc.changed_imports.insert(old.import_id);
                    acc.changed_sensors.insert(old.sensor_id.clone());
                    self.counters.total_footage_imports =
                        self.counters.total_footage_imports.saturating_sub(1);
                    let slot = ProjectionCounters::adapter_slot(old.adapter_kind);
                    self.counters.footage_adapter_counts[slot] =
                        self.counters.footage_adapter_counts[slot].saturating_sub(1);
                    self.remove_footage_secondary_indexes(&old);
                    acc.add_edge_delta(
                        GraphEdgeKey::new(
                            "footage_sensor",
                            old.import_id.to_text(),
                            old.sensor_id.as_str(),
                        ),
                        -1,
                    )?;
                }
            }
            ObjectEntityRef::Coverage(sensor_id, zone_id) => {
                let removed = if let Some(zones_arc) =
                    Arc::make_mut(&mut self.coverage_index).get_mut(&sensor_id)
                {
                    let inner = Arc::make_mut(zones_arc);
                    let r = inner.remove(&zone_id);
                    if inner.is_empty() {
                        Arc::make_mut(&mut self.coverage_index).remove(&sensor_id);
                    }
                    r
                } else {
                    None
                };
                if let Some(old) = removed {
                    acc.changed_sensors.insert(sensor_id.clone());
                    self.counters.adjust_coverage(old.status, false);
                    if let Some(sensors_arc) =
                        Arc::make_mut(&mut self.coverage_by_zone).get_mut(&zone_id)
                    {
                        let inner = Arc::make_mut(sensors_arc);
                        inner.remove(&sensor_id);
                        if inner.is_empty() {
                            Arc::make_mut(&mut self.coverage_by_zone).remove(&zone_id);
                        }
                    }
                    if old.status == CoverageStatus::Covered {
                        acc.add_edge_delta(
                            GraphEdgeKey::new(
                                "sensor_covers_zone",
                                sensor_id.as_str(),
                                zone_id.as_str(),
                            ),
                            -1,
                        )?;
                    }
                }
            }
            ObjectEntityRef::Hold(hold_id) => {
                if let Some(old) = Arc::make_mut(&mut self.active_holds).remove(&hold_id)
                    && old.active
                {
                    self.counters.active_holds = self.counters.active_holds.saturating_sub(1);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn record_object_entity(&mut self, object_id: &ObjectId, entity: ObjectEntityRef) {
        let shard = object_id_shard(object_id);
        let outer = Arc::make_mut(&mut self.object_entity_index);
        let bucket = outer
            .entry(shard)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(bucket).insert(object_id.clone(), entity);
    }
}
