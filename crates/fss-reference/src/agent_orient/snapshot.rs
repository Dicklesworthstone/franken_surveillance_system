#![forbid(unsafe_code)]
//! Anchor-pinned snapshot compilation from a committed [`super::DeploymentHistory`] prefix.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalDecode, ContentDigest, DecisionPath, EventHypothesis, EventState, ProbabilityInterval,
    TimestampNs,
};
use fss_object::ObjectManifest;
use fss_projection_store::{PROJECTION_PAYLOAD_MAGIC, ProjectionRecordPayload};

use super::coverage::{self, MAX_COVERAGE_CAPSULE_READS, RetainedCoverage, RetainedSourceCoverage};
use super::historical_health;
use super::reader::{DeploymentHistory, Reader};
use super::types::{
    DeploymentReadError, DeploymentSnapshot, HistoryPosition, MAX_DEPLOYMENT_EVENTS, RetainedEvent,
    corrupt,
};
use crate::MockModelResult;
use crate::ingest::calibration_adoption::{AdoptionError, retained_adoptions_from_batches};
use crate::ingest::recorded_coverage::CoverageRecord;
use crate::ingest::source_coverage::{SourceCoverageRecord, verify_retained_coverage};
use crate::reference_deployment::{
    FAMILY_COVERAGE_WITNESS, FAMILY_EVENT_REVISION, FAMILY_FILE_IMPORT_MANIFEST,
    FAMILY_SENSOR_CAPSULE,
};

impl DeploymentHistory {
    /// Compiles the snapshot of one committed `position` from the records inside it.
    ///
    /// Only the ledger batches through the position's commit sequence, the effect records through
    /// its record count, and the spool objects those batches publish are read back (each object
    /// rehashed). A position that is not a committed prefix is
    /// [`DeploymentReadError::NotCommitted`].
    pub fn snapshot_at(
        &self,
        position: HistoryPosition,
    ) -> Result<DeploymentSnapshot, DeploymentReadError> {
        self.snapshot_at_cancellable(position, &|| false)
    }

    /// Compiles one committed snapshot while admitting every bounded payload read through
    /// the request's cancellation probe. No successful partial snapshot is returned after
    /// cancellation; an already-running bounded host read cannot be preempted.
    pub fn snapshot_at_cancellable(
        &self,
        position: HistoryPosition,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DeploymentSnapshot, DeploymentReadError> {
        if cancelled() {
            if let Some(budget) = &self.metadata_budget {
                budget.fail();
            }
            return Err(corrupt("retained read authority cancelled"));
        }
        let not_committed = || DeploymentReadError::NotCommitted {
            reason: format!(
                "commit {} with {} effect record(s) is not a committed prefix of this deployment",
                position.commit_sequence,
                position
                    .effect_records
                    .map_or_else(|| "no".to_owned(), |count| count.to_string())
            ),
        };
        let batch_count = self
            .ledger_prefix(position.commit_sequence)
            .ok_or_else(not_committed)?;
        let effect_count = self
            .effect_prefix(position.effect_records)
            .ok_or_else(not_committed)?;
        let (anchor, ledger_root, effect_journal_root) =
            self.roots_at(position).ok_or_else(not_committed)?;
        let batches = self.batches.get(..batch_count).ok_or_else(not_committed)?;
        let ledger_len = batch_count
            .checked_sub(1)
            .and_then(|last| self.ledger_positions.get(last))
            .map_or(0, |committed| committed.prefix_len);

        let mut reader = Reader {
            files_read: 2,
            bytes_read: self.layout_bytes + ledger_len,
            budget: self.metadata_budget.clone(),
            cancelled: Some(cancelled),
            pack_catalog: self.pack_catalog.as_ref(),
        };
        let (effect_journal_digest, obligations, operations) = match effect_count {
            None => (ContentDigest::sha256(&[]), Vec::new(), Vec::new()),
            Some(count) => {
                let records = self.effect_records.get(..count).ok_or_else(not_committed)?;
                let prefix_len: u64 = records
                    .iter()
                    .map(fss_ledger::JournalRecord::framed_len)
                    .sum();
                let prefix = usize::try_from(prefix_len)
                    .ok()
                    .and_then(|len| self.effect_bytes.as_ref()?.get(..len))
                    .ok_or_else(not_committed)?;
                let journal = crate::durable_effect::replay_records(records).map_err(|error| {
                    corrupt(format!("durable effect journal replay failed: {error}"))
                })?;
                reader.files_read += 1;
                reader.bytes_read += prefix_len;
                (
                    ContentDigest::sha256(prefix),
                    journal.obligations().cloned().collect(),
                    journal.operations().cloned().collect(),
                )
            }
        };

        let mut family_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut completed_imports = Vec::new();
        let mut latest_evidence_time = TimestampNs::ZERO;
        // object id -> (generation -> (payload root, witnessed revision digest, commit sequence))
        let mut event_deltas: BTreeMap<String, BTreeMap<u64, (ContentDigest, ContentDigest, u64)>> =
            BTreeMap::new();
        let mut coverage_deltas: Vec<(ContentDigest, u64)> = Vec::new();
        let mut capsule_deltas: Vec<(ContentDigest, TimestampNs)> = Vec::new();
        let mut event_ledger_root = None;
        let mut evidence_ledger_root = None;
        let mut import_ledger_root = None;
        for (index, batch) in batches.iter().enumerate() {
            reader
                .admit()
                .map_err(|_| corrupt("retained read authority cancelled"))?;
            let record_root = self
                .ledger_positions
                .get(index)
                .map(|committed| committed.record_root)
                .ok_or_else(not_committed)?;
            if batch
                .deltas
                .iter()
                .any(|delta| delta.family == FAMILY_EVENT_REVISION)
            {
                event_ledger_root = Some(record_root);
            }
            if batch.deltas.iter().any(|delta| {
                delta.family == FAMILY_SENSOR_CAPSULE
                    || delta.family == FAMILY_COVERAGE_WITNESS
                    || delta.family == crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS
            }) {
                evidence_ledger_root = Some(record_root);
            }
            if batch
                .deltas
                .iter()
                .any(|delta| delta.family == FAMILY_FILE_IMPORT_MANIFEST)
            {
                import_ledger_root = Some(record_root);
            }
            for delta in &batch.deltas {
                if delta.family == FAMILY_COVERAGE_WITNESS {
                    coverage_deltas.push((delta.payload_digest, batch.new_anchor.commit_sequence));
                }
                if delta.family == FAMILY_SENSOR_CAPSULE {
                    capsule_deltas.push((delta.payload_digest, delta.validity.latest));
                }
                *family_counts.entry(delta.family.clone()).or_default() += 1;
                // Unbounded-horizon policy/configuration deltas (such as privacy mask policies
                // spanning `[0, i64::MAX]`) must not advance `latest_evidence_time` to year 2262.
                let unbounded_policy_horizon = TimestampNs(i128::from(i64::MAX));
                if delta.validity.latest < unbounded_policy_horizon
                    && delta.validity.latest > latest_evidence_time
                {
                    latest_evidence_time = delta.validity.latest;
                }
                if delta.family == FAMILY_FILE_IMPORT_MANIFEST {
                    completed_imports.push(delta.payload_digest);
                }
                if delta.family == FAMILY_EVENT_REVISION {
                    let witness = delta.witness_digest.ok_or_else(|| {
                        corrupt(format!(
                            "event_revision delta {} carries no revision witness",
                            delta.delta_id
                        ))
                    })?;
                    event_deltas
                        .entry(delta.object_id.as_str().to_owned())
                        .or_default()
                        .insert(
                            delta.new_generation,
                            (
                                delta.payload_digest,
                                witness,
                                batch.new_anchor.commit_sequence,
                            ),
                        );
                }
            }
        }

        let limits = &self.limits;
        if event_deltas.len() > limits.max_events.min(MAX_DEPLOYMENT_EVENTS) {
            return Err(DeploymentReadError::Unreadable {
                reason: format!(
                    "complete event catalogue has {} events, above the read bound {}",
                    event_deltas.len(),
                    limits.max_events.min(MAX_DEPLOYMENT_EVENTS)
                ),
            });
        }
        let objects = &self.objects;
        // Deletion records are read from the whole committed history: bytes a later deletion
        // removed are `deleted` at every position, never read back as corrupt or missing.
        let deletions = if crate::deletion::has_records(&self.batches) {
            crate::deletion::DeletionIndex::from_batches(&self.batches, |digest| {
                reader.read_object(objects, digest, limits.max_object_bytes)
            })?
        } else {
            crate::deletion::DeletionIndex::default()
        };
        let mut events = Vec::new();
        for (object_id, generations) in &event_deltas {
            if generations.len() > limits.max_revisions_per_event {
                return Err(corrupt(format!(
                    "{object_id} has {} committed revisions, above the read bound {}",
                    generations.len(),
                    limits.max_revisions_per_event
                )));
            }
            let mut revisions = Vec::new();
            let mut latest = None;
            let (bytes_before, reads_before) = (reader.bytes_read, reader.files_read);
            for (generation, (root_digest, witness, sequence)) in generations {
                let raw_root =
                    reader.read_object(objects, *root_digest, limits.max_object_bytes)?;
                if raw_root.starts_with(&PROJECTION_PAYLOAD_MAGIC) {
                    let payload =
                        ProjectionRecordPayload::decode_bytes(&raw_root).map_err(|error| {
                            corrupt(format!("{object_id}: v2 projection payload: {error}"))
                        })?;
                    let ProjectionRecordPayload::EventRevision(ev_rev) = payload else {
                        return Err(corrupt(format!(
                            "{object_id}: expected event_revision projection payload"
                        )));
                    };
                    if ev_rev.revision != *generation {
                        return Err(corrupt(format!(
                            "{object_id}: v2 revision {} does not match committed generation {generation}",
                            ev_rev.revision
                        )));
                    }
                    let revision = EventHypothesis {
                        schema: EventHypothesis::SCHEMA.to_owned(),
                        event_id: ev_rev.event_id,
                        revision: ev_rev.revision,
                        supersedes: ev_rev.supersedes,
                        state: ev_rev.state,
                        kind: ev_rev.kind,
                        interval: ev_rev.interval,
                        uncertainty_reason: None,
                        zone_ids: ev_rev.zones,
                        track_ids: Vec::new(),
                        probability: ProbabilityInterval {
                            lower: if ev_rev.corroborated { 0.5 } else { 0.0 },
                            upper: 1.0,
                            calibration_generation: None,
                        },
                        evidence: Vec::new(),
                        model_receipts: Vec::new(),
                        decision_path: DecisionPath {
                            policy_generation: ev_rev.event_root,
                            fingerprint: ev_rev.event_root,
                            abstained: !ev_rev.corroborated,
                            abstention_reason: (!ev_rev.corroborated)
                                .then(|| "v2_projection_held_or_uncorroborated".to_owned()),
                        },
                    };
                    latest = Some((*root_digest, *witness, *sequence));
                    revisions.push(revision);
                    continue;
                }
                let manifest = ObjectManifest::from_canonical_bytes(&raw_root)
                    .map_err(|error| corrupt(format!("{object_id}: manifest: {error}")))?;
                let payload = manifest
                    .metadata_digest()
                    .or_else(|| manifest.children().first().copied())
                    .ok_or_else(|| {
                        corrupt(format!("{object_id}: event manifest names no payload"))
                    })?;
                let revision = EventHypothesis::from_canonical_bytes(&reader.read_object(
                    objects,
                    payload,
                    limits.max_object_bytes,
                )?)
                .map_err(|error| corrupt(format!("{object_id}: event revision: {error}")))?;
                if revision.revision != *generation || revision.revision_digest() != *witness {
                    return Err(corrupt(format!(
                        "{object_id}: revision {generation} does not match its committed witness"
                    )));
                }
                latest = Some((*root_digest, *witness, *sequence));
                revisions.push(revision);
            }
            let (Some(event), Some((event_root, revision_digest, committed_sequence))) =
                (revisions.last().cloned(), latest)
            else {
                continue;
            };
            let tamper = fss_core::event::compute_sensor_tamper_status(revisions.iter(), None);
            events.push(RetainedEvent {
                event,
                revisions,
                event_root,
                revision_digest,
                committed_sequence,
                tamper,
                object_bytes: reader.bytes_read - bytes_before,
                object_reads: reader.files_read - reads_before,
            });
        }
        events.sort_by(|left, right| left.event.event_id.cmp(&right.event.event_id));

        let mut coverage = Vec::with_capacity(coverage_deltas.len());
        let mut source_records = Vec::new();
        let mut coverage_privacy_checks = 0;
        // Authority is evaluated at this requested prefix, not the later deployment head.
        // Every adoption and withdrawal receipt is verified before any old coverage is reused;
        // missing or damaged custody must never be interpreted as no invalidation.
        let mut calibration_read_error = None;
        let adoptions = retained_adoptions_from_batches(batches, |digest, maximum| {
            reader
                .read_object(objects, digest, maximum.min(limits.max_object_bytes))
                .map_err(|error| {
                    calibration_read_error = Some(error);
                    AdoptionError::InvalidRecord("calibration authority custody is unavailable")
                })
        })
        .map_err(|error| {
            calibration_read_error.unwrap_or_else(|| {
                corrupt(format!(
                    "calibration authority at requested prefix: {error}"
                ))
            })
        })?;
        let invalidated_calibrations = coverage::InvalidatedCalibrations::from_adoptions(adoptions);
        for (digest, committed_sequence) in coverage_deltas {
            if deletions.object(digest).is_some() {
                continue;
            }
            let bytes = reader.read_object(objects, digest, limits.max_object_bytes)?;
            if bytes.starts_with(&PROJECTION_PAYLOAD_MAGIC) {
                let payload = ProjectionRecordPayload::decode_bytes(&bytes).map_err(|error| {
                    corrupt(format!("v2 coverage projection payload {digest}: {error}"))
                })?;
                if !matches!(payload, ProjectionRecordPayload::CoverageWitness(_)) {
                    return Err(corrupt(format!(
                        "v2 coverage delta {digest} carries non-coverage projection payload"
                    )));
                }
                continue;
            }
            if SourceCoverageRecord::is_source_record(&bytes) {
                let record = SourceCoverageRecord::from_bytes(&bytes, digest).map_err(|error| {
                    corrupt(format!("source coverage record {digest}: {error}"))
                })?;
                source_records.push((record, digest, committed_sequence));
                continue;
            }
            let record = CoverageRecord::from_bytes(&bytes, digest)
                .map_err(|error| corrupt(format!("coverage record {digest}: {error}")))?;
            let privacy =
                coverage::privacy_at_basis(&record, batches, &mut coverage_privacy_checks)
                    .map_err(|error| {
                        corrupt(format!("coverage record {digest} privacy basis: {error}"))
                    })?;
            coverage.push(RetainedCoverage {
                calibration_invalidation: invalidated_calibrations.for_record(&record),
                record,
                payload_digest: digest,
                committed_sequence,
                privacy_policy_digest: privacy.map(|(digest, _)| digest),
                privacy_generation: privacy.map(|(_, generation)| generation),
            });
        }
        // The hydrated results of each rejected event's model receipts (fss-f8jls): the shared
        // rule requires them to analyse every frame of the record. A receipt that is deleted,
        // unreadable or not a mock model result stays unhydrated, so the rule refuses the
        // certification; it never fails the ordinary read. Metadata-only queries deliberately
        // skip this optional hydration: these are untyped event-supplied digests and can alias
        // raw source payloads. No analysis is therefore offered to the absence rule in that
        // mode, preserving unknown absence without silently acquiring media-read authority.
        let mut event_analyses: BTreeMap<String, Vec<MockModelResult>> = BTreeMap::new();
        if self.metadata_budget.is_none() && !source_records.is_empty() {
            for retained in &events {
                if retained.event.state != EventState::Rejected {
                    continue;
                }
                let mut hydrated = Vec::new();
                for receipt in &retained.event.model_receipts {
                    if deletions.object(*receipt).is_some() {
                        continue;
                    }
                    if let Ok(bytes) =
                        reader.read_object(objects, *receipt, limits.max_object_bytes)
                        && let Ok(result) = MockModelResult::from_retained_bytes(&bytes, *receipt)
                    {
                        hydrated.push(result);
                    }
                }
                event_analyses.insert(retained.event.event_id.as_str().to_owned(), hydrated);
            }
        }
        let analyses_of = |event: &EventHypothesis| -> &[MockModelResult] {
            event_analyses
                .get(event.event_id.as_str())
                .map_or(&[], Vec::as_slice)
        };
        // A stored witness certifies a rejected event's absence only under the shared rule
        // (fss-tch7u), evaluated against exactly this position's committed history.
        let mut retained_absences = BTreeMap::new();
        for retained in &events {
            for (record, _, _) in &source_records {
                if let Ok(absence) = verify_retained_coverage(
                    record,
                    Some(&retained.event),
                    analyses_of(&retained.event),
                    batches,
                    &anchor,
                ) {
                    retained_absences
                        .entry(retained.event.event_id.as_str().to_owned())
                        .or_insert(absence);
                }
            }
        }
        let source_coverage = source_records
            .into_iter()
            .map(|(record, payload_digest, committed_sequence)| {
                let citing = events.iter().find(|retained| {
                    retained.event.state == EventState::Rejected
                        && retained
                            .event
                            .evidence
                            .iter()
                            .any(|edge| edge.digest == record.witness_object())
                });
                let verdict = verify_retained_coverage(
                    &record,
                    citing.map(|retained| &retained.event),
                    citing.map_or(&[], |retained| analyses_of(&retained.event)),
                    batches,
                    &anchor,
                );
                RetainedSourceCoverage {
                    record,
                    payload_digest,
                    committed_sequence,
                    verdict,
                }
            })
            .collect();
        // The newest evidence of each sensor, read only where it could postdate an analysis.
        let mut sensor_newest_evidence: BTreeMap<String, TimestampNs> = BTreeMap::new();
        let mut coverage_evidence_unattributed = false;
        if let Some(earliest) = coverage.iter().map(|c| c.record.analysed.latest).min() {
            let newer: Vec<ContentDigest> = capsule_deltas
                .iter()
                .filter(|(digest, latest)| {
                    *latest > earliest && deletions.object(*digest).is_none()
                })
                .map(|(digest, _)| *digest)
                .collect();
            if newer.len() > MAX_COVERAGE_CAPSULE_READS {
                coverage_evidence_unattributed = true;
            } else {
                for digest in newer {
                    let bytes = reader.read_object(objects, digest, limits.max_object_bytes)?;
                    let capsule = fss_core::SensorCapsule::from_canonical_bytes(&bytes)
                        .map_err(|error| corrupt(format!("sensor capsule {digest}: {error}")))?;
                    let entry = sensor_newest_evidence
                        .entry(capsule.sensor_id.as_str().to_owned())
                        .or_insert(capsule.capture.latest);
                    if capsule.capture.latest > *entry {
                        *entry = capsule.capture.latest;
                    }
                }
            }
        }
        let historical_health = historical_health::read_inventory(
            batches,
            &deletions,
            limits.max_object_bytes,
            |digest, max| reader.read_object(objects, digest, max),
        )?;

        let has_v2_fspp_liveness = batches.iter().any(|batch| {
            batch.deltas.iter().any(|delta| {
                delta.family == crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS
                    && !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::discovery::retained_liveness::LIVENESS_OBJECT_PREFIX)
            })
        });
        let sensor_liveness = if has_v2_fspp_liveness {
            Vec::new()
        } else {
            crate::discovery::retained_liveness::read_liveness_inventory(batches, |digest, max| {
                if deletions.object(digest).is_some() {
                    return Err(crate::discovery::retained_liveness::LivenessError::Corrupt);
                }
                reader
                    .read_object(objects, digest, max.min(limits.max_object_bytes))
                    .map_err(|_| crate::discovery::retained_liveness::LivenessError::Corrupt)
            })
            .map_err(|error| corrupt(format!("retained sensor liveness: {error}")))?
        };

        reader
            .admit()
            .map_err(|_| corrupt("retained read authority cancelled"))?;
        Ok(DeploymentSnapshot {
            site_lineage: self.site_lineage.clone(),
            doctor_verdict: self.doctor_verdict,
            doctor_inspected: self.doctor_inspected,
            position,
            anchor,
            ledger_root,
            batch_count,
            event_ledger_root,
            evidence_ledger_root,
            import_ledger_root,
            ledger_tail_uncommitted: self.ledger_tail_uncommitted,
            family_counts,
            effect_journal_present: effect_count.is_some(),
            effect_journal_digest,
            effect_journal_root,
            effect_tail_uncommitted: effect_count.is_some() && self.effect_tail_uncommitted,
            obligations,
            operations,
            events,
            historical_health,
            sensor_liveness,
            coverage,
            source_coverage,
            retained_absences,
            sensor_newest_evidence,
            coverage_evidence_unattributed,
            latest_evidence_time,
            completed_imports: completed_imports
                .into_iter()
                .filter(|digest| deletions.object(*digest).is_none())
                .collect(),
            deletions_committed: batches
                .iter()
                .flat_map(|batch| &batch.deltas)
                .filter(|delta| delta.family == crate::reference_deployment::FAMILY_DELETION_RECORD)
                .count(),
            deletions,
            files_read: reader.files_read,
            bytes_read: reader.bytes_read,
        })
    }
}
