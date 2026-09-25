#![forbid(unsafe_code)]
//! Per-zone coverage of an orientation from retained `coverage_witness` records.
//!
//! Every (sensor, zone scope) named by a retained record, and every zone a published event names,
//! is assessed at the snapshot:
//!
//! * `stale`: no record of the zone's current pipeline generation (the generation of its most
//!   recently committed record) analysed the sensor's newest retained evidence, or the sensor's
//!   newest evidence could not be attributed within the read bound. Records of another pipeline
//!   generation are never reused and are named.
//! * `not_observable`: the freshest current record has no witness for the zone (unknown capture
//!   time, zone outside the frame, capture unreliable after a source gap, too short, ...), or the
//!   current witnesses leave a hole between the first witness and the freshest one that is not
//!   exactly a zone-entry frame whose event is published. A zone named only by an event has no
//!   coverage at all.
//! * `covered`: the current witnesses form one contiguous window (overlapping bounds, or holes
//!   that are exactly zone-entry frames of published events) ending with the freshest record.
//!
//! The declared window of a covered zone is the witnesses' certain hull; everything outside it
//! (warm-up, confirmation latency, earlier gaps) is named, never folded in. Completeness is
//! complete only when every assessed zone is covered.
//!
//! A ground zone with geometric visibility (fss-2h5zq.53) carries it into the assessment: an
//! `occluded` or `outside_frustum` zone is not observable with that reason and its sample counts,
//! and a covered zone whose occlusion was never tested is declared frustum-only
//! (`occlusion_unknown`) in its domain, its cell statement and its named gaps. Tolerant-decode
//! gaps are named `decode_refused` with their error id; a witness never spans one.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CaptureInterval, ContentDigest, LedgerAnchor, TimestampNs};

use crate::ingest::ground_visibility::ZoneVisibility;
use crate::ingest::recorded_coverage::{
    CoverageRecord, UncoveredReason, ZoneCoverage, ZoneWitness,
};

/// Sensor-capsule payloads read to attribute the newest evidence of each covered sensor; more is
/// reported as unattributed (every zone stale), never skipped.
pub const MAX_COVERAGE_CAPSULE_READS: usize = 4096;

/// One committed coverage record read back from the spool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedCoverage {
    /// Decoded, validated record.
    pub record: CoverageRecord,
    /// Committed payload digest.
    pub payload_digest: ContentDigest,
    /// Commit sequence that retained it.
    pub committed_sequence: u64,
}

/// Coverage state of one zone at the snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneCoverageState {
    /// One contiguous window of current witnesses through the newest analysed evidence.
    Covered,
    /// No usable witness, or a hole in the window.
    NotObservable,
    /// Newer evidence than any current record analysed, or only another pipeline generation.
    Stale,
}

impl ZoneCoverageState {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::NotObservable => "not_observable",
            Self::Stale => "stale",
        }
    }
}

/// Assessment of one zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneAssessment {
    /// Sensor, or `None` for a zone named only by a published event.
    pub sensor_id: Option<String>,
    /// Zone scope (`zone:<id>`, `ground-zone:<id>`, or `event-zone:<id>`).
    pub scope: String,
    /// Zone identifier.
    pub zone_id: String,
    /// State.
    pub state: ZoneCoverageState,
    /// Certain covered window (covered zones only).
    pub window: Option<CaptureInterval>,
    /// Current pipeline generation.
    pub pipeline_generation: Option<ContentDigest>,
    /// Witness digests the window rests on (covered zones only), in window order.
    pub witnesses: Vec<ContentDigest>,
    /// Basis anchor of the zone's most recent record (the stale basis).
    pub basis: Option<LedgerAnchor>,
    /// Named gaps and exclusions.
    pub gaps: Vec<String>,
    /// Geometric visibility of a ground zone in its most recent record, when geometry was used.
    pub visibility: Option<ZoneVisibility>,
}

impl ZoneAssessment {
    /// Stable claim identity of the zone's coverage cell.
    #[must_use]
    pub fn claim_id(&self) -> String {
        let sensor = self.sensor_id.as_deref().map_or_else(
            || "unattributed".to_owned(),
            |sensor| {
                ContentDigest::sha256(sensor.as_bytes())
                    .to_text()
                    .split_once(':')
                    .map_or_else(String::new, |(_, hex)| hex.chars().take(16).collect())
            },
        );
        format!("claim:coverage:{sensor}:{}", self.scope)
    }

    /// Whether a covered claim over this zone is frustum-only (occlusion never tested).
    #[must_use]
    pub fn frustum_only(&self) -> bool {
        self.visibility
            .as_ref()
            .is_some_and(ZoneVisibility::frustum_only)
    }

    /// Human label `sensor scope`.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.sensor_id {
            Some(sensor) => format!("{sensor} {}", self.scope),
            None => self.scope.clone(),
        }
    }
}

/// Coverage of every objective zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageAssessment {
    /// Zones in (sensor, scope) order; event-only zones last.
    pub zones: Vec<ZoneAssessment>,
    /// Retained records read.
    pub record_count: usize,
}

impl CoverageAssessment {
    /// Whether every assessed zone is covered (and at least one exists).
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.zones.is_empty()
            && self
                .zones
                .iter()
                .all(|zone| zone.state == ZoneCoverageState::Covered)
    }

    /// Every witness digest the covered windows rest on.
    #[must_use]
    pub fn witness_digests(&self) -> Vec<ContentDigest> {
        let set: BTreeSet<ContentDigest> = self
            .zones
            .iter()
            .flat_map(|zone| zone.witnesses.iter().copied())
            .collect();
        set.into_iter().collect()
    }

    /// Declared domains of the covered zones (`sensor scope [a, b] ns`).
    #[must_use]
    pub fn declared_domains(&self) -> Vec<String> {
        self.zones
            .iter()
            .filter_map(|zone| {
                zone.window.map(|window| {
                    format!(
                        "{} [{}, {}] ns{}",
                        zone.label(),
                        window.earliest.0,
                        window.latest.0,
                        if zone.frustum_only() {
                            " (frustum-only: occlusion_unknown)"
                        } else {
                            ""
                        }
                    )
                })
            })
            .collect()
    }

    /// Every named gap.
    #[must_use]
    pub fn gaps(&self) -> Vec<String> {
        self.zones
            .iter()
            .flat_map(|zone| zone.gaps.iter().cloned())
            .collect()
    }
}

fn short(digest: ContentDigest) -> String {
    let text = digest.to_text();
    text.split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.chars().take(16).collect())
}

/// One named gap per uncovered interval of `zone` in `record`.
fn describe(
    label: &str,
    record: &CoverageRecord,
    zone: &ZoneCoverage,
    published: &BTreeSet<String>,
) -> Vec<String> {
    zone.uncovered
        .iter()
        .map(|gap| {
            let capture = gap.capture.map_or_else(
                || "capture unbounded".to_owned(),
                |capture| format!("[{}, {}] ns", capture.earliest.0, capture.latest.0),
            );
            let reason = match &gap.reason {
                UncoveredReason::ZoneEntry {
                    candidate,
                    event_id,
                } => match event_id {
                    Some(event) if published.contains(event) => {
                        format!(
                            "zone_entry of {} (event {event} published)",
                            short(*candidate)
                        )
                    }
                    Some(event) => format!(
                        "zone_entry of {} (event {event} not published)",
                        short(*candidate)
                    ),
                    None => format!("zone_entry of {} (no event)", short(*candidate)),
                },
                UncoveredReason::DecodeRefused { error_id } => format!("decode_refused {error_id}"),
                UncoveredReason::Occluded | UncoveredReason::OutsideFrustum => {
                    match &zone.visibility {
                        Some(visibility) => {
                            format!("{}: {}", gap.reason.as_str(), visibility.summary())
                        }
                        None => gap.reason.as_str().to_owned(),
                    }
                }
                other => other.as_str().to_owned(),
            };
            format!(
                "{label}, import {}, segments {}..{} {capture}: not covered ({reason}).",
                short(record.import_identity),
                gap.first_segment,
                gap.last_segment
            )
        })
        .collect()
}

/// Whether every segment strictly between `before` and `after` of one record's zone is a
/// zone-entry frame whose event is published (the hole is an observed, published event).
fn accounted_hole(
    zone: &ZoneCoverage,
    before: &ZoneWitness,
    after: &ZoneWitness,
    published: &BTreeSet<String>,
) -> bool {
    let first = before.last_segment + 1;
    let last = match after.first_segment.checked_sub(1) {
        Some(last) if last >= first => last,
        _ => return false,
    };
    (first..=last).all(|segment| {
        zone.uncovered.iter().any(|gap| {
            gap.first_segment <= segment
                && segment <= gap.last_segment
                && matches!(
                    &gap.reason,
                    UncoveredReason::ZoneEntry { event_id: Some(event), .. }
                        if published.contains(event)
                )
        })
    })
}

/// Assesses every objective zone; `None` when no coverage record is retained.
pub(super) fn assess(
    records: &[RetainedCoverage],
    newest_evidence: &BTreeMap<String, TimestampNs>,
    evidence_unattributed: bool,
    event_zones: &BTreeSet<String>,
    published: &BTreeSet<String>,
) -> Option<CoverageAssessment> {
    if records.is_empty() {
        return None;
    }
    // (sensor, scope) -> indices of records naming it, in commit order.
    let mut scopes: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (index, retained) in records.iter().enumerate() {
        for zone in &retained.record.zones {
            scopes
                .entry((retained.record.sensor_id.clone(), zone.scope.clone()))
                .or_default()
                .push(index);
        }
    }
    let zone_of = |index: usize, scope: &str| -> Option<&ZoneCoverage> {
        records
            .get(index)?
            .record
            .zones
            .iter()
            .find(|zone| zone.scope == scope)
    };
    let mut zones = Vec::new();
    for ((sensor, scope), mut indices) in scopes {
        indices.sort_by_key(|index| (records[*index].committed_sequence, *index));
        let Some(latest) = indices.last().copied() else {
            continue;
        };
        let Some(latest_zone) = zone_of(latest, &scope) else {
            continue;
        };
        let generation = latest_zone.pipeline_generation;
        let zone_id = latest_zone.zone_id.clone();
        let label = format!("{sensor} {scope}");
        let mut gaps = Vec::new();
        let current: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|index| {
                zone_of(*index, &scope).is_some_and(|zone| zone.pipeline_generation == generation)
            })
            .collect();
        let other = indices.len() - current.len();
        if other > 0 {
            gaps.push(format!(
                "{label}: {other} retained record(s) of another pipeline generation are stale \
                 and not reused (current generation {generation})."
            ));
        }
        let basis = Some(records[latest].record.basis.clone());
        let newest = newest_evidence.get(&sensor).copied();
        let fresh: Vec<usize> = current
            .iter()
            .copied()
            .filter(|index| {
                !evidence_unattributed
                    && newest.is_none_or(|newest| records[*index].record.analysed.latest >= newest)
            })
            .collect();
        let mut assessment = ZoneAssessment {
            sensor_id: Some(sensor.clone()),
            scope: scope.clone(),
            zone_id,
            state: ZoneCoverageState::Stale,
            window: None,
            pipeline_generation: Some(generation),
            witnesses: Vec::new(),
            basis,
            gaps,
            visibility: latest_zone.visibility.clone(),
        };
        let Some(freshest) = fresh.last().copied() else {
            let analysed = current
                .iter()
                .map(|index| records[*index].record.analysed.latest.0)
                .max()
                .unwrap_or_default();
            assessment.gaps.push(if evidence_unattributed {
                format!(
                    "{label}: stale: newer retained evidence could not be attributed to sensors \
                     within {MAX_COVERAGE_CAPSULE_READS} capsule reads."
                )
            } else {
                format!(
                    "{label}: stale: retained evidence captured through {} ns is newer than any \
                     current coverage analysis (analysed through {analysed} ns).",
                    newest.map_or(0, |newest| newest.0)
                )
            });
            zones.push(assessment);
            continue;
        };
        for index in &current {
            if let Some(zone) = zone_of(*index, &scope) {
                assessment
                    .gaps
                    .extend(describe(&label, &records[*index].record, zone, published));
            }
        }
        let freshest_zone = zone_of(freshest, &scope);
        let Some(last_witness) = freshest_zone.and_then(|zone| zone.witnesses.last()) else {
            assessment.state = ZoneCoverageState::NotObservable;
            assessment.gaps.push(format!(
                "{label}: not observable: the freshest coverage analysis (import {}) retains no \
                 witness for this zone.",
                short(records[freshest].record.import_identity)
            ));
            zones.push(assessment);
            continue;
        };
        // Every current witness, ordered by its certain window.
        let mut witnesses: Vec<(usize, &ZoneCoverage, &ZoneWitness)> = Vec::new();
        for index in &current {
            if let Some(zone) = zone_of(*index, &scope) {
                witnesses.extend(zone.witnesses.iter().map(|witness| (*index, zone, witness)));
            }
        }
        witnesses.sort_by_key(|(index, _, witness)| {
            (
                witness.covered.earliest,
                witness.covered.latest,
                records[*index].committed_sequence,
                witness.first_segment,
            )
        });
        let mut windows: Vec<(CaptureInterval, Vec<ContentDigest>)> = Vec::new();
        let mut previous: Option<(usize, &ZoneCoverage, &ZoneWitness)> = None;
        for (index, zone, witness) in witnesses {
            let digest = witness.witness.witness_digest();
            let joins = match (windows.last(), previous) {
                (Some((window, _)), Some((before_index, before_zone, before))) => {
                    witness.covered.earliest <= window.latest
                        || (before_index == index
                            && accounted_hole(before_zone, before, witness, published))
                }
                _ => false,
            };
            match windows.last_mut() {
                Some((window, digests)) if joins => {
                    window.latest = window.latest.max(witness.covered.latest);
                    digests.push(digest);
                }
                _ => windows.push((witness.covered, vec![digest])),
            }
            previous = Some((index, zone, witness));
        }
        let ends_fresh = windows
            .last()
            .is_some_and(|(window, _)| window.latest >= last_witness.covered.latest);
        if windows.len() == 1 && ends_fresh {
            if let Some((window, digests)) = windows.pop() {
                assessment.state = ZoneCoverageState::Covered;
                assessment.window = Some(window);
                assessment.witnesses = digests;
                if let Some(visibility) = assessment
                    .visibility
                    .as_ref()
                    .filter(|visibility| visibility.frustum_only())
                {
                    assessment.gaps.push(format!(
                        "{label}: covered frustum-only: occlusion_unknown ({}); an occluder in \
                         view could hide an entry.",
                        visibility.summary()
                    ));
                }
            }
        } else {
            assessment.state = ZoneCoverageState::NotObservable;
            for pair in windows.windows(2) {
                assessment.gaps.push(format!(
                    "{label}: not observable between {} ns and {} ns: no current witness covers \
                     the interval.",
                    pair[0].0.latest.0, pair[1].0.earliest.0
                ));
            }
        }
        zones.push(assessment);
    }
    let covered_ids: BTreeSet<String> = zones.iter().map(|zone| zone.zone_id.clone()).collect();
    for zone_id in event_zones.difference(&covered_ids) {
        zones.push(ZoneAssessment {
            sensor_id: None,
            scope: format!("event-zone:{zone_id}"),
            zone_id: zone_id.clone(),
            state: ZoneCoverageState::NotObservable,
            window: None,
            pipeline_generation: None,
            witnesses: Vec::new(),
            basis: None,
            gaps: vec![format!(
                "event-zone:{zone_id}: not observable: a published event names this zone but no \
                 coverage record covers it."
            )],
            visibility: None,
        });
    }
    Some(CoverageAssessment {
        zones,
        record_count: records.len(),
    })
}
