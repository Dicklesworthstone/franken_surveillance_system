#![forbid(unsafe_code)]
//! Six-pane [`super::live_model::LiveCockpitFrame`] projection builder uniting live daemon
//! telemetry with lock-free read-only MVCC/v1 store state.
//!
//! Semantic plane: `"projection"`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use fss_core::{EventState, ResourcePressure};
use fss_daemon::DaemonRuntimeDescriptor;
use fss_ipc::{ActiveScrubStatus, CameraLiveStatus, LiveDaemonStatus, RingWatermarkStatus};
use fss_projection_store::{
    CoverageStatus, DoctorScrubReceipt, EventQueryFilter, MAX_VERIFIED_FRACTION_PPM, OrientSummary,
    ProjectedCoverageState, ProjectedEventSummary, ProjectionSnapshot, ScrubVerdict,
    SensorLivenessStatus,
};

use super::live_model::{
    LIVE_FRAME_SCHEMA, LiveAffordanceItem, LiveAgentActivityLog, LiveAttentionItem,
    LiveCameraHealth, LiveCockpitFrame, LiveDaemonInfo, LiveDeltaEntry, LiveEventRow,
    LiveObligationsHolds, LiveSituationFrontier, LiveStorageRingTelemetry,
    PrivacyMaskedEventHandle, build_operator_workflows, format_mb, parse_delta_kv,
};
use super::live_readonly_store::{PackDiskScan, ReadonlyStoreState, load_readonly_store};

const MAX_FRAME_EVENTS: usize = 64;

fn build_cameras_from_mvcc(
    live_status: Option<&LiveDaemonStatus>,
    snapshot: &ProjectionSnapshot,
    recent_deltas: &[LiveDeltaEntry],
) -> Vec<LiveCameraHealth> {
    let mut cov_by_sensor: BTreeMap<String, Vec<ProjectedCoverageState>> = BTreeMap::new();
    for cov in snapshot.query_coverage(None, None) {
        cov_by_sensor
            .entry(cov.sensor_id.as_str().to_owned())
            .or_default()
            .push(cov);
    }
    let mut dropped_by_sensor: BTreeMap<String, u64> = BTreeMap::new();
    for delta in recent_deltas {
        if let (Some(sensor), Some(dropped_str)) = (
            parse_delta_kv(&delta.summary, "sensor"),
            parse_delta_kv(&delta.summary, "dropped"),
        ) && let Ok(dropped) = dropped_str.parse::<u64>()
        {
            let entry = dropped_by_sensor.entry(sensor.to_owned()).or_insert(0);
            *entry = entry.saturating_add(dropped);
        }
    }
    let mut live_by_id: BTreeMap<String, &CameraLiveStatus> = BTreeMap::new();
    if let Some(status) = live_status {
        for cam in &status.cameras {
            live_by_id.insert(cam.camera_id.clone(), cam);
        }
    }
    let mut all_ids: BTreeSet<String> = live_by_id.keys().cloned().collect();
    all_ids.extend(cov_by_sensor.keys().cloned());

    let mut rows = Vec::with_capacity(all_ids.len());
    for cam_id in all_ids {
        let live_cam = live_by_id.get(&cam_id).copied();
        let liveness = fss_core::SensorId::parse(&cam_id)
            .ok()
            .and_then(|sid| snapshot.get_sensor_liveness(&sid));
        let (coverage_status, active_gaps, zones) = match cov_by_sensor.get(&cam_id) {
            Some(list) if !list.is_empty() => {
                let (mut worst, mut gaps, mut zone_list) =
                    (CoverageStatus::Covered, 0u32, Vec::new());
                for c in list {
                    gaps = gaps.saturating_add(c.active_gaps);
                    zone_list.push(c.zone_id.clone());
                    if c.status == CoverageStatus::NotObservable {
                        worst = CoverageStatus::NotObservable;
                    } else if c.status == CoverageStatus::Stale && worst == CoverageStatus::Covered
                    {
                        worst = CoverageStatus::Stale;
                    }
                }
                zone_list.sort();
                zone_list.dedup();
                (worst.as_str().to_owned(), gaps, zone_list)
            }
            _ => ("unknown".to_owned(), 0, Vec::new()),
        };
        let running = live_cam.is_some_and(|c| c.running);
        let state = if let Some(c) = live_cam {
            if c.running && coverage_status == "covered" {
                "streaming"
            } else if c.running {
                "degraded"
            } else {
                "offline"
            }
        } else if let Some(l) = liveness {
            match l.state {
                SensorLivenessStatus::Online => "online_retained",
                SensorLivenessStatus::Degraded => "degraded",
                SensorLivenessStatus::Offline => "offline",
                SensorLivenessStatus::Unknown => "unknown",
            }
        } else {
            "unknown"
        };
        let fps = live_cam.map_or(0, |c| c.fps_milli);
        rows.push(LiveCameraHealth {
            camera_id: cam_id.clone(),
            state: state.to_owned(),
            running,
            fps_in_milli: fps,
            fps_decode_milli: fps,
            reconnect_count: live_cam.map_or(0, |c| c.reconnect_count),
            queue_depth: live_cam.map_or(0, |c| c.queue_depth),
            dropped_frames: dropped_by_sensor.get(&cam_id).copied().unwrap_or(0),
            frames_ingested: live_cam.map_or(0, |c| c.frames_ingested),
            coverage_status,
            active_gaps,
            zones,
        });
    }
    rows
}

fn build_events_from_mvcc(
    root: &Path,
    snapshot: &ProjectionSnapshot,
    privacy_masks: usize,
    recent_deltas: &[LiveDeltaEntry],
) -> Vec<LiveEventRow> {
    let page = snapshot.query_events(&EventQueryFilter::default(), MAX_FRAME_EVENTS);
    let mut delta_hints: BTreeMap<String, &LiveDeltaEntry> = BTreeMap::new();
    for d in recent_deltas {
        if let Some(ev_id) = parse_delta_kv(&d.summary, "event") {
            delta_hints.insert(ev_id.to_owned(), d);
        }
    }
    let root_str = root.to_string_lossy();
    let mut rows: Vec<LiveEventRow> = page
        .entries
        .iter()
        .map(|ev: &ProjectedEventSummary| {
            let hint = delta_hints.get(ev.event_id.as_str()).copied();
            let shared_held = hint.is_some_and(|d| d.summary.contains("shared_failure_domain_held"));
            let clusters = hint
                .and_then(|d| parse_delta_kv(&d.summary, "clusters"))
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or_else(|| {
                    if ev.corroborated || ev.state == EventState::Corroborated {
                        u32::try_from(ev.sensor_ids.len().max(2)).unwrap_or(2)
                    } else if shared_held {
                        1
                    } else {
                        u32::try_from(ev.sensor_ids.len()).unwrap_or(0)
                    }
                });
            let epistemic = if ev.corroborated || ev.state == EventState::Corroborated {
                "Corroborated"
            } else if shared_held {
                "SharedFailureDomainHeld"
            } else if ev.state == EventState::Indeterminate {
                "Indeterminate"
            } else {
                "Observed"
            };
            let fusion_summary = if let Some(d) = hint {
                if d.summary.contains("shared_failure_domain_held") {
                    let doms = parse_delta_kv(&d.summary, "domains").unwrap_or("shared");
                    format!("held(shared_failure_domain={doms}; clusters=1)")
                } else if d.summary.contains("corroborated") {
                    format!("corroborated(independent_clusters={clusters}; milliban_llr=positive)")
                } else {
                    d.summary.clone()
                }
            } else if ev.corroborated {
                format!("corroborated(independent_clusters={clusters})")
            } else {
                "uncorroborated_or_held(single_cluster_or_uncalibrated)".to_owned()
            };
            let rev_digest = ev.revision_digest.to_text();
            LiveEventRow {
                event_id: ev.event_id.as_str().to_owned(),
                revision: ev.revision,
                kind: ev.kind.as_str().to_owned(),
                state: ev.state.as_str().to_owned(),
                epistemic_classification: epistemic.to_owned(),
                failure_domain_clusters: clusters,
                fusion_summary,
                zones: ev.zones.clone(),
                sensors: ev.sensor_ids.iter().map(|s| s.as_str().to_owned()).collect(),
                tamper_open: ev.tamper_open,
                committed_sequence: ev.committed_sequence,
                privacy_masked_handle: PrivacyMaskedEventHandle {
                    handle_id: format!("h0:event:{}:rev{}", ev.event_id.as_str(), ev.revision),
                    event_root: ev.event_root.to_text(),
                    revision_digest: rev_digest.clone(),
                    hydration_level: "H0".to_owned(),
                    privacy_masks_active: privacy_masks,
                    raw_media_exposed: false,
                    inspect_command: format!(
                        "fss query --target evidence-hydration --json --root {root_str} --session <SESSION> --generation 1 --event-id {} --revision-digest {rev_digest} --anchor <ANCHOR> --level H0",
                        ev.event_id.as_str()
                    ),
                },
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.committed_sequence
            .cmp(&a.committed_sequence)
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    rows
}

fn derive_scrub_metrics(
    head_seq: u64,
    orient: &OrientSummary,
    live_status: Option<&LiveDaemonStatus>,
    sealed_pack_count: u64,
) -> (String, u64, u64, u32, u64) {
    let from_receipt = |r: &DoctorScrubReceipt| -> (String, u64, u64, u32, u64) {
        let behind = head_seq.saturating_sub(r.anchor.commit_sequence);
        let label = match r.verdict {
            ScrubVerdict::Failed => "Failed",
            ScrubVerdict::Degraded => "Degraded",
            ScrubVerdict::Clean => {
                if behind == 0 && r.verified_fraction_ppm == MAX_VERIFIED_FRACTION_PPM {
                    "Clean"
                } else {
                    "Stale"
                }
            }
        };
        (
            label.to_owned(),
            r.verified_objects,
            r.verified_packs,
            r.verified_fraction_ppm,
            behind,
        )
    };
    if let Some(status) = live_status {
        match &status.scrub {
            ActiveScrubStatus::Running {
                checked_objects, ..
            } => {
                return (
                    "Running".to_owned(),
                    *checked_objects,
                    sealed_pack_count,
                    0,
                    0,
                );
            }
            ActiveScrubStatus::Failed { .. } => return ("Failed".to_owned(), 0, 0, 0, 0),
            ActiveScrubStatus::Completed {
                checked_objects,
                anomalies_found,
            } => {
                if *anomalies_found > 0 {
                    return (
                        "Degraded".to_owned(),
                        *checked_objects,
                        sealed_pack_count,
                        0,
                        0,
                    );
                }
                if let Some(ref r) = orient.scrub_receipt {
                    let (lbl, objs, packs, ppm, behind) = from_receipt(r);
                    return (lbl, objs.max(*checked_objects), packs, ppm, behind);
                }
                return (
                    "Clean".to_owned(),
                    *checked_objects,
                    sealed_pack_count,
                    MAX_VERIFIED_FRACTION_PPM,
                    0,
                );
            }
            ActiveScrubStatus::Idle => {}
        }
    }
    orient
        .scrub_receipt
        .as_ref()
        .map_or_else(|| ("NeverScrubbed".to_owned(), 0, 0, 0, 0), from_receipt)
}

fn build_situation_and_storage(
    orient: &OrientSummary,
    state_digest: String,
    live_status: Option<&LiveDaemonStatus>,
    packs: &PackDiskScan,
    events: &[LiveEventRow],
    daemon_live: bool,
) -> (LiveSituationFrontier, LiveStorageRingTelemetry) {
    let head_seq = live_status.map_or(orient.anchor.commit_sequence, |s| s.head_commit_sequence);
    let authority_root = live_status
        .map(|s| s.state_root.to_text())
        .unwrap_or_else(|| orient.anchor.authority_root.to_text());
    let history_root = live_status
        .map(|s| s.history_root.to_text())
        .unwrap_or_else(|| orient.anchor.history_root.to_text());

    let ring: Option<&RingWatermarkStatus> = live_status.and_then(|s| s.ring.as_ref());
    let ring_used = ring.map_or(packs.on_disk_pack_bytes, |r| r.used_bytes);
    let ring_cap = ring.map_or(0, |r| r.capacity_bytes);
    let watermark_pct = ring.map_or(0, |r| r.watermark_percent);
    let pressure = if watermark_pct >= 95 {
        ResourcePressure::Critical
    } else if watermark_pct >= 75 {
        ResourcePressure::Elevated
    } else {
        ResourcePressure::Nominal
    };
    let pressure_str = match pressure {
        ResourcePressure::Nominal => "Nominal",
        ResourcePressure::Elevated => "Elevated",
        ResourcePressure::Constrained => "Constrained",
        ResourcePressure::Critical => "Critical",
    };
    let (scrubber_status, verified_objects, verified_packs, verified_ppm, behind_commits) =
        derive_scrub_metrics(head_seq, orient, live_status, packs.sealed_pack_count);

    let has_corroborated = events
        .iter()
        .any(|e| e.epistemic_classification == "Corroborated");
    let has_held = events.iter().any(|e| {
        e.epistemic_classification == "SharedFailureDomainHeld"
            || e.epistemic_classification == "Indeterminate"
    });
    let epistemic_state = if orient.indeterminate_effects > 0 || orient.not_observable_zones > 0 {
        "indeterminate"
    } else if has_corroborated {
        "corroborated"
    } else if orient.total_events > 0 || orient.covered_zones > 0 {
        "observed"
    } else {
        "unknown"
    };

    let mut attention = Vec::new();
    if pressure == ResourcePressure::Critical {
        attention.push(LiveAttentionItem {
            priority: "critical".to_owned(),
            category: "storage_pressure".to_owned(),
            summary: format!("Storage ring watermark at {watermark_pct}% (Critical)."),
        });
    }
    if orient.indeterminate_effects > 0 {
        attention.push(LiveAttentionItem {
            priority: "critical".to_owned(),
            category: "indeterminate_effect".to_owned(),
            summary: format!(
                "{} unresolved indeterminate effect(s) require reconciliation.",
                orient.indeterminate_effects
            ),
        });
    }
    if has_corroborated {
        let count = events
            .iter()
            .filter(|e| e.epistemic_classification == "Corroborated")
            .count();
        attention.push(LiveAttentionItem {
            priority: "high".to_owned(),
            category: "corroborated_event".to_owned(),
            summary: format!("{count} multi-cluster corroborated event(s) eligible for preview->approve alert planning."),
        });
    }
    if orient.not_observable_zones > 0 {
        attention.push(LiveAttentionItem {
            priority: "high".to_owned(),
            category: "coverage_gap".to_owned(),
            summary: format!(
                "{} zone(s) NotObservable; silence is not evidence of absence.",
                orient.not_observable_zones
            ),
        });
    }
    if has_held {
        attention.push(LiveAttentionItem {
            priority: "normal".to_owned(),
            category: "shared_failure_domain_held".to_owned(),
            summary: "Events held as Indeterminate/SharedFailureDomainHeld; independent corroboration required.".to_owned(),
        });
    }
    if !daemon_live {
        attention.push(LiveAttentionItem {
            priority: "normal".to_owned(),
            category: "daemon_offline_fallback".to_owned(),
            summary: "fss-daemon offline; displaying read-only MVCC projection fallback."
                .to_owned(),
        });
    }
    if scrubber_status == "NeverScrubbed" || scrubber_status == "Stale" {
        attention.push(LiveAttentionItem {
            priority: "normal".to_owned(),
            category: "scrub_status".to_owned(),
            summary: format!("Storage integrity scrub status is {scrubber_status}."),
        });
    }

    let mut affordances = vec![
        LiveAffordanceItem {
            affordance_id: "affordance:orient:query".to_owned(),
            classification: "robust".to_owned(),
            requires_approval: false,
            summary: "Query bounded committed event/footage records read-only (AOP-005)."
                .to_owned(),
        },
        LiveAffordanceItem {
            affordance_id: "affordance:orient:follow".to_owned(),
            classification: "robust".to_owned(),
            requires_approval: false,
            summary: "Follow meaningful deltas since current authority anchor (AOP-004)."
                .to_owned(),
        },
    ];
    if has_corroborated {
        affordances.push(LiveAffordanceItem {
            affordance_id: "affordance:orient:plan".to_owned(),
            classification: "conditional".to_owned(),
            requires_approval: true,
            summary: "Preview witnessed ControlPlan for corroborated event; requires approval_digest (AOP-007/008).".to_owned(),
        });
    }
    if has_held || orient.not_observable_zones > 0 || orient.stale_zones > 0 {
        affordances.push(LiveAffordanceItem {
            affordance_id: "affordance:orient:investigate".to_owned(),
            classification: "information_gathering".to_owned(),
            requires_approval: false,
            summary:
                "Open or inspect an InvestigationCase for unresolved hypotheses or gaps (AOP-006)."
                    .to_owned(),
        });
    }
    affordances.push(LiveAffordanceItem {
        affordance_id: "affordance:orient:hold".to_owned(),
        classification: "conditional".to_owned(),
        requires_approval: true,
        summary: "Preview -> approval_digest -> approve an evidence retention hold.".to_owned(),
    });

    (
        LiveSituationFrontier {
            anchor_commit_sequence: head_seq,
            authority_root,
            history_root,
            state_digest,
            epistemic_state: epistemic_state.to_owned(),
            covered_zones: orient.covered_zones,
            stale_zones: orient.stale_zones,
            not_observable_zones: orient.not_observable_zones,
            absence_certified: false,
            attention_frontier: attention,
            affordances,
        },
        LiveStorageRingTelemetry {
            pack_count: packs.pack_count,
            sealed_pack_count: packs.sealed_pack_count,
            on_disk_pack_bytes: packs.on_disk_pack_bytes,
            on_disk_mb: format_mb(packs.on_disk_pack_bytes),
            ring_used_bytes: ring_used,
            ring_cap_bytes: ring_cap,
            watermark_percent: watermark_pct,
            resource_pressure: pressure_str.to_owned(),
            scrubber_status,
            scrub_verified_objects: verified_objects,
            scrub_verified_packs: verified_packs,
            scrub_verified_fraction_ppm: verified_ppm,
            scrub_behind_commits: behind_commits,
            total_footage_imports: orient.total_footage_imports,
        },
    )
}

fn assemble_frame_from_v1(
    root: &Path,
    site: &str,
    v1: &fss_reference::agent_orient::DeploymentSnapshot,
    fallback_reason: Option<String>,
) -> LiveCockpitFrame {
    let root_str = root.to_string_lossy();
    let events: Vec<LiveEventRow> = v1
        .events
        .iter()
        .take(MAX_FRAME_EVENTS)
        .map(|retained| {
            let ev = &retained.event;
            let clusters = u32::try_from(retained.failure_domains().len()).unwrap_or(0);
            let epistemic = if ev.state == EventState::Corroborated {
                "Corroborated"
            } else if ev.state == EventState::Indeterminate {
                "Indeterminate"
            } else {
                "Observed"
            };
            LiveEventRow {
                event_id: ev.event_id.as_str().to_owned(),
                revision: ev.revision,
                kind: ev.kind.as_str().to_owned(),
                state: ev.state.as_str().to_owned(),
                epistemic_classification: epistemic.to_owned(),
                failure_domain_clusters: clusters,
                fusion_summary: format!(
                    "probability=[{:.3},{:.3}] domains={clusters}",
                    ev.probability.lower, ev.probability.upper
                ),
                zones: ev.zone_ids.clone(),
                sensors: Vec::new(),
                tamper_open: retained.tamper.has_open_tamper(),
                committed_sequence: retained.committed_sequence,
                privacy_masked_handle: PrivacyMaskedEventHandle {
                    handle_id: format!("h0:event:{}:rev{}", ev.event_id.as_str(), ev.revision),
                    event_root: retained.event_root.to_text(),
                    revision_digest: retained.revision_digest.to_text(),
                    hydration_level: "H0".to_owned(),
                    privacy_masks_active: 0,
                    raw_media_exposed: false,
                    inspect_command: format!(
                        "fss explain --json --root {root_str} --event-id {} --view decision_diff",
                        ev.event_id.as_str()
                    ),
                },
            }
        })
        .collect();
    let open_obligations = v1.open_obligations().len();
    let indeterminate_effects = v1.indeterminate_operations().len();
    LiveCockpitFrame {
        schema: LIVE_FRAME_SCHEMA,
        site: site.to_owned(),
        read_only: true,
        daemon_live: false,
        connection_mode: "offline_v1_readonly".to_owned(),
        daemon_info: None,
        fallback_reason,
        deltas_received: 0,
        max_delta_latency_ms: 0,
        last_delta_latency_ms: None,
        cameras: Vec::new(),
        situation: LiveSituationFrontier {
            anchor_commit_sequence: v1.position.commit_sequence,
            authority_root: v1.anchor.state_root.to_text(),
            history_root: v1.ledger_root.to_text(),
            state_digest: "v1_reference_readonly".to_owned(),
            epistemic_state: if indeterminate_effects > 0 {
                "indeterminate"
            } else {
                "unknown"
            }
            .to_owned(),
            covered_zones: v1.coverage.len(),
            stale_zones: 0,
            not_observable_zones: 0,
            absence_certified: false,
            attention_frontier: vec![LiveAttentionItem {
                priority: "normal".to_owned(),
                category: "daemon_offline_fallback".to_owned(),
                summary: "fss-daemon offline; displaying v1 read-only deployment projection."
                    .to_owned(),
            }],
            affordances: vec![LiveAffordanceItem {
                affordance_id: "affordance:orient:query".to_owned(),
                classification: "robust".to_owned(),
                requires_approval: false,
                summary: "Query bounded committed records read-only (AOP-005).".to_owned(),
            }],
        },
        events,
        obligations_and_holds: LiveObligationsHolds {
            open_obligations,
            indeterminate_effects,
            active_holds: 0,
            privacy_masks: 0,
            notes: vec![format!("doctor_verdict={:?}", v1.doctor_verdict)],
        },
        storage_ring: LiveStorageRingTelemetry {
            pack_count: 0,
            sealed_pack_count: 0,
            on_disk_pack_bytes: 0,
            on_disk_mb: "0.00".to_owned(),
            ring_used_bytes: 0,
            ring_cap_bytes: 0,
            watermark_percent: 0,
            resource_pressure: "Nominal".to_owned(),
            scrubber_status: "NeverScrubbed".to_owned(),
            scrub_verified_objects: 0,
            scrub_verified_packs: 0,
            scrub_verified_fraction_ppm: 0,
            scrub_behind_commits: 0,
            total_footage_imports: v1.completed_imports.len(),
        },
        agent_log: LiveAgentActivityLog {
            read_only: true,
            recent_deltas: Vec::new(),
            operator_workflows: build_operator_workflows(root, site),
        },
    }
}

/// Builds one complete 6-pane [`LiveCockpitFrame`] combining live daemon telemetry (if running)
/// with lock-free read-only MVCC/v1 projection inspection.
#[allow(clippy::too_many_arguments)]
pub fn assemble_live_frame(
    root: &Path,
    site: &str,
    live: Option<(&DaemonRuntimeDescriptor, &LiveDaemonStatus)>,
    fallback_reason: Option<String>,
    recent_deltas: &[LiveDeltaEntry],
    deltas_received: u64,
    max_delta_latency_ms: u64,
    last_delta_latency_ms: Option<u64>,
) -> io::Result<LiveCockpitFrame> {
    match load_readonly_store(root, site)? {
        ReadonlyStoreState::V1 { snapshot } => Ok(assemble_frame_from_v1(
            root,
            site,
            &snapshot,
            fallback_reason,
        )),
        ReadonlyStoreState::Mvcc { snapshot, packs } => {
            let orient = snapshot.orient_summary();
            let live_status = live.map(|(_, s)| s);
            let daemon_live = live.is_some();
            let daemon_info = live.map(|(desc, status)| LiveDaemonInfo {
                daemon_instance_id: desc.daemon_instance_id.clone(),
                pid: desc.pid,
                uptime_ms: status.daemon_uptime_ms,
                active_connections: status.active_connections,
                manifest_digest: desc.manifest_digest.to_text(),
                contract_basis_digest: desc.contract_basis_digest.to_text(),
            });
            let cameras = build_cameras_from_mvcc(live_status, &snapshot, recent_deltas);
            let events =
                build_events_from_mvcc(root, &snapshot, orient.privacy_masks, recent_deltas);
            let (situation, storage_ring) = build_situation_and_storage(
                &orient,
                snapshot.state_digest().to_text(),
                live_status,
                &packs,
                &events,
                daemon_live,
            );
            let mut log_deltas = recent_deltas.to_vec();
            if log_deltas.is_empty() && orient.anchor.commit_sequence > 0 {
                let start = orient.anchor.commit_sequence.saturating_sub(16);
                if let Ok(page) = snapshot.follow_since(start, 16) {
                    for commit in page.commits {
                        log_deltas.push(LiveDeltaEntry {
                            commit_sequence: commit.commit_sequence,
                            delta_digest: commit.authority_root.to_text(),
                            delta_class: "committed_history".to_owned(),
                            priority: "normal".to_owned(),
                            summary: format!(
                                "batch={} families={} events={} sensors={}",
                                commit.batch_id.as_str(),
                                commit.families.join(","),
                                commit.changed_events.len(),
                                commit.changed_sensors.len()
                            ),
                            latency_ms: None,
                        });
                    }
                }
            }
            let mut notes = Vec::new();
            if orient.open_obligations > 0 {
                notes.push(format!(
                    "{} open obligation(s) awaiting terminal proof.",
                    orient.open_obligations
                ));
            }
            if orient.indeterminate_effects > 0 {
                notes.push(format!(
                    "{} indeterminate effect(s) awaiting reconciliation.",
                    orient.indeterminate_effects
                ));
            }
            if orient.active_holds > 0 {
                notes.push(format!(
                    "{} active hold(s) pinning closures against compaction.",
                    orient.active_holds
                ));
            }
            Ok(LiveCockpitFrame {
                schema: LIVE_FRAME_SCHEMA,
                site: site.to_owned(),
                read_only: true,
                daemon_live,
                connection_mode: if daemon_live {
                    "live_daemon_ipc"
                } else {
                    "offline_mvcc_readonly"
                }
                .to_owned(),
                daemon_info,
                fallback_reason: if daemon_live { None } else { fallback_reason },
                deltas_received,
                max_delta_latency_ms,
                last_delta_latency_ms,
                cameras,
                situation,
                events,
                obligations_and_holds: LiveObligationsHolds {
                    open_obligations: orient.open_obligations,
                    indeterminate_effects: orient.indeterminate_effects,
                    active_holds: orient.active_holds,
                    privacy_masks: orient.privacy_masks,
                    notes,
                },
                storage_ring,
                agent_log: LiveAgentActivityLog {
                    read_only: true,
                    recent_deltas: log_deltas,
                    operator_workflows: build_operator_workflows(root, site),
                },
            })
        }
    }
}
