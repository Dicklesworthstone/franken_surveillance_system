#![forbid(unsafe_code)]
//! Deterministic serde-free JSON (`fss.dashboard_live_frame.v1`) and 6-pane terminal TUI
//! renderer for [`super::live::LiveCockpitFrame`].
//!
//! Semantic plane: `"projection"`.

use std::fmt::Write as _;

use fss_cli::agent_json::{array, object, optional_string, string, strings};

use super::live_model::{
    LiveAffordanceItem, LiveAttentionItem, LiveCameraHealth, LiveCockpitFrame, LiveDaemonInfo,
    LiveDeltaEntry, LiveEventRow, OperatorWorkflowHint,
};

fn render_daemon_info(info: &LiveDaemonInfo) -> String {
    object(&[
        ("daemon_instance_id", string(&info.daemon_instance_id)),
        ("pid", info.pid.to_string()),
        ("uptime_ms", info.uptime_ms.to_string()),
        ("active_connections", info.active_connections.to_string()),
        ("manifest_digest", string(&info.manifest_digest)),
        ("contract_basis_digest", string(&info.contract_basis_digest)),
    ])
}

fn render_camera(cam: &LiveCameraHealth) -> String {
    object(&[
        ("camera_id", string(&cam.camera_id)),
        ("state", string(&cam.state)),
        ("running", cam.running.to_string()),
        ("fps_in_milli", cam.fps_in_milli.to_string()),
        ("fps_decode_milli", cam.fps_decode_milli.to_string()),
        ("reconnect_count", cam.reconnect_count.to_string()),
        ("queue_depth", cam.queue_depth.to_string()),
        ("dropped_frames", cam.dropped_frames.to_string()),
        ("frames_ingested", cam.frames_ingested.to_string()),
        ("coverage_status", string(&cam.coverage_status)),
        ("active_gaps", cam.active_gaps.to_string()),
        ("zones", strings(&cam.zones)),
    ])
}

fn render_attention(item: &LiveAttentionItem) -> String {
    object(&[
        ("priority", string(&item.priority)),
        ("category", string(&item.category)),
        ("summary", string(&item.summary)),
    ])
}

fn render_affordance(item: &LiveAffordanceItem) -> String {
    object(&[
        ("affordance_id", string(&item.affordance_id)),
        ("classification", string(&item.classification)),
        ("requires_approval", item.requires_approval.to_string()),
        ("summary", string(&item.summary)),
    ])
}

fn render_event(ev: &LiveEventRow) -> String {
    let h = &ev.privacy_masked_handle;
    let handle_json = object(&[
        ("handle_id", string(&h.handle_id)),
        ("event_root", string(&h.event_root)),
        ("revision_digest", string(&h.revision_digest)),
        ("hydration_level", string(&h.hydration_level)),
        ("privacy_masks_active", h.privacy_masks_active.to_string()),
        ("raw_media_exposed", h.raw_media_exposed.to_string()),
        ("inspect_command", string(&h.inspect_command)),
    ]);
    object(&[
        ("event_id", string(&ev.event_id)),
        ("revision", ev.revision.to_string()),
        ("kind", string(&ev.kind)),
        ("state", string(&ev.state)),
        (
            "epistemic_classification",
            string(&ev.epistemic_classification),
        ),
        (
            "failure_domain_clusters",
            ev.failure_domain_clusters.to_string(),
        ),
        ("fusion_summary", string(&ev.fusion_summary)),
        ("zones", strings(&ev.zones)),
        ("sensors", strings(&ev.sensors)),
        ("tamper_open", ev.tamper_open.to_string()),
        ("committed_sequence", ev.committed_sequence.to_string()),
        ("privacy_masked_handle", handle_json),
    ])
}

fn render_delta(d: &LiveDeltaEntry) -> String {
    object(&[
        ("commit_sequence", d.commit_sequence.to_string()),
        ("delta_digest", string(&d.delta_digest)),
        ("delta_class", string(&d.delta_class)),
        ("priority", string(&d.priority)),
        ("summary", string(&d.summary)),
        (
            "latency_ms",
            d.latency_ms
                .map_or_else(|| "null".to_owned(), |v| v.to_string()),
        ),
    ])
}

fn render_workflow(w: &OperatorWorkflowHint) -> String {
    object(&[
        ("action", string(&w.action)),
        (
            "requires_approval_digest",
            w.requires_approval_digest.to_string(),
        ),
        ("preview_command", string(&w.preview_command)),
        ("approve_command", string(&w.approve_command)),
    ])
}

/// Renders one [`LiveCockpitFrame`] as deterministic, serde-free `fss.dashboard_live_frame.v1` JSON.
#[must_use]
pub fn render_live_frame_json(frame: &LiveCockpitFrame) -> String {
    let cameras_json: Vec<String> = frame.cameras.iter().map(render_camera).collect();
    let attention_json: Vec<String> = frame
        .situation
        .attention_frontier
        .iter()
        .map(render_attention)
        .collect();
    let affordances_json: Vec<String> = frame
        .situation
        .affordances
        .iter()
        .map(render_affordance)
        .collect();
    let events_json: Vec<String> = frame.events.iter().map(render_event).collect();
    let deltas_json: Vec<String> = frame
        .agent_log
        .recent_deltas
        .iter()
        .map(render_delta)
        .collect();
    let workflows_json: Vec<String> = frame
        .agent_log
        .operator_workflows
        .iter()
        .map(render_workflow)
        .collect();

    let situation_json = object(&[
        (
            "anchor_commit_sequence",
            frame.situation.anchor_commit_sequence.to_string(),
        ),
        ("authority_root", string(&frame.situation.authority_root)),
        ("history_root", string(&frame.situation.history_root)),
        ("state_digest", string(&frame.situation.state_digest)),
        ("epistemic_state", string(&frame.situation.epistemic_state)),
        (
            "coverage_summary",
            object(&[
                ("covered_zones", frame.situation.covered_zones.to_string()),
                ("stale_zones", frame.situation.stale_zones.to_string()),
                (
                    "not_observable_zones",
                    frame.situation.not_observable_zones.to_string(),
                ),
                (
                    "absence_certified",
                    frame.situation.absence_certified.to_string(),
                ),
            ]),
        ),
        ("attention_frontier", array(&attention_json)),
        ("affordances", array(&affordances_json)),
    ]);

    let obligations_json = object(&[
        (
            "open_obligations",
            frame.obligations_and_holds.open_obligations.to_string(),
        ),
        (
            "indeterminate_effects",
            frame
                .obligations_and_holds
                .indeterminate_effects
                .to_string(),
        ),
        (
            "active_holds",
            frame.obligations_and_holds.active_holds.to_string(),
        ),
        (
            "privacy_masks",
            frame.obligations_and_holds.privacy_masks.to_string(),
        ),
        ("notes", strings(&frame.obligations_and_holds.notes)),
    ]);

    let storage_json = object(&[
        ("pack_count", frame.storage_ring.pack_count.to_string()),
        (
            "sealed_pack_count",
            frame.storage_ring.sealed_pack_count.to_string(),
        ),
        (
            "on_disk_pack_bytes",
            frame.storage_ring.on_disk_pack_bytes.to_string(),
        ),
        ("on_disk_mb", string(&frame.storage_ring.on_disk_mb)),
        (
            "ring_used_bytes",
            frame.storage_ring.ring_used_bytes.to_string(),
        ),
        (
            "ring_cap_bytes",
            frame.storage_ring.ring_cap_bytes.to_string(),
        ),
        (
            "watermark_percent",
            frame.storage_ring.watermark_percent.to_string(),
        ),
        (
            "resource_pressure",
            string(&frame.storage_ring.resource_pressure),
        ),
        (
            "scrubber_status",
            string(&frame.storage_ring.scrubber_status),
        ),
        (
            "scrub_verified_objects",
            frame.storage_ring.scrub_verified_objects.to_string(),
        ),
        (
            "scrub_verified_packs",
            frame.storage_ring.scrub_verified_packs.to_string(),
        ),
        (
            "scrub_verified_fraction_ppm",
            frame.storage_ring.scrub_verified_fraction_ppm.to_string(),
        ),
        (
            "scrub_behind_commits",
            frame.storage_ring.scrub_behind_commits.to_string(),
        ),
        (
            "total_footage_imports",
            frame.storage_ring.total_footage_imports.to_string(),
        ),
    ]);

    let agent_log_json = object(&[
        ("read_only", frame.agent_log.read_only.to_string()),
        ("recent_deltas", array(&deltas_json)),
        ("operator_workflows", array(&workflows_json)),
    ]);

    object(&[
        ("schema", string(frame.schema)),
        ("site", string(&frame.site)),
        ("read_only", frame.read_only.to_string()),
        ("daemon_live", frame.daemon_live.to_string()),
        ("connection_mode", string(&frame.connection_mode)),
        (
            "daemon_info",
            frame
                .daemon_info
                .as_ref()
                .map_or_else(|| "null".to_owned(), render_daemon_info),
        ),
        (
            "fallback_reason",
            optional_string(frame.fallback_reason.as_deref()),
        ),
        ("deltas_received", frame.deltas_received.to_string()),
        (
            "max_delta_latency_ms",
            frame.max_delta_latency_ms.to_string(),
        ),
        (
            "last_delta_latency_ms",
            frame
                .last_delta_latency_ms
                .map_or_else(|| "null".to_owned(), |v| v.to_string()),
        ),
        ("cameras", array(&cameras_json)),
        ("situation", situation_json),
        ("events", array(&events_json)),
        ("obligations_and_holds", obligations_json),
        ("storage_ring", storage_json),
        ("agent_log", agent_log_json),
    ])
}

fn short_hash(digest: &str) -> &str {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    if body.len() > 12 { &body[..12] } else { body }
}

fn format_fps(milli: u32) -> String {
    format!("{}.{:01}", milli / 1000, (milli % 1000) / 100)
}

/// Renders all 6 panes of a [`LiveCockpitFrame`] as a deterministic, human-legible operator TUI.
#[must_use]
pub fn render_live_tui(frame: &LiveCockpitFrame, ansi: bool) -> String {
    let (bold, dim, reset) = if ansi {
        ("\x1b[1m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    let mut out = String::with_capacity(2048);
    let mode_tag = if frame.daemon_live {
        "LIVE DAEMON IPC"
    } else {
        "OFFLINE MVCC FALLBACK"
    };
    let _ = writeln!(
        out,
        "{bold}=== FSS LIVE OPERATOR COCKPIT [{mode_tag}] | site={} | READ-ONLY ==={reset}",
        frame.site
    );
    if let Some(info) = &frame.daemon_info {
        let _ = writeln!(
            out,
            "daemon={} pid={} uptime={}ms conns={} anchor_seq={} deltas_rx={} max_latency={}ms",
            info.daemon_instance_id,
            info.pid,
            info.uptime_ms,
            info.active_connections,
            frame.situation.anchor_commit_sequence,
            frame.deltas_received,
            frame.max_delta_latency_ms,
        );
    } else {
        let _ = writeln!(
            out,
            "daemon_live=false mode={} anchor_seq={} fallback={}",
            frame.connection_mode,
            frame.situation.anchor_commit_sequence,
            frame
                .fallback_reason
                .as_deref()
                .unwrap_or("daemon stopped (read-only MVCC)"),
        );
    }

    // Pane 1: Camera Mesh Health
    let _ = writeln!(
        out,
        "\n{bold}[1] CAMERA MESH HEALTH ({} camera(s)){reset}",
        frame.cameras.len()
    );
    if frame.cameras.is_empty() {
        let _ = writeln!(
            out,
            "  (no camera telemetry rows; silence is not evidence of absence)"
        );
    } else {
        let _ = writeln!(
            out,
            "  {:<22} {:<10} {:>7} {:>7} {:>5} {:>5} {:>5} {:<14} {:>4}",
            "CAMERA", "STATE", "IN_FPS", "DEC_FPS", "RCON", "QDEP", "DROP", "COVERAGE", "GAPS"
        );
        for cam in &frame.cameras {
            let _ = writeln!(
                out,
                "  {:<22} {:<10} {:>7} {:>7} {:>5} {:>5} {:>5} {:<14} {:>4}",
                cam.camera_id,
                cam.state,
                format_fps(cam.fps_in_milli),
                format_fps(cam.fps_decode_milli),
                cam.reconnect_count,
                cam.queue_depth,
                cam.dropped_frames,
                cam.coverage_status,
                cam.active_gaps,
            );
        }
    }

    // Pane 2: Active Situation & Attention Frontier
    let _ = writeln!(
        out,
        "\n{bold}[2] ACTIVE SITUATION & ATTENTION FRONTIER{reset}"
    );
    let _ = writeln!(
        out,
        "  anchor_seq={} authority={} history={} epistemic={} coverage(covered={}, stale={}, not_obs={}) absence_certified={}",
        frame.situation.anchor_commit_sequence,
        short_hash(&frame.situation.authority_root),
        short_hash(&frame.situation.history_root),
        frame.situation.epistemic_state,
        frame.situation.covered_zones,
        frame.situation.stale_zones,
        frame.situation.not_observable_zones,
        frame.situation.absence_certified,
    );
    for item in &frame.situation.attention_frontier {
        let _ = writeln!(
            out,
            "  ! [{}] {}: {}",
            item.priority.to_uppercase(),
            item.category,
            item.summary
        );
    }
    let aff_names: Vec<&str> = frame
        .situation
        .affordances
        .iter()
        .map(|a| a.affordance_id.as_str())
        .collect();
    let _ = writeln!(out, "  affordances: {}", aff_names.join(", "));

    // Pane 3: Corroborated Events & Milliban Fusion Scores
    let _ = writeln!(
        out,
        "\n{bold}[3] CORROBORATED EVENTS & MILLIBAN FUSION ({} event(s)){reset}",
        frame.events.len()
    );
    if frame.events.is_empty() {
        let _ = writeln!(
            out,
            "  (no committed events; empty inventory never certifies physical absence)"
        );
    } else {
        if frame.events.len() > 12 {
            let _ = writeln!(
                out,
                "  Showing 12 of {} events in this frame. Use --json for all frame rows.",
                frame.events.len()
            );
        }
        for ev in frame.events.iter().take(12) {
            let _ = writeln!(
                out,
                "  - {} [{}] state={} clusters={} zones=[{}] fusion={} handle={} (raw_media={})",
                ev.event_id,
                ev.epistemic_classification,
                ev.state,
                if ev.failure_domain_clusters == 0 {
                    "unknown".to_owned()
                } else {
                    ev.failure_domain_clusters.to_string()
                },
                ev.zones.join(","),
                ev.fusion_summary,
                ev.privacy_masked_handle.handle_id,
                ev.privacy_masked_handle.raw_media_exposed,
            );
        }
    }

    // Pane 4: Active Obligations, Effects & Legal Holds
    let _ = writeln!(
        out,
        "\n{bold}[4] ACTIVE OBLIGATIONS, EFFECTS & LEGAL HOLDS{reset}"
    );
    let _ = writeln!(
        out,
        "  open_obligations={} indeterminate_effects={} active_holds={} privacy_masks={}",
        frame.obligations_and_holds.open_obligations,
        frame.obligations_and_holds.indeterminate_effects,
        frame.obligations_and_holds.active_holds,
        frame.obligations_and_holds.privacy_masks,
    );
    for note in &frame.obligations_and_holds.notes {
        let _ = writeln!(out, "  * {note}");
    }

    // Pane 5: Storage Ring Capacity & Compaction Telemetry
    let _ = writeln!(
        out,
        "\n{bold}[5] STORAGE RING CAPACITY & COMPACTION TELEMETRY{reset}"
    );
    let _ = writeln!(
        out,
        "  packs={} (sealed={}) on_disk={}MB ring={}/{}B ({}%) pressure={} scrubber={} verified_objs={} imports={}",
        frame.storage_ring.pack_count,
        frame.storage_ring.sealed_pack_count,
        frame.storage_ring.on_disk_mb,
        frame.storage_ring.ring_used_bytes,
        frame.storage_ring.ring_cap_bytes,
        frame.storage_ring.watermark_percent,
        frame.storage_ring.resource_pressure,
        frame.storage_ring.scrubber_status,
        frame.storage_ring.scrub_verified_objects,
        frame.storage_ring.total_footage_imports,
    );

    // Pane 6: Agent Activity Log & Preview->Approve Workflows
    let _ = writeln!(
        out,
        "\n{bold}[6] AGENT ACTIVITY LOG (read_only=true; preview -> approval_digest -> approve){reset}"
    );
    if frame.agent_log.recent_deltas.is_empty() {
        let _ = writeln!(out, "  (no deltas observed yet)");
    } else {
        for d in frame.agent_log.recent_deltas.iter().rev().take(8) {
            let lat = d
                .latency_ms
                .map_or_else(|| "-".to_owned(), |v| format!("{v}ms"));
            let _ = writeln!(
                out,
                "  seq={:<6} [{:<14}] {:<8} lat={:<6} {}",
                d.commit_sequence, d.delta_class, d.priority, lat, d.summary
            );
        }
    }
    let _ = writeln!(
        out,
        "{dim}  Operator mutation workflows (explicit approval_digest required):{reset}"
    );
    for wf in &frame.agent_log.operator_workflows {
        let _ = writeln!(
            out,
            "  - {}: preview=`{}` -> approve=`{}`",
            wf.action, wf.preview_command, wf.approve_command
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_model::{
        LIVE_FRAME_SCHEMA, LiveAgentActivityLog, LiveObligationsHolds, LiveSituationFrontier,
        LiveStorageRingTelemetry, PrivacyMaskedEventHandle,
    };

    fn sample_frame(daemon_live: bool) -> LiveCockpitFrame {
        LiveCockpitFrame {
            schema: LIVE_FRAME_SCHEMA,
            site: "site:test-live".to_owned(),
            read_only: true,
            daemon_live,
            connection_mode: if daemon_live {
                "live_daemon_ipc".to_owned()
            } else {
                "offline_mvcc_readonly".to_owned()
            },
            daemon_info: daemon_live.then(|| LiveDaemonInfo {
                daemon_instance_id: "daemon:site:test-live:42".to_owned(),
                pid: 42,
                uptime_ms: 1200,
                active_connections: 1,
                manifest_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                        .to_owned(),
                contract_basis_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000002"
                        .to_owned(),
            }),
            fallback_reason: (!daemon_live).then(|| "daemon offline".to_owned()),
            deltas_received: 2,
            max_delta_latency_ms: 14,
            last_delta_latency_ms: Some(9),
            cameras: vec![LiveCameraHealth {
                camera_id: "sensor:wyze-51".to_owned(),
                state: "streaming".to_owned(),
                running: true,
                fps_in_milli: 15_000,
                fps_decode_milli: 15_000,
                reconnect_count: 1,
                queue_depth: 2,
                dropped_frames: 0,
                frames_ingested: 120,
                coverage_status: "covered".to_owned(),
                active_gaps: 0,
                zones: vec!["driveway".to_owned()],
            }],
            situation: LiveSituationFrontier {
                anchor_commit_sequence: 12,
                authority_root:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                history_root:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned(),
                state_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                epistemic_state: "corroborated".to_owned(),
                covered_zones: 3,
                stale_zones: 0,
                not_observable_zones: 0,
                absence_certified: false,
                attention_frontier: vec![LiveAttentionItem {
                    priority: "high".to_owned(),
                    category: "corroborated_event".to_owned(),
                    summary: "1 corroborated event".to_owned(),
                }],
                affordances: vec![LiveAffordanceItem {
                    affordance_id: "affordance:orient:plan".to_owned(),
                    classification: "conditional".to_owned(),
                    requires_approval: true,
                    summary: "preview->approve alert plan".to_owned(),
                }],
            },
            events: vec![LiveEventRow {
                event_id: "event:live:1".to_owned(),
                revision: 1,
                kind: "perimeter_breach".to_owned(),
                state: "corroborated".to_owned(),
                epistemic_classification: "Corroborated".to_owned(),
                failure_domain_clusters: 2,
                fusion_summary: "corroborated event=event:live:1 clusters=2 rev=1".to_owned(),
                zones: vec!["driveway".to_owned()],
                sensors: vec![
                    "sensor:wyze-51".to_owned(),
                    "sensor:unifi-g4-177".to_owned(),
                ],
                tamper_open: false,
                committed_sequence: 12,
                privacy_masked_handle: PrivacyMaskedEventHandle {
                    handle_id: "h0:event:event:live:1:rev1".to_owned(),
                    event_root:
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .to_owned(),
                    revision_digest:
                        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .to_owned(),
                    hydration_level: "H0".to_owned(),
                    privacy_masks_active: 3,
                    raw_media_exposed: false,
                    inspect_command: "fss query --target evidence-hydration ... --level H0"
                        .to_owned(),
                },
            }],
            obligations_and_holds: LiveObligationsHolds {
                open_obligations: 1,
                indeterminate_effects: 0,
                active_holds: 2,
                privacy_masks: 3,
                notes: vec!["2 active holds".to_owned()],
            },
            storage_ring: LiveStorageRingTelemetry {
                pack_count: 4,
                sealed_pack_count: 3,
                on_disk_pack_bytes: 2_097_152,
                on_disk_mb: "2.00".to_owned(),
                ring_used_bytes: 1_048_576,
                ring_cap_bytes: 67_108_864,
                watermark_percent: 2,
                resource_pressure: "Nominal".to_owned(),
                scrubber_status: "Clean".to_owned(),
                scrub_verified_objects: 64,
                scrub_verified_packs: 3,
                scrub_verified_fraction_ppm: 1_000_000,
                scrub_behind_commits: 0,
                total_footage_imports: 18,
            },
            agent_log: LiveAgentActivityLog {
                read_only: true,
                recent_deltas: vec![LiveDeltaEntry {
                    commit_sequence: 12,
                    delta_digest:
                        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .to_owned(),
                    delta_class: "Hypothesis".to_owned(),
                    priority: "High".to_owned(),
                    summary: "corroborated event=event:live:1 clusters=2 rev=1".to_owned(),
                    latency_ms: Some(9),
                }],
                operator_workflows: vec![OperatorWorkflowHint {
                    action: "alert".to_owned(),
                    requires_approval_digest: true,
                    preview_command: "fss plan ...".to_owned(),
                    approve_command: "fss commit --approve <APPROVAL_DIGEST>".to_owned(),
                }],
            },
        }
    }

    #[test]
    fn json_and_tui_render_all_six_panes_deterministically() {
        let live = sample_frame(true);
        let json = render_live_frame_json(&live);
        assert!(fss_cli::json_input::parse(&json).is_ok());
        for needle in [
            "\"schema\":\"fss.dashboard_live_frame.v1\"",
            "\"daemon_live\":true",
            "\"read_only\":true",
            "\"camera_id\":\"sensor:wyze-51\"",
            "\"affordance_id\":\"affordance:orient:plan\"",
            "\"epistemic_classification\":\"Corroborated\"",
            "\"raw_media_exposed\":false",
            "\"active_holds\":2",
            "\"scrubber_status\":\"Clean\"",
            "\"requires_approval_digest\":true",
        ] {
            assert!(json.contains(needle), "missing {needle} in {json}");
        }
        let tui = render_live_tui(&live, false);
        for heading in [
            "[1] CAMERA MESH HEALTH",
            "[2] ACTIVE SITUATION & ATTENTION FRONTIER",
            "[3] CORROBORATED EVENTS & MILLIBAN FUSION",
            "[4] ACTIVE OBLIGATIONS, EFFECTS & LEGAL HOLDS",
            "[5] STORAGE RING CAPACITY & COMPACTION TELEMETRY",
            "[6] AGENT ACTIVITY LOG",
        ] {
            assert!(tui.contains(heading), "missing {heading} in:\n{tui}");
        }
        let offline = sample_frame(false);
        let offline_tui = render_live_tui(&offline, false);
        assert!(offline_tui.contains("OFFLINE MVCC FALLBACK"));
        assert!(offline_tui.contains("daemon_live=false"));
    }
}
