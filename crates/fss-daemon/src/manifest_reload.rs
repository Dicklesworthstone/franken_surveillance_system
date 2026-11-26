#![forbid(unsafe_code)]
//! Preflight for manifest changes whose live owners can be updated atomically.
//!
//! Semantic plane: `"authority"`.

use std::collections::BTreeMap;

use crate::manifest::SiteManifest;

/// Names the first startup-owned field changed by a reload. No live state is touched.
///
/// Camera inventory, source identity, credential bindings, frame geometry, bounded rings,
/// storage policy, and IPC ownership require a drained restart. A driver metadata update
/// cannot replace those owners or acquire a fresh vault lease.
pub(super) fn restart_required_field(
    current: &SiteManifest,
    candidate: &SiteManifest,
) -> Option<&'static str> {
    for (changed, field) in [
        (current.site_id != candidate.site_id, "site_id"),
        (
            current.deployment_root != candidate.deployment_root,
            "deployment_root",
        ),
        (
            current.ipc_socket_override != candidate.ipc_socket_override,
            "ipc_socket_override",
        ),
        (
            current.ring_cap_bytes != candidate.ring_cap_bytes,
            "ring_cap_bytes",
        ),
        (
            current.soft_watermark_pct != candidate.soft_watermark_pct,
            "soft_watermark_pct",
        ),
        (
            current.hard_watermark_pct != candidate.hard_watermark_pct,
            "hard_watermark_pct",
        ),
        (
            current.pack_target_bytes != candidate.pack_target_bytes,
            "pack_target_bytes",
        ),
        (
            current.scrub_budget_bytes_per_tick != candidate.scrub_budget_bytes_per_tick,
            "scrub_budget_bytes_per_tick",
        ),
        (
            current.retain_hot_ns != candidate.retain_hot_ns,
            "retain_hot_ns",
        ),
        // The resident model cache does not key its immutable contract by threshold.
        // Reusing that package would retain the old score policy despite new metadata.
        (
            current.detector_min_score_ppm != candidate.detector_min_score_ppm,
            "detector_min_score_ppm",
        ),
    ] {
        if changed {
            return Some(field);
        }
    }

    let current_cameras: BTreeMap<_, _> = current
        .cameras
        .iter()
        .map(|camera| (camera.sensor_id.clone(), camera))
        .collect();
    if current_cameras.len() != candidate.cameras.len() {
        return Some("camera_inventory");
    }

    for camera in &candidate.cameras {
        let Some(previous) = current_cameras.get(&camera.sensor_id) else {
            return Some("camera_inventory");
        };
        for (changed, field) in [
            (previous.adapter != camera.adapter, "camera_adapter"),
            (previous.endpoint != camera.endpoint, "camera_endpoint"),
            (previous.secret_id != camera.secret_id, "camera_secret_id"),
            (
                previous.dimensions != camera.dimensions,
                "camera_dimensions",
            ),
            (
                previous.primary_zone != camera.primary_zone,
                "camera_primary_zone",
            ),
            (
                previous.ring_max_frames != camera.ring_max_frames,
                "camera_ring_max_frames",
            ),
            (
                previous.ring_max_bytes != camera.ring_max_bytes,
                "camera_ring_max_bytes",
            ),
            (
                previous.retain_hot_ns != camera.retain_hot_ns,
                "camera_retain_hot_ns",
            ),
            (
                previous.max_sensor_bytes != camera.max_sensor_bytes,
                "camera_max_sensor_bytes",
            ),
            (
                previous.auth_realm != camera.auth_realm,
                "camera_auth_realm",
            ),
            (
                previous.allow_inband_sps_pps != camera.allow_inband_sps_pps,
                "camera_allow_inband_sps_pps",
            ),
            (
                previous.setup_companion_tracks != camera.setup_companion_tracks,
                "camera_setup_companion_tracks",
            ),
        ] {
            if changed {
                return Some(field);
            }
        }
    }

    // Allowlist the fields with an implemented hot owner. Future manifest fields fail closed
    // until their activation semantics are deliberately added here and in the supervisor.
    let mut permitted = current.clone();
    permitted.detector_package_path = candidate.detector_package_path.clone();
    permitted.detector_package_digest = candidate.detector_package_digest;
    permitted.topology = candidate.topology.clone();
    permitted.cameras.clear();
    for camera in &candidate.cameras {
        let Some(previous) = current_cameras.get(&camera.sensor_id) else {
            return Some("camera_inventory");
        };
        let mut permitted_camera = (**previous).clone();
        permitted_camera.osd_ignore_rects = camera.osd_ignore_rects.clone();
        permitted_camera.priority_tier = camera.priority_tier;
        permitted_camera.zones = camera.zones.clone();
        permitted_camera.failure_domains = camera.failure_domains.clone();
        permitted_camera.reconnect_min_ms = camera.reconnect_min_ms;
        permitted_camera.reconnect_max_ms = camera.reconnect_max_ms;
        permitted_camera.stall_timeout_ms = camera.stall_timeout_ms;
        permitted_camera.gop_frames = camera.gop_frames;
        permitted.cameras.push(permitted_camera);
    }
    if permitted != *candidate {
        return Some("unsupported_configuration");
    }
    None
}

/// Timing and GOP changes do not invalidate the accumulated perception/clock state.
pub(super) fn perception_changed(current: &SiteManifest, candidate: &SiteManifest) -> bool {
    current.detector_package_path != candidate.detector_package_path
        || current.detector_package_digest != candidate.detector_package_digest
        || current.detector_min_score_ppm != candidate.detector_min_score_ppm
        || current.topology != candidate.topology
        || current.cameras.len() != candidate.cameras.len()
        || current
            .cameras
            .iter()
            .zip(&candidate.cameras)
            .any(|(old, new)| {
                old.sensor_id != new.sensor_id
                    || old.priority_tier != new.priority_tier
                    || old.osd_ignore_rects != new.osd_ignore_rects
                    || old.zones != new.zones
                    || old.failure_domains != new.failure_domains
            })
}
