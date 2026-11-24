#![forbid(unsafe_code)]
//! `AOP-005 query --target cameras` — live `fss-daemon` telemetry over `fss-ipc` with automatic
//! read-only MVCC/deployment fallback when the daemon is offline.
//!
//! Semantic plane: `"cognition"` (strictly read-only observation; grants no control authority).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest, ExecutionBoundary,
    KnowledgeState, PrincipalId, ResponseSafeRetry, SessionId,
};
use fss_daemon::control::{DaemonRuntimeDescriptor, query_live_daemon_status};
use fss_ipc::{ActiveScrubStatus, CameraLiveStatus, LiveDaemonStatus, RingWatermarkStatus};
use fss_reference::agent_orient::{DeploymentSnapshot, OrientLimits, read_deployment_cancellable};

use super::{
    CAP_AGENT_QUERY, CAP_OBSERVE_STATUS, OpsEnvelopeParams, OpsError, ensure_deployment_root,
    render_ok_envelope, render_refusal_envelope, require_capabilities,
    resolve_effective_capabilities,
};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};

/// Registered payload schema for `query --target cameras`.
pub const CAMERAS_PAYLOAD_SCHEMA: &str = "fss.agent_ops_cameras.v1";
/// Canonical digest domain for `query --target cameras`.
pub const CAMERAS_DIGEST_DOMAIN: &str = "fss.ops_targets.cameras.v1";

/// Request parameters for read-only camera telemetry and fallback status inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CamerasQueryRequest {
    /// Existing deployment root directory.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity for capability resolution.
    pub session_id: Option<SessionId>,
    /// Optional filter restricting output to one camera/sensor ID.
    pub camera_id: Option<String>,
    /// Optional explicit site identifier override for local daemon handshake.
    pub site_id: Option<String>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Executes `query --target cameras` and renders a registered `AgentResponseEnvelope`.
pub(crate) fn execute(
    req: &CamerasQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "query",
            &req.principal,
            req.session_id.as_ref(),
            CAMERAS_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run<'a>(
    req: &'a CamerasQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<OpsEnvelopeParams<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let effective = resolve_effective_capabilities(
        &req.root,
        &req.principal,
        req.session_id.as_ref(),
        &req.granted_capabilities,
    )?;
    require_capabilities(
        &effective,
        &[CAP_AGENT_QUERY, CAP_OBSERVE_STATUS],
        "query --target cameras",
    )?;
    ensure_deployment_root(&req.root)?;
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    if cancelled() {
        return Err(OpsError::Cancelled);
    }

    let live_probe =
        query_live_daemon_status(&req.root, req.site_id.as_deref(), req.principal.clone());

    let retained_liveness = render_retained_liveness(&snapshot, req.camera_id.as_deref());
    let retained_coverage = render_retained_coverage(&snapshot, req.camera_id.as_deref());

    let (payload_json, epistemic_state, warnings, proof_pointers, fingerprint, completed_note) =
        match live_probe {
            Ok((descriptor, status)) => {
                let fp =
                    fingerprint_live(&snapshot, &descriptor, &status, req.camera_id.as_deref());
                let payload = render_live_payload(
                    &snapshot,
                    &descriptor,
                    &status,
                    req.camera_id.as_deref(),
                    retained_liveness,
                    retained_coverage,
                );
                let proofs = vec![
                    snapshot.anchor.state_root.to_text(),
                    descriptor.descriptor_digest().to_text(),
                    status.history_root.to_text(),
                ];
                let mut warnings = Vec::new();
                if let Some(ring) = &status.ring
                    && ring.watermark_percent >= 90
                {
                    warnings.push(format!(
                        "Retention ring watermark is critical at {}% ({}/{} bytes).",
                        ring.watermark_percent, ring.used_bytes, ring.capacity_bytes
                    ));
                }
                (
                    payload,
                    KnowledgeState::Known,
                    warnings,
                    proofs,
                    fp,
                    "Connected to live fss-daemon over fss-ipc and returned camera telemetry, ring pressure, and retained coverage summary.".to_owned(),
                )
            }
            Err(err) => {
                let reason = err.to_string();
                let fp = fingerprint_offline(&snapshot, req.camera_id.as_deref(), &reason);
                let payload = render_offline_payload(
                    &snapshot,
                    req.camera_id.as_deref(),
                    &reason,
                    retained_liveness,
                    retained_coverage,
                );
                let proofs = vec![
                    snapshot.anchor.state_root.to_text(),
                    snapshot.ledger_root.to_text(),
                ];
                let warnings = vec![
                    "fss-daemon is offline; live FPS, reconnect counts, queue depths, and ring pressure are not_observable. Returned read-only retained deployment snapshot.".to_owned(),
                ];
                (
                    payload,
                    KnowledgeState::NotObservable,
                    warnings,
                    proofs,
                    fp,
                    "fss-daemon unavailable; completed read-only MVCC/deployment fallback inspection with retained sensor liveness and coverage summary.".to_owned(),
                )
            }
        };

    Ok(OpsEnvelopeParams {
        operation: "query",
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: snapshot.anchor.clone(),
        view: AgentView::Case,
        capabilities: vec![CAP_AGENT_QUERY.to_owned(), CAP_OBSERVE_STATUS.to_owned()],
        privacy_purpose: "read-only camera liveness, daemon telemetry, and retained coverage summary",
        allowed_domains: &[
            "live-daemon-camera-telemetry",
            "retained-sensor-liveness",
            "retained-coverage-summary",
        ],
        redacted_domains: &["media-payloads", "camera-credentials", "rtsp-secrets"],
        payload_schema: CAMERAS_PAYLOAD_SCHEMA,
        payload_json,
        epistemic_state,
        completeness: Completeness::Bounded,
        warnings,
        proof_pointers,
        decision_fingerprint: fingerprint,
        idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![completed_note],
            not_started: vec![
                "No camera control command, credential read, or authority mutation was performed."
                    .to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Offline fallback never fabricates live FPS, queue depth, or current reachability."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn ring_pressure_label(percent: u8) -> &'static str {
    if percent >= 90 {
        "critical"
    } else if percent >= 75 {
        "elevated"
    } else {
        "nominal"
    }
}

fn render_camera_live(cam: &CameraLiveStatus, stream_generation: &str) -> String {
    object(&[
        ("cameraId", string(&cam.camera_id)),
        ("running", cam.running.to_string()),
        ("fpsMilli", cam.fps_milli.to_string()),
        ("reconnectCount", cam.reconnect_count.to_string()),
        ("queueDepth", cam.queue_depth.to_string()),
        ("framesIngested", cam.frames_ingested.to_string()),
        ("activeStreamGeneration", string(stream_generation)),
    ])
}

fn render_ring(ring: &RingWatermarkStatus) -> String {
    object(&[
        ("usedBytes", ring.used_bytes.to_string()),
        ("capacityBytes", ring.capacity_bytes.to_string()),
        ("watermarkPercent", ring.watermark_percent.to_string()),
        (
            "ringPressure",
            string(ring_pressure_label(ring.watermark_percent)),
        ),
    ])
}

fn render_scrub(scrub: &ActiveScrubStatus) -> String {
    match scrub {
        ActiveScrubStatus::Idle => object(&[("state", string("idle"))]),
        ActiveScrubStatus::Running {
            checked_objects,
            total_objects,
        } => object(&[
            ("state", string("running")),
            ("checkedObjects", checked_objects.to_string()),
            ("totalObjects", total_objects.to_string()),
        ]),
        ActiveScrubStatus::Completed {
            checked_objects,
            anomalies_found,
        } => object(&[
            ("state", string("completed")),
            ("checkedObjects", checked_objects.to_string()),
            ("anomaliesFound", anomalies_found.to_string()),
        ]),
        ActiveScrubStatus::Failed { error_id } => object(&[
            ("state", string("failed")),
            ("errorId", string(error_id.as_str())),
        ]),
    }
}

fn render_retained_liveness(snapshot: &DeploymentSnapshot, filter: Option<&str>) -> String {
    let rows: Vec<String> = snapshot
        .sensor_liveness
        .iter()
        .filter(|entry| filter.is_none_or(|id| entry.record.enrollment().sensor().as_str() == id))
        .map(|entry| {
            object(&[
                (
                    "sensorId",
                    string(entry.record.enrollment().sensor().as_str()),
                ),
                ("receiptDigest", string(&entry.root.to_text())),
                (
                    "committedSequence",
                    entry.anchor.commit_sequence.to_string(),
                ),
                (
                    "observedAtNs",
                    string(&entry.record.observed_at_ns().to_string()),
                ),
                ("reachable", entry.record.fresh_sighting().to_string()),
            ])
        })
        .collect();
    array(&rows)
}

fn render_retained_coverage(snapshot: &DeploymentSnapshot, filter: Option<&str>) -> String {
    let mut per_sensor: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for cov in &snapshot.coverage {
        let sensor = cov.record.sensor_id.as_str();
        if filter.is_some_and(|id| sensor != id) {
            continue;
        }
        let entry = per_sensor.entry(sensor.to_owned()).or_insert((0, 0));
        entry.0 += cov.record.zones.len();
        let witnesses: usize = if cov.calibration_invalidation.is_some() {
            0
        } else {
            cov.record.zones.iter().map(|z| z.witnesses.len()).sum()
        };
        entry.1 += witnesses;
    }
    let rows: Vec<String> = per_sensor
        .into_iter()
        .map(|(sensor_id, (zone_count, witness_count))| {
            object(&[
                ("sensorId", string(&sensor_id)),
                ("zoneCount", zone_count.to_string()),
                ("retainedWitnessCount", witness_count.to_string()),
            ])
        })
        .collect();
    array(&rows)
}

fn render_live_payload(
    snapshot: &DeploymentSnapshot,
    descriptor: &DaemonRuntimeDescriptor,
    status: &LiveDaemonStatus,
    filter: Option<&str>,
    retained_liveness: String,
    retained_coverage: String,
) -> String {
    let stream_generation = format!(
        "manifest:{}@commit:{}",
        descriptor.manifest_digest.to_text(),
        status.head_commit_sequence
    );
    let cameras: Vec<String> = status
        .cameras
        .iter()
        .filter(|cam| filter.is_none_or(|id| cam.camera_id == id))
        .map(|cam| render_camera_live(cam, &stream_generation))
        .collect();
    let ring_json = status
        .ring
        .as_ref()
        .map_or_else(|| "null".to_owned(), render_ring);
    object(&[
        ("schema", string(CAMERAS_PAYLOAD_SCHEMA)),
        ("siteLineage", string(&snapshot.site_lineage)),
        ("daemonLive", "true".to_owned()),
        ("daemonInstanceId", string(&descriptor.daemon_instance_id)),
        ("daemonPid", descriptor.pid.to_string()),
        ("daemonUptimeMs", status.daemon_uptime_ms.to_string()),
        (
            "headCommitSequence",
            status.head_commit_sequence.to_string(),
        ),
        ("historyRoot", string(&status.history_root.to_text())),
        ("stateRoot", string(&status.state_root.to_text())),
        ("activeConnections", status.active_connections.to_string()),
        ("cameras", array(&cameras)),
        ("ring", ring_json),
        ("scrub", render_scrub(&status.scrub)),
        ("retainedSensorLiveness", retained_liveness),
        ("retainedCoverageSummary", retained_coverage),
        ("effectsAuthorized", "false".to_owned()),
    ])
}

fn render_offline_payload(
    snapshot: &DeploymentSnapshot,
    filter: Option<&str>,
    reason: &str,
    retained_liveness: String,
    retained_coverage: String,
) -> String {
    object(&[
        ("schema", string(CAMERAS_PAYLOAD_SCHEMA)),
        ("siteLineage", string(&snapshot.site_lineage)),
        ("daemonLive", "false".to_owned()),
        ("fallbackMode", string("readonly_mvcc_deployment_snapshot")),
        ("fallbackReason", string(reason)),
        (
            "cameraFilter",
            filter.map_or_else(|| "null".to_owned(), string),
        ),
        (
            "headCommitSequence",
            snapshot.anchor.commit_sequence.to_string(),
        ),
        ("cameras", "[]".to_owned()),
        ("ring", "null".to_owned()),
        ("scrub", "null".to_owned()),
        ("retainedSensorLiveness", retained_liveness),
        ("retainedCoverageSummary", retained_coverage),
        ("effectsAuthorized", "false".to_owned()),
    ])
}

fn fingerprint_live(
    snapshot: &DeploymentSnapshot,
    descriptor: &DaemonRuntimeDescriptor,
    status: &LiveDaemonStatus,
    filter: Option<&str>,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(CAMERAS_DIGEST_DOMAIN);
    enc.bool(true);
    snapshot.anchor.encode_canonical(&mut enc);
    enc.digest(descriptor.descriptor_digest());
    enc.u64(status.head_commit_sequence);
    enc.digest(status.history_root);
    enc.text(filter.unwrap_or(""));
    enc.u64(status.cameras.len() as u64);
    for cam in &status.cameras {
        cam.encode_canonical(&mut enc);
    }
    ContentDigest::sha256(&enc.finish())
}

fn fingerprint_offline(
    snapshot: &DeploymentSnapshot,
    filter: Option<&str>,
    reason: &str,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(CAMERAS_DIGEST_DOMAIN);
    enc.bool(false);
    snapshot.anchor.encode_canonical(&mut enc);
    enc.digest(snapshot.ledger_root);
    enc.text(filter.unwrap_or(""));
    enc.text(reason);
    ContentDigest::sha256(&enc.finish())
}
