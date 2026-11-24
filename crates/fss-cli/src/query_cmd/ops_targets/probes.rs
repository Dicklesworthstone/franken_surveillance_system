#![forbid(unsafe_code)]
//! `AOP-006 investigate` bounded cognition-only discriminating probes:
//! - `probe-detect`: bounded `TwoStageCascade` + `ResidentModelPool` (`fss_activity_v1.fmpk`)
//!   over privacy-masked retained import/event segments emitting uncalibrated proposals
//!   (`calibrated: false`, `effects_authorized: false`, `policy_mutated: false`).
//! - `probe-corroborate`: bounded multi-camera geometric/temporal corroboration via C8
//!   `LiveCorroborationEngine` emitting exact [`LiveCorroborationDecision`] outcomes.
//!
//! Semantic plane: `"cognition"` (strictly read-only; never mutates policy or triggers alerts).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError};
use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, CaptureInterval, Completeness, ContentDigest,
    EventId, ExecutionBoundary, KnowledgeState, Plane, PrincipalId, ResponseSafeRetry, SessionId,
};
use fss_fusion::ScoreCalibration;
use fss_reference::agent_orient::{OrientLimits, read_deployment_cancellable};
use fss_reference::ingest::foreground::ForegroundConfig;
use fss_reference::ingest::live_corroborate::{
    BoundedCaptureInterval, CameraTopologyEntry, ClockBasis, ClockEstimatorConfig,
    ClockObservationSample, CorroborationOutcome, LiveCorroborationConfig,
    LiveCorroborationDecision, LiveCorroborationEngine, LiveFusionConfig, LiveObservation,
    MAX_CLOCK_UNCERTAINTY_CEILING_NS, SharedZoneOverlap, SiteTopologyRegistry, TransitCorridor,
};
use fss_reference::ingest::model_pool::{
    CameraPriorityTier, CascadePolicyConfig, FramePixelInput, ResidentModelPool, StreamFrameInput,
    StreamRegistration, TwoStageCascade,
};
use fss_reference::ingest::privacy_mask::current_mask;
use fss_reference::ingest::recorded_decode::{retained_source_capsule, verify_custody};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};
use fss_reference::{ExecBudget, KernelBackend, ScalarExecCx};

use super::{
    CAP_AGENT_INVESTIGATE, OpsEnvelopeParams, OpsError, build_readonly_context,
    ensure_deployment_root, is_valid_sha256, open_readonly_source, render_ok_envelope,
    render_refusal_envelope, require_capabilities, resolve_effective_capabilities,
};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string, strings};

/// Registered payload schema for `investigate --transition probe-detect`.
pub const PROBE_DETECT_PAYLOAD_SCHEMA: &str = "fss.agent_ops_probe_detect.v1";
/// Canonical digest domain for `probe-detect` uncalibrated proposal attachments.
pub const PROBE_DETECT_DIGEST_DOMAIN: &str = "fss.ops_targets.probe_detect.v1";
/// Registered payload schema for `investigate --transition probe-corroborate`.
pub const PROBE_CORROBORATE_PAYLOAD_SCHEMA: &str = "fss.agent_ops_probe_corroborate.v1";
/// Canonical digest domain for `probe-corroborate` decisions.
pub const PROBE_CORROBORATE_DIGEST_DOMAIN: &str = "fss.ops_targets.probe_corroborate.v1";
/// Maximum retained frames evaluated by a single bounded `probe-detect` pass.
pub const MAX_PROBE_DETECT_FRAMES: usize = 16;
/// Maximum cameras declared in a single bounded `probe-corroborate` call.
pub const MAX_PROBE_CORROBORATE_CAMERAS: usize = 8;
/// Maximum observations evaluated in a single bounded `probe-corroborate` call.
pub const MAX_PROBE_CORROBORATE_OBSERVATIONS: usize = 16;

/// Request parameters for bounded cognition-only `probe-detect`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDetectRequest {
    /// Existing deployment root directory (opened strictly read-only).
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Owning session identity.
    pub session_id: SessionId,
    /// Investigation case identifier this uncalibrated proposal attaches to.
    pub case_id: String,
    /// Hypothesis identifier inside `case_id`.
    pub hypothesis_id: String,
    /// Optional retained event identifier to resolve backing import segments.
    pub event_id: Option<EventId>,
    /// Optional exact completed file import identity SHA-256.
    pub import_id: Option<ContentDigest>,
    /// Maximum frames to evaluate (`1..=16`).
    pub max_frames: usize,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Camera topology declaration for a bounded `probe-corroborate` pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborateCameraSpec {
    /// Stable camera sensor identifier.
    pub sensor_id: String,
    /// Declared failure domains (`wifi:home`, `power:poe-1`, etc.).
    pub failure_domains: BTreeSet<String>,
    /// Logical zones observed by this camera.
    pub zones: BTreeSet<String>,
}

/// Transit corridor specification for `probe-corroborate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborateCorridorSpec {
    /// Stable corridor identifier.
    pub corridor_id: String,
    /// Origin camera sensor ID.
    pub from_camera: String,
    /// Origin zone ID.
    pub from_zone: String,
    /// Destination camera sensor ID.
    pub to_camera: String,
    /// Destination zone ID.
    pub to_zone: String,
    /// Minimum transit time in nanoseconds.
    pub min_transit_ns: u64,
    /// Maximum transit time in nanoseconds.
    pub max_transit_ns: u64,
    /// Whether traversal is admitted in both directions.
    pub bidirectional: bool,
}

/// Observation input submitted to `probe-corroborate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborateObservationSpec {
    /// Camera sensor ID that produced this observation.
    pub sensor_id: String,
    /// Zone ID where the observation occurred.
    pub zone_id: String,
    /// Track identity.
    pub track_id: u64,
    /// Class label (e.g. `"person"`, `"vehicle"`).
    pub class_label: String,
    /// Detection score in integer parts-per-million (`0..=1_000_000`).
    pub score_ppm: u32,
    /// Earliest capture-time bound (Unix ns).
    pub earliest_ns: i128,
    /// Latest capture-time bound (Unix ns).
    pub latest_ns: i128,
}

/// Request parameters for bounded cognition-only `probe-corroborate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeCorroborateRequest {
    /// Existing deployment root directory (pinned read-only to current anchor).
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Owning session identity.
    pub session_id: SessionId,
    /// Optional investigation case identifier.
    pub case_id: Option<String>,
    /// Optional hypothesis identifier.
    pub hypothesis_id: Option<String>,
    /// Camera topology entries (`2..=8`).
    pub cameras: Vec<CorroborateCameraSpec>,
    /// Optional directed/bidirectional transit corridors (`0..=8`).
    pub corridors: Vec<CorroborateCorridorSpec>,
    /// Cross-camera observations (`2..=16`).
    pub observations: Vec<CorroborateObservationSpec>,
    /// Maximum tolerable capture-interval clock uncertainty (ns).
    pub max_clock_uncertainty_ns: u64,
    /// Maximum shared-zone concurrent time separation (ns).
    pub shared_zone_max_separation_ns: u64,
    /// Whether to apply reference Wilson score calibration counts for probe evaluation.
    pub use_probe_calibration: bool,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Executes `investigate --transition probe-detect` and renders an `AgentResponseEnvelope`.
pub(crate) fn execute_probe_detect(
    req: &ProbeDetectRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_probe_detect(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "investigate",
            &req.principal,
            Some(&req.session_id),
            PROBE_DETECT_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

/// Executes `investigate --transition probe-corroborate` and renders an `AgentResponseEnvelope`.
pub(crate) fn execute_probe_corroborate(
    req: &ProbeCorroborateRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_probe_corroborate(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "investigate",
            &req.principal,
            Some(&req.session_id),
            PROBE_CORROBORATE_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run_probe_detect<'a>(
    req: &'a ProbeDetectRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<OpsEnvelopeParams<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    if !(1..=MAX_PROBE_DETECT_FRAMES).contains(&req.max_frames) {
        return Err(OpsError::BoundsExceeded(format!(
            "probe-detect max_frames must be in 1..={MAX_PROBE_DETECT_FRAMES}"
        )));
    }
    let effective = resolve_effective_capabilities(
        &req.root,
        &req.principal,
        Some(&req.session_id),
        &req.granted_capabilities,
    )?;
    require_capabilities(
        &effective,
        &[CAP_AGENT_INVESTIGATE],
        "investigate --transition probe-detect",
    )?;
    ensure_deployment_root(&req.root)?;
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    let (_, cx) = build_readonly_context(&req.root, &snapshot.site_lineage, &req.principal, &[])?;
    let owner = open_readonly_source(&req.root, &cx, cancelled)?;

    let import_id = resolve_probe_import(&owner, req)?;
    let read_limits = RetainedReadLimits::default();
    let retained = RetainedFileImport::open(&owner, import_id, read_limits, &cx)
        .map_err(|err| OpsError::NotFound(format!("retained import unavailable: {err}")))?;
    let total_segments = retained.manifest().segment_spans.len();
    if total_segments == 0 {
        return Err(OpsError::NotFound(
            "retained import contains zero segments".into(),
        ));
    }
    let first_capsule = retained_source_capsule(&owner, &retained, 0)
        .map_err(|err| OpsError::OperationFailed(format!("capsule read refused: {err}")))?;
    let sensor_id = first_capsule.sensor_id.clone();
    let mask_binding = current_mask(&owner, &sensor_id).map_err(|err| {
        OpsError::OperationFailed(format!("privacy mask resolution failed: {err}"))
    })?;
    let eval_count = total_segments.min(req.max_frames);
    let mut chunks = VerifiedChunkCache::default();
    type DecodedProbeFrame = (usize, CaptureInterval, Vec<u8>, [u32; 2], ContentDigest);
    let mut decoded_frames: Vec<DecodedProbeFrame> = Vec::with_capacity(eval_count);
    for seg_idx in 0..eval_count {
        if cancelled() {
            return Err(OpsError::Cancelled);
        }
        let capsule = retained_source_capsule(&owner, &retained, seg_idx)
            .map_err(|err| OpsError::OperationFailed(format!("capsule read refused: {err}")))?;
        let (mut rgb, dims) = decode_mjpeg_segment(
            &owner,
            &retained,
            seg_idx,
            &capsule,
            read_limits,
            &mut chunks,
            &cx,
            cancelled,
        )?;
        mask_binding
            .apply_rgb(&mut rgb, dims)
            .map_err(|err| OpsError::OperationFailed(format!("privacy mask failed: {err}")))?;
        let digest = ContentDigest::sha256(&rgb);
        decoded_frames.push((seg_idx, capsule.capture, rgb, dims, digest));
    }
    cx.drain_and_finalize();

    let first_dims = decoded_frames
        .first()
        .map(|(_, _, _, d, _)| *d)
        .ok_or_else(|| OpsError::NotFound("no decoded frames available".into()))?;
    let mut cascade = TwoStageCascade::new(CascadePolicyConfig {
        foreground: ForegroundConfig {
            base_threshold: 20,
            threshold_sigma: 2,
            learning_rate_num: 16,
            learning_rate_den: 256,
            minimum_region_pixels: 8,
            dimensions: first_dims,
        },
        min_foreground_pixels_trigger: 8,
        sentinel_interval_frames: 4,
        post_motion_hold_frames: 1,
        quiescent_keyframe_only: false,
        sentinel_on_first_keyframe: true,
        enable_sensor_health: false,
        health_max_samples_per_stream: 65_536,
    })
    .map_err(|err| OpsError::OperationFailed(format!("cascade setup failed: {err}")))?;
    cascade
        .register_stream(StreamRegistration {
            sensor_id: sensor_id.clone(),
            stream_order: 0,
            priority: CameraPriorityTier::Standard,
            dimensions: first_dims,
            ignore_regions: Vec::new(),
        })
        .map_err(|err| OpsError::OperationFailed(format!("stream registration failed: {err}")))?;

    let exec_cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool
        .load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &exec_cx)
        .map_err(|err| OpsError::OperationFailed(format!("resident model load failed: {err}")))?;
    let infer_budget = ExecBudget {
        max_macs: 64 * 1024 * 1024,
        max_bytes: 64 * 1024 * 1024,
    };
    let ref_pixels = decoded_frames
        .first()
        .map(|(_, _, px, _, _)| px.as_slice())
        .ok_or_else(|| OpsError::NotFound("missing reference frame".into()))?;

    let mut frame_rows = Vec::with_capacity(decoded_frames.len());
    let (mut triggered_count, mut max_score_ppm, mut total_macs) = (0_usize, 0_u32, 0_u64);
    let mut prop_enc = CanonicalEncoder::new();
    prop_enc.text(PROBE_DETECT_DIGEST_DOMAIN);
    snapshot.anchor.encode_canonical(&mut prop_enc);
    prop_enc.text(&req.case_id);
    prop_enc.text(&req.hypothesis_id);
    prop_enc.digest(import_id);
    prop_enc.digest(resident.resident_digest());

    for (seg_idx, capture_time, rgb, dims, masked_digest) in &decoded_frames {
        if *dims != first_dims {
            continue;
        }
        let stage1 = cascade
            .evaluate_stage1(
                &StreamFrameInput {
                    sensor_id: sensor_id.clone(),
                    frame_sequence: *seg_idx as u64,
                    capture_interval: *capture_time,
                    source_digest: *masked_digest,
                    dimensions: *dims,
                    is_keyframe: true,
                    pixels: FramePixelInput::Rgb {
                        pixels: rgb.clone(),
                    },
                },
                None,
            )
            .map_err(|err| OpsError::OperationFailed(format!("stage1 cascade failed: {err}")))?;
        let inferred = resident
            .infer_activity(rgb, 3, ref_pixels, 3, *dims, infer_budget, &exec_cx)
            .map_err(|err| {
                OpsError::OperationFailed(format!("activity inference failed: {err}"))
            })?;
        pool.record_inference();
        let score = inferred
            .activity_score_bits
            .map(f32::from_bits)
            .filter(|v| v.is_finite())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let score_ppm = (score * 1_000_000.0).round() as u32;
        max_score_ppm = max_score_ppm.max(score_ppm);
        total_macs = total_macs.saturating_add(inferred.executed_macs);
        if stage1.telemetry.foreground_pixels > 0 {
            triggered_count += 1;
        }
        prop_enc.u64(*seg_idx as u64);
        prop_enc.digest(inferred.output_digest);
        prop_enc.u32(score_ppm);
        frame_rows.push(object(&[
            ("segmentIndex", seg_idx.to_string()),
            (
                "stage1Decision",
                string(&format!("{:?}", stage1.stage_decision)),
            ),
            (
                "foregroundPixels",
                stage1.telemetry.foreground_pixels.to_string(),
            ),
            ("uncalibratedScorePpm", score_ppm.to_string()),
            ("outputDigest", string(&inferred.output_digest.to_text())),
            ("executedMacs", inferred.executed_macs.to_string()),
            ("calibrated", "false".to_owned()),
        ]));
    }
    let proposal_digest = ContentDigest::sha256(&prop_enc.finish());
    let payload_json = object(&[
        ("schema", string(PROBE_DETECT_PAYLOAD_SCHEMA)),
        ("proposalDigest", string(&proposal_digest.to_text())),
        ("caseId", string(&req.case_id)),
        ("hypothesisId", string(&req.hypothesis_id)),
        ("importId", string(&import_id.to_text())),
        ("sensorId", string(sensor_id.as_str())),
        ("privacyMaskBinding", string(mask_binding.label())),
        ("modelId", string(&resident.key().model_id)),
        ("modelGeneration", string(&resident.key().model_generation)),
        (
            "residentDigest",
            string(&resident.resident_digest().to_text()),
        ),
        ("framesEvaluated", frame_rows.len().to_string()),
        ("stage1TriggeredFrames", triggered_count.to_string()),
        ("maxUncalibratedScorePpm", max_score_ppm.to_string()),
        ("totalExecutedMacs", total_macs.to_string()),
        ("proposals", array(&frame_rows)),
        ("calibrated", "false".to_owned()),
        ("effectsAuthorized", "false".to_owned()),
        ("policyMutated", "false".to_owned()),
    ]);
    Ok(OpsEnvelopeParams {
        operation: "investigate", principal: &req.principal, session_id: Some(&req.session_id),
        anchor: snapshot.anchor.clone(), view: AgentView::Case,
        capabilities: vec![CAP_AGENT_INVESTIGATE.to_owned()],
        privacy_purpose: "cognition-only bounded activity detection probe over privacy-masked frames",
        allowed_domains: &["uncalibrated-activity-probe-proposals", "resident-model-receipt-metadata"],
        redacted_domains: &["unmasked-pixels", "raw-media-bytes"],
        payload_schema: PROBE_DETECT_PAYLOAD_SCHEMA, payload_json,
        epistemic_state: KnowledgeState::Estimated, completeness: Completeness::Bounded,
        warnings: vec!["Uncalibrated cognition-only detection proposal attached to hypothesis; never mutates policy or authorizes alerts.".to_owned()],
        proof_pointers: vec![
            snapshot.anchor.state_root.to_text(), import_id.to_text(),
            resident.resident_digest().to_text(), proposal_digest.to_text(),
        ],
        decision_fingerprint: proposal_digest, idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest, recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![format!("Executed bounded TwoStageCascade + ResidentModelPool activity probe over {} masked frame(s) for case {} hypothesis {}.", frame_rows.len(), req.case_id, req.hypothesis_id)],
            not_started: vec!["No deployment authority was mutated, no policy changed, and no alert was prepared or sent.".to_owned()],
            possibly_occurred: Vec::new(),
            preserved_truth: vec!["Uncalibrated probe scores carry calibrated=false and never trigger effects.".to_owned()],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn run_probe_corroborate<'a>(
    req: &'a ProbeCorroborateRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<OpsEnvelopeParams<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    if !(2..=MAX_PROBE_CORROBORATE_CAMERAS).contains(&req.cameras.len()) {
        return Err(OpsError::BoundsExceeded(format!(
            "probe-corroborate requires 2..={MAX_PROBE_CORROBORATE_CAMERAS} cameras"
        )));
    }
    if !(2..=MAX_PROBE_CORROBORATE_OBSERVATIONS).contains(&req.observations.len()) {
        return Err(OpsError::BoundsExceeded(format!(
            "probe-corroborate requires 2..={MAX_PROBE_CORROBORATE_OBSERVATIONS} observations"
        )));
    }
    if req.max_clock_uncertainty_ns == 0
        || req.max_clock_uncertainty_ns > MAX_CLOCK_UNCERTAINTY_CEILING_NS
    {
        return Err(OpsError::InvalidRequest(
            "max_clock_uncertainty_ns outside admitted range".into(),
        ));
    }
    let effective = resolve_effective_capabilities(
        &req.root,
        &req.principal,
        Some(&req.session_id),
        &req.granted_capabilities,
    )?;
    require_capabilities(
        &effective,
        &[CAP_AGENT_INVESTIGATE],
        "investigate --transition probe-corroborate",
    )?;
    ensure_deployment_root(&req.root)?;
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;

    let mut topology = SiteTopologyRegistry::new(&snapshot.site_lineage);
    let mut zone_cameras: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for cam in &req.cameras {
        for zone in &cam.zones {
            zone_cameras
                .entry(zone.clone())
                .or_default()
                .insert(cam.sensor_id.clone());
        }
        topology.register_camera(CameraTopologyEntry {
            sensor_id: cam.sensor_id.clone(),
            failure_domains: cam.failure_domains.clone(),
            homography: None,
            zones: cam.zones.clone(),
        });
    }
    for (zone_id, cams) in zone_cameras {
        if cams.len() >= 2 {
            topology.add_shared_zone(SharedZoneOverlap {
                zone_id,
                cameras: cams,
                max_separation_ns: req.shared_zone_max_separation_ns,
            });
        }
    }
    for c in &req.corridors {
        topology.add_transit_corridor(TransitCorridor {
            corridor_id: c.corridor_id.clone(),
            from_camera: c.from_camera.clone(),
            from_zone: c.from_zone.clone(),
            to_camera: c.to_camera.clone(),
            to_zone: c.to_zone.clone(),
            min_transit_ns: c.min_transit_ns,
            max_transit_ns: c.max_transit_ns,
            bidirectional: c.bidirectional,
        });
    }

    let mut fusion_cfg = LiveFusionConfig::default_policy()
        .map_err(|err| OpsError::OperationFailed(format!("fusion config failed: {err}")))?;
    if req.use_probe_calibration {
        let cal = ScoreCalibration::from_counts(
            "cal:probe-corroborate:v1",
            &[0, 500_000, 800_000],
            &[(2, 80), (15, 19), (95, 1)],
        )
        .map_err(|err| OpsError::OperationFailed(format!("calibration init failed: {err}")))?;
        fusion_cfg = fusion_cfg.with_default_calibration(cal);
    }
    let config = LiveCorroborationConfig {
        clock: ClockEstimatorConfig {
            max_clock_uncertainty_ns: req.max_clock_uncertainty_ns,
            ..ClockEstimatorConfig::default()
        },
        window: Default::default(),
        fusion: fusion_cfg,
    };
    let mut engine = LiveCorroborationEngine::new(topology, config).map_err(|err| {
        OpsError::InvalidRequest(format!("corroboration topology invalid: {err}"))
    })?;
    for cam in &req.cameras {
        let _ = engine.observe_clock_sample(
            &cam.sensor_id,
            ClockObservationSample {
                media_pts_ns: 1_000_000_000,
                host_receive_ns: 1_000_000_000,
                rtt_jitter_ns: 1_000_000,
                node_clock_uncertainty_ns: 1_000_000,
            },
        );
    }
    let mut decisions: Vec<LiveCorroborationDecision> = Vec::new();
    for (idx, obs) in req.observations.iter().enumerate() {
        let capture = BoundedCaptureInterval::new(
            obs.earliest_ns,
            obs.latest_ns,
            ClockBasis::BoundedReceiveEnvelope,
        )
        .map_err(|err| OpsError::InvalidRequest(format!("invalid capture interval: {err}")))?;
        let tag = format!("probe:{}:{idx}:{}", obs.sensor_id, obs.track_id);
        let emitted = engine
            .ingest_observation(LiveObservation {
                sensor_id: obs.sensor_id.clone(),
                stream_id: "main".to_owned(),
                zone_id: obs.zone_id.clone(),
                track_id: obs.track_id,
                foot_px: None,
                class_label: obs.class_label.clone(),
                score_ppm: obs.score_ppm,
                bounded_capture: capture,
                source_capsule_digest: ContentDigest::sha256(format!("cap:{tag}").as_bytes()),
                model_receipt_digest: ContentDigest::sha256(format!("model:{tag}").as_bytes()),
                cascade_receipt_digest: ContentDigest::sha256(format!("cascade:{tag}").as_bytes()),
            })
            .map_err(|err| OpsError::InvalidRequest(format!("corroboration failed: {err}")))?;
        decisions.extend(emitted);
    }
    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(PROBE_CORROBORATE_DIGEST_DOMAIN);
    snapshot.anchor.encode_canonical(&mut fp_enc);
    fp_enc.digest(engine.topology_digest());
    fp_enc.u64(decisions.len() as u64);
    for d in &decisions {
        fp_enc.digest(d.decision_digest);
    }
    let fingerprint = ContentDigest::sha256(&fp_enc.finish());
    let decision_rows: Vec<String> = decisions
        .iter()
        .map(render_corroboration_decision)
        .collect();
    let traces: Vec<String> = engine.recent_traces().iter().cloned().collect();
    let mut proof_pointers = vec![
        snapshot.anchor.state_root.to_text(),
        engine.topology_digest().to_text(),
        fingerprint.to_text(),
    ];
    proof_pointers.extend(decisions.iter().map(|d| d.decision_digest.to_text()));
    let payload_json = object(&[
        ("schema", string(PROBE_CORROBORATE_PAYLOAD_SCHEMA)),
        (
            "caseId",
            req.case_id
                .as_deref()
                .map_or_else(|| "null".to_owned(), string),
        ),
        (
            "hypothesisId",
            req.hypothesis_id
                .as_deref()
                .map_or_else(|| "null".to_owned(), string),
        ),
        (
            "topologyDigest",
            string(&engine.topology_digest().to_text()),
        ),
        ("decisionCount", decisions.len().to_string()),
        ("decisions", array(&decision_rows)),
        ("auditTraces", strings(&traces)),
        ("effectsAuthorized", "false".to_owned()),
        ("policyMutated", "false".to_owned()),
    ]);
    Ok(OpsEnvelopeParams {
        operation: "investigate", principal: &req.principal, session_id: Some(&req.session_id),
        anchor: snapshot.anchor.clone(), view: AgentView::Case,
        capabilities: vec![CAP_AGENT_INVESTIGATE.to_owned()],
        privacy_purpose: "cognition-only bounded multi-camera geometric/temporal corroboration probe",
        allowed_domains: &["derived-corroboration-decisions", "failure-domain-clusters"],
        redacted_domains: &["media-payloads", "raw-credentials"],
        payload_schema: PROBE_CORROBORATE_PAYLOAD_SCHEMA, payload_json,
        epistemic_state: KnowledgeState::Estimated, completeness: Completeness::Bounded,
        warnings: vec!["Cognition-only corroboration probe; never mutates deployment authority or dispatches alerts.".to_owned()],
        proof_pointers, decision_fingerprint: fingerprint, idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest, recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![format!("Executed LiveCorroborationEngine across {} camera(s) and {} observation(s), emitting {} decision(s).", req.cameras.len(), req.observations.len(), decisions.len())],
            not_started: vec!["No event was published to authority, no policy changed, and no alert was triggered.".to_owned()],
            possibly_occurred: Vec::new(),
            preserved_truth: vec!["Shared failure domains hold as SharedFailureDomainHeld; excessive clock uncertainty abstains as ClockUncertaintyAbstained.".to_owned()],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn resolve_probe_import(
    owner: &ImmutableRetainedSource<'_>,
    req: &ProbeDetectRequest,
) -> Result<ContentDigest, OpsError> {
    if let Some(import_id) = req.import_id {
        if !is_valid_sha256(import_id) {
            return Err(OpsError::InvalidRequest(
                "import_id must be a canonical nonzero SHA-256 digest".into(),
            ));
        }
        return Ok(import_id);
    }
    let Some(event_id) = &req.event_id else {
        return Err(OpsError::InvalidRequest(
            "probe-detect requires either import_id or event_id".into(),
        ));
    };
    let snapshot = owner.snapshot();
    let retained = snapshot.event(event_id).ok_or_else(|| {
        OpsError::NotFound(format!(
            "event {} not found in deployment",
            event_id.as_str()
        ))
    })?;
    let cited: BTreeSet<ContentDigest> = retained
        .event
        .evidence
        .iter()
        .filter_map(|e| e.capsule_digest)
        .collect();
    for batch in owner.ledger().batches() {
        let Some(rest) = batch.batch_id.as_str().strip_prefix("batch:file-import:") else {
            continue;
        };
        let Some((hex_id, _)) = rest.split_once(":c") else {
            continue;
        };
        if batch.deltas.iter().any(|d| {
            d.family == "sensor_capsule"
                && d.plane == Plane::Authority
                && cited.contains(&d.payload_digest)
        }) && let Ok(digest) = ContentDigest::parse(format!("sha256:{hex_id}"))
        {
            return Ok(digest);
        }
    }
    snapshot.completed_imports.first().copied().ok_or_else(|| {
        OpsError::NotFound("event carries no retained file import for probe-detect".into())
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_mjpeg_segment(
    owner: &ImmutableRetainedSource<'_>,
    retained: &RetainedFileImport,
    seg_index: usize,
    capsule: &fss_core::SensorCapsule,
    read_limits: RetainedReadLimits,
    chunks: &mut VerifiedChunkCache,
    cx: &fss_reference::ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<(Vec<u8>, [u32; 2]), OpsError> {
    if retained.manifest().format != "mjpeg" {
        return Err(OpsError::InvalidRequest(format!(
            "probe-detect currently evaluates retained mjpeg imports, found {}",
            retained.manifest().format
        )));
    }
    let encoded = retained
        .read_segment_cached(owner, seg_index, read_limits, cx, chunks)
        .map_err(|err| OpsError::OperationFailed(format!("segment custody read failed: {err}")))?;
    verify_custody(capsule, &encoded)
        .map_err(|err| OpsError::OperationFailed(format!("segment custody mismatch: {err}")))?;
    let rgb_limits = RgbDecodeLimits::default();
    let mut budget = DecodeBudget::with_cancellation_probe(rgb_limits.rgb_work_bound(), cancelled);
    let decoded = match decode_rgb(
        &encoded,
        capsule.source_digest.bytes(),
        ComponentInterpretation::YCbCr,
        rgb_limits,
        &mut budget,
    ) {
        Ok(img) => img,
        Err(DecodeError::Unsupported) => {
            let mut g_budget =
                DecodeBudget::with_cancellation_probe(rgb_limits.rgb_work_bound(), cancelled);
            decode_rgb(
                &encoded,
                capsule.source_digest.bytes(),
                ComponentInterpretation::Grayscale,
                rgb_limits,
                &mut g_budget,
            )
            .map_err(|err| OpsError::OperationFailed(format!("JPEG decode failed: {err}")))?
        }
        Err(DecodeError::Cancelled) => return Err(OpsError::Cancelled),
        Err(err) => {
            return Err(OpsError::OperationFailed(format!(
                "JPEG decode failed: {err}"
            )));
        }
    };
    Ok((decoded.pixels().to_vec(), decoded.dimensions()))
}

fn render_corroboration_decision(decision: &LiveCorroborationDecision) -> String {
    let mut f = vec![
        ("sequence", decision.sequence.to_string()),
        ("outcome", string(decision.outcome.as_str())),
        (
            "decisionDigest",
            string(&decision.decision_digest.to_text()),
        ),
        (
            "topologyDigest",
            string(&decision.topology_digest.to_text()),
        ),
        (
            "mechanism",
            decision
                .match_mechanism
                .as_ref()
                .map_or_else(|| "null".to_owned(), |m| string(m.as_str())),
        ),
    ];
    match &decision.outcome {
        CorroborationOutcome::Corroborated {
            supporting_clusters,
            posterior,
            probability_ppm,
            fusion_decision_digest,
            event,
            alert_eligible,
            ..
        } => {
            f.extend([
                ("supportingClusters", supporting_clusters.to_string()),
                (
                    "posteriorMillibans",
                    format!("[{},{}]", posterior.lo(), posterior.hi()),
                ),
                (
                    "probabilityPpm",
                    format!("[{},{}]", probability_ppm.0, probability_ppm.1),
                ),
                (
                    "fusionDecisionDigest",
                    string(&fusion_decision_digest.to_text()),
                ),
                ("eventId", string(event.event_id.as_str())),
                ("eventState", string(event.state.as_str())),
                ("alertEligible", alert_eligible.to_string()),
            ]);
        }
        CorroborationOutcome::SharedFailureDomainHeld {
            supporting_clusters,
            shared_domains,
            requires_operator_confirmation,
            explanation,
            posterior,
            fusion_decision_digest,
            event,
            ..
        } => {
            f.extend([
                ("supportingClusters", supporting_clusters.to_string()),
                ("sharedDomains", strings(shared_domains)),
                (
                    "requiresOperatorConfirmation",
                    requires_operator_confirmation.to_string(),
                ),
                ("explanation", string(explanation)),
                (
                    "posteriorMillibans",
                    format!("[{},{}]", posterior.lo(), posterior.hi()),
                ),
                (
                    "fusionDecisionDigest",
                    string(&fusion_decision_digest.to_text()),
                ),
                ("eventId", string(event.event_id.as_str())),
                ("eventState", string(event.state.as_str())),
            ]);
        }
        CorroborationOutcome::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
            sensor_ids,
            explanation,
        } => {
            f.extend([
                ("uncertaintyNs", string(&uncertainty_ns.to_string())),
                ("maxAllowedNs", string(&max_allowed_ns.to_string())),
                ("sensorIds", strings(sensor_ids)),
                ("explanation", string(explanation)),
            ]);
        }
        CorroborationOutcome::InsufficientEvidenceHeld {
            supporting_clusters,
            posterior,
            fusion_decision,
            fusion_decision_digest,
            event,
            explanation,
            ..
        } => {
            f.extend([
                ("supportingClusters", supporting_clusters.to_string()),
                (
                    "posteriorMillibans",
                    format!("[{},{}]", posterior.lo(), posterior.hi()),
                ),
                ("fusionDecision", string(fusion_decision.as_str())),
                (
                    "fusionDecisionDigest",
                    string(&fusion_decision_digest.to_text()),
                ),
                ("eventId", string(event.event_id.as_str())),
                ("eventState", string(event.state.as_str())),
                ("explanation", string(explanation)),
            ]);
        }
    }
    object(&f)
}
