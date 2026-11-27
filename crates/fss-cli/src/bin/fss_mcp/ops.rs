#![forbid(unsafe_code)]
//! Strict MCP adapter routing typed operational `query` targets, `investigate` discriminating
//! probes, and approval-gated `plan`/`commit` intent families into [`fss_cli::query_cmd::ops_targets`].
//!
//! Semantic plane: `"cognition"` (pure bounded wire-argument validator; performs zero I/O,
//! accepts zero authority/path/capability/shell overrides from clients, and forwards only
//! launcher-granted capabilities).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::PathBuf;

use fss_cli::FssCommand;
use fss_cli::query_cmd::QueryArgs;
use fss_cli::query_cmd::ops_targets::OpsDispatch;
use fss_cli::query_cmd::ops_targets::cameras::CamerasQueryRequest;
use fss_cli::query_cmd::ops_targets::fusion::{FusionEvidenceInput, FusionQueryRequest};
use fss_cli::query_cmd::ops_targets::graph::{
    GraphAlgorithmKind, GraphProjectionKind, GraphQueryRequest,
};
use fss_cli::query_cmd::ops_targets::holds_masks::{HoldsQueryRequest, PrivacyMasksQueryRequest};
use fss_cli::query_cmd::ops_targets::intents::{OpsIntentKind, OpsIntentRequest};
use fss_cli::query_cmd::ops_targets::probes::{
    CorroborateCameraSpec, CorroborateCorridorSpec, CorroborateObservationSpec,
    MAX_PROBE_CORROBORATE_CAMERAS, MAX_PROBE_CORROBORATE_OBSERVATIONS, MAX_PROBE_DETECT_FRAMES,
    ProbeCorroborateRequest, ProbeDetectRequest,
};
use fss_core::{ContentDigest, DigestAlgorithm, EventId, PrincipalId, SensorId, SessionId};
use fss_ipc::BoundedControlOp;
use fss_reference::agent_query::{DEFAULT_QUERY_ENTRIES, EventQueryFilter, EventQueryRequest};

use super::json::Value;

pub(super) type Refusal = (i32, &'static str);
const INVALID_ARGS: Refusal = (
    -32602,
    "Unexpected operational argument or authority override",
);

/// Returns `true` when `args.target` selects one of the 5 operational `AOP-005 query` targets.
pub(super) fn selects_query_target(args: &BTreeMap<String, Value>) -> bool {
    matches!(
        args.get("target").and_then(Value::text),
        Some("cameras" | "graph" | "fusion" | "holds" | "privacy-masks")
    )
}

/// Returns `true` when `transition` selects a bounded cognition-only discriminating probe.
pub(super) fn selects_investigate_transition(transition: &str) -> bool {
    matches!(transition, "probe-detect" | "probe-corroborate")
}

/// Returns `true` when `(name, args.intent)` selects a typed operational `plan`/`commit` intent.
pub(super) fn selects_control_intent(name: &str, args: &BTreeMap<String, Value>) -> bool {
    matches!(name, "plan" | "commit")
        && matches!(
            args.get("intent").and_then(Value::text),
            Some("privacy-mask" | "evidence-hold" | "retention-policy" | "camera-supervision")
        )
}

/// Translates an MCP `query` tool call for operational targets into an admitted [`FssCommand`].
pub(super) fn query_command(
    root: &OsStr,
    principal: &str,
    granted_capabilities: &[String],
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let target = args
        .get("target")
        .and_then(Value::text)
        .ok_or((-32602, "Expected operational query target"))?;
    let root_path = PathBuf::from(root);
    let principal_id = parse_principal(principal)?;
    let grants: BTreeSet<String> = granted_capabilities.iter().cloned().collect();
    let dispatch = match target {
        "cameras" => {
            allow_only(args, &["target", "session", "camera_id", "site_id"])?;
            OpsDispatch::Cameras(CamerasQueryRequest {
                root: root_path.clone(),
                principal: principal_id.clone(),
                session_id: optional_session(args)?,
                camera_id: optional_clean_text(args, "camera_id", 128)?,
                site_id: optional_clean_text(args, "site_id", 128)?,
                granted_capabilities: grants,
            })
        }
        "graph" => {
            allow_only(
                args,
                &["target", "session", "projection", "algorithm", "root_node"],
            )?;
            let proj_str = optional_clean_text(args, "projection", 64)?
                .unwrap_or_else(|| "SensorCoverageGraph".to_owned());
            let algo_str = optional_clean_text(args, "algorithm", 64)?
                .unwrap_or_else(|| "ALG-BRIDGE-001".to_owned());
            OpsDispatch::Graph(GraphQueryRequest {
                root: root_path.clone(),
                principal: principal_id.clone(),
                session_id: optional_session(args)?,
                projection: GraphProjectionKind::parse(&proj_str)
                    .map_err(|_| (-32602, "Unsupported Certified Graph Atlas projection"))?,
                algorithm: GraphAlgorithmKind::parse(&algo_str)
                    .map_err(|_| (-32602, "Unsupported Certified Graph Atlas algorithm"))?,
                root_node: optional_clean_text(args, "root_node", 128)?,
                granted_capabilities: grants,
            })
        }
        "fusion" => parse_fusion_query(&root_path, &principal_id, grants, args)?,
        "holds" => {
            allow_only(
                args,
                &[
                    "target",
                    "session",
                    "sensor",
                    "attested_earliest_ns",
                    "attested_latest_ns",
                ],
            )?;
            OpsDispatch::Holds(HoldsQueryRequest {
                root: root_path.clone(),
                principal: principal_id.clone(),
                session_id: optional_session(args)?,
                sensor: optional_sensor(args, "sensor")?,
                attested_now_ns: parse_optional_interval(
                    args,
                    "attested_earliest_ns",
                    "attested_latest_ns",
                )?,
                granted_capabilities: grants,
            })
        }
        "privacy-masks" => {
            allow_only(args, &["target", "session", "sensor"])?;
            OpsDispatch::PrivacyMasks(PrivacyMasksQueryRequest {
                root: root_path.clone(),
                principal: principal_id.clone(),
                session_id: optional_session(args)?,
                sensor: optional_sensor(args, "sensor")?,
                granted_capabilities: grants,
            })
        }
        _ => return Err((-32602, "Unsupported operational query target")),
    };
    Ok(wrap_dispatch(root_path, principal_id, dispatch))
}

/// Translates an MCP `investigate` discriminating probe call into an admitted [`FssCommand`].
pub(super) fn investigate_command(
    root: &OsStr,
    principal: &str,
    granted_capabilities: &[String],
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let transition = args
        .get("transition")
        .and_then(Value::text)
        .ok_or((-32602, "Expected investigation transition"))?;
    let root_path = PathBuf::from(root);
    let principal_id = parse_principal(principal)?;
    let grants: BTreeSet<String> = granted_capabilities.iter().cloned().collect();
    let dispatch = match transition {
        "probe-detect" => parse_probe_detect(&root_path, &principal_id, grants, args)?,
        "probe-corroborate" => parse_probe_corroborate(&root_path, &principal_id, grants, args)?,
        _ => return Err((-32602, "Unsupported probe transition")),
    };
    Ok(wrap_dispatch(root_path, principal_id, dispatch))
}

/// Translates an MCP `plan` or `commit` operational intent call into an admitted [`FssCommand`].
pub(super) fn control_command(
    name: &str,
    root: &OsStr,
    principal: &str,
    granted_capabilities: &[String],
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let is_commit = match name {
        "plan" => false,
        "commit" => true,
        _ => return Err((-32602, "Operational intents support only plan and commit")),
    };
    let intent_name = args
        .get("intent")
        .and_then(Value::text)
        .ok_or((-32602, "Expected operational intent"))?;
    let root_path = PathBuf::from(root);
    let principal_id = parse_principal(principal)?;
    let grants: BTreeSet<String> = granted_capabilities.iter().cloned().collect();
    if !is_commit && (args.contains_key("approval_digest") || args.contains_key("approve")) {
        return Err((
            -32602,
            "plan preview does not accept approval_digest or approve",
        ));
    }
    if args.contains_key("approval_digest") && args.contains_key("approve") {
        return Err((-32602, "Supply approval_digest or approve, not both"));
    }
    let approval_digest = if is_commit {
        args.get("approval_digest")
            .or_else(|| args.get("approve"))
            .map(parse_sha256_value)
            .transpose()?
    } else {
        None
    };
    let intent = match intent_name {
        "privacy-mask" => parse_intent_privacy_mask(args, is_commit)?,
        "evidence-hold" => parse_intent_evidence_hold(args, is_commit)?,
        "retention-policy" => parse_intent_retention_policy(args, is_commit)?,
        "camera-supervision" => parse_intent_camera_supervision(args, is_commit)?,
        _ => return Err((-32602, "Unsupported operational intent")),
    };
    let req = OpsIntentRequest {
        root: root_path.clone(),
        principal: principal_id.clone(),
        session_id: optional_session(args)?,
        intent,
        approval_digest,
        granted_capabilities: grants,
    };
    let dispatch = if is_commit {
        OpsDispatch::CommitIntent(req)
    } else {
        OpsDispatch::PlanIntent(req)
    };
    Ok(wrap_dispatch(root_path, principal_id, dispatch))
}

fn wrap_dispatch(root: PathBuf, principal: PrincipalId, dispatch: OpsDispatch) -> FssCommand {
    FssCommand::Query(QueryArgs {
        root,
        at: None,
        request: EventQueryRequest {
            filter: EventQueryFilter {
                event_id: None,
                kind: None,
                state: None,
                zone: None,
                from_ns: None,
                through_ns: None,
            },
            principal,
            max_entries: DEFAULT_QUERY_ENTRIES,
            expected_anchor: None,
            continuation: None,
        },
        ops: Some(dispatch),
    })
}

fn parse_fusion_query(
    root: &std::path::Path,
    principal: &PrincipalId,
    grants: BTreeSet<String>,
    args: &BTreeMap<String, Value>,
) -> Result<OpsDispatch, Refusal> {
    allow_only(
        args,
        &[
            "target",
            "session",
            "event_id",
            "evidence",
            "prior_lo",
            "prior_hi",
            "coverage",
            "alert_threshold",
            "retain_threshold",
            "reject_threshold",
            "min_independent_support",
            "without_sensors",
            "without_domains",
        ],
    )?;
    let event_id = optional_clean_text(args, "event_id", 128)?
        .map(|raw| EventId::parse(raw).map_err(|_| (-32602, "Invalid event_id")))
        .transpose()?;
    let evidence = match args.get("evidence") {
        None => Vec::new(),
        Some(Value::Array(items)) if items.len() <= 32 => items
            .iter()
            .map(parse_fusion_evidence_item)
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err((
                -32602,
                "evidence must be a bounded array of at most 32 objects",
            ));
        }
    };
    Ok(OpsDispatch::Fusion(FusionQueryRequest {
        root: root.to_path_buf(),
        principal: principal.clone(),
        session_id: optional_session(args)?,
        event_id,
        evidence,
        prior: (
            optional_i64(args, "prior_lo", -100_000, 100_000)?.unwrap_or(-500),
            optional_i64(args, "prior_hi", -100_000, 100_000)?.unwrap_or(-400),
        ),
        coverage_state: optional_clean_text(args, "coverage", 32)?
            .unwrap_or_else(|| "complete".to_owned()),
        alert_threshold: optional_i64(args, "alert_threshold", -100_000, 100_000)?.unwrap_or(1000),
        retain_threshold: optional_i64(args, "retain_threshold", -100_000, 100_000)?.unwrap_or(0),
        reject_threshold: optional_i64(args, "reject_threshold", -100_000, 100_000)?
            .unwrap_or(-1000),
        min_independent_support: optional_u64(args, "min_independent_support", 1, 16)?.unwrap_or(2)
            as u32,
        without_sensors: optional_string_vec(args, "without_sensors", 16, 128)?,
        without_domains: optional_string_vec(args, "without_domains", 16, 128)?,
        granted_capabilities: grants,
    }))
}

fn parse_fusion_evidence_item(val: &Value) -> Result<FusionEvidenceInput, Refusal> {
    let obj = val
        .object()
        .ok_or((-32602, "evidence item must be an object"))?;
    allow_only(
        obj,
        &[
            "id",
            "sensor",
            "failure_domains",
            "llr_lo",
            "llr_hi",
            "calibration_generation",
            "uncalibrated_reason",
            "observability",
        ],
    )?;
    let llr = match (
        optional_i64(obj, "llr_lo", -100_000, 100_000)?,
        optional_i64(obj, "llr_hi", -100_000, 100_000)?,
    ) {
        (Some(lo), Some(hi)) => Some((lo, hi)),
        (None, None) => None,
        _ => {
            return Err((
                -32602,
                "evidence requires both llr_lo and llr_hi or neither",
            ));
        }
    };
    Ok(FusionEvidenceInput {
        id: required_clean_text(obj, "id", 128)?,
        sensor: required_clean_text(obj, "sensor", 128)?,
        failure_domains: optional_string_vec(obj, "failure_domains", 16, 128)?
            .into_iter()
            .collect(),
        llr,
        calibration_generation: optional_clean_text(obj, "calibration_generation", 128)?,
        uncalibrated_reason: optional_clean_text(obj, "uncalibrated_reason", 256)?,
        observability: optional_clean_text(obj, "observability", 32)?
            .unwrap_or_else(|| "observed".to_owned()),
    })
}

fn parse_probe_detect(
    root: &std::path::Path,
    principal: &PrincipalId,
    grants: BTreeSet<String>,
    args: &BTreeMap<String, Value>,
) -> Result<OpsDispatch, Refusal> {
    allow_only(
        args,
        &[
            "transition",
            "session",
            "case_id",
            "hypothesis_id",
            "event_id",
            "import_id",
            "max_frames",
        ],
    )?;
    let event_id = optional_clean_text(args, "event_id", 128)?
        .map(|v| EventId::parse(v).map_err(|_| (-32602, "Invalid event_id")))
        .transpose()?;
    let import_id = args.get("import_id").map(parse_sha256_value).transpose()?;
    if event_id.is_none() && import_id.is_none() {
        return Err((-32602, "probe-detect requires event_id or import_id"));
    }
    Ok(OpsDispatch::ProbeDetect(ProbeDetectRequest {
        root: root.to_path_buf(),
        principal: principal.clone(),
        session_id: required_session(args)?,
        case_id: required_clean_text(args, "case_id", 128)?,
        hypothesis_id: required_clean_text(args, "hypothesis_id", 128)?,
        event_id,
        import_id,
        max_frames: optional_u64(args, "max_frames", 1, MAX_PROBE_DETECT_FRAMES as u64)?
            .unwrap_or(4) as usize,
        granted_capabilities: grants,
    }))
}

fn parse_probe_corroborate(
    root: &std::path::Path,
    principal: &PrincipalId,
    grants: BTreeSet<String>,
    args: &BTreeMap<String, Value>,
) -> Result<OpsDispatch, Refusal> {
    allow_only(
        args,
        &[
            "transition",
            "session",
            "case_id",
            "hypothesis_id",
            "cameras",
            "corridors",
            "observations",
            "max_clock_uncertainty_ns",
            "shared_zone_max_separation_ns",
            "use_probe_calibration",
        ],
    )?;
    let cam_arr = match args.get("cameras") {
        Some(Value::Array(items)) if (2..=MAX_PROBE_CORROBORATE_CAMERAS).contains(&items.len()) => {
            items
        }
        _ => return Err((-32602, "probe-corroborate requires 2..=8 camera objects")),
    };
    let mut cameras = Vec::with_capacity(cam_arr.len());
    for item in cam_arr {
        let obj = item
            .object()
            .ok_or((-32602, "camera entry must be an object"))?;
        allow_only(obj, &["sensor_id", "failure_domains", "zones"])?;
        cameras.push(CorroborateCameraSpec {
            sensor_id: required_clean_text(obj, "sensor_id", 128)?,
            failure_domains: optional_string_vec(obj, "failure_domains", 16, 128)?
                .into_iter()
                .collect(),
            zones: optional_string_vec(obj, "zones", 16, 128)?
                .into_iter()
                .collect(),
        });
    }
    let corridors = match args.get("corridors") {
        None => Vec::new(),
        Some(Value::Array(items)) if items.len() <= 8 => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let obj = item
                    .object()
                    .ok_or((-32602, "corridor entry must be an object"))?;
                allow_only(
                    obj,
                    &[
                        "corridor_id",
                        "from_camera",
                        "from_zone",
                        "to_camera",
                        "to_zone",
                        "min_transit_ns",
                        "max_transit_ns",
                        "bidirectional",
                    ],
                )?;
                out.push(CorroborateCorridorSpec {
                    corridor_id: required_clean_text(obj, "corridor_id", 128)?,
                    from_camera: required_clean_text(obj, "from_camera", 128)?,
                    from_zone: required_clean_text(obj, "from_zone", 128)?,
                    to_camera: required_clean_text(obj, "to_camera", 128)?,
                    to_zone: required_clean_text(obj, "to_zone", 128)?,
                    min_transit_ns: required_u64(obj, "min_transit_ns", 0, u64::MAX)?,
                    max_transit_ns: required_u64(obj, "max_transit_ns", 1, u64::MAX)?,
                    bidirectional: optional_bool(obj, "bidirectional")?.unwrap_or(true),
                });
            }
            out
        }
        _ => return Err((-32602, "corridors must be an array of at most 8 objects")),
    };
    let obs_arr = match args.get("observations") {
        Some(Value::Array(items))
            if (2..=MAX_PROBE_CORROBORATE_OBSERVATIONS).contains(&items.len()) =>
        {
            items
        }
        _ => {
            return Err((
                -32602,
                "probe-corroborate requires 2..=16 observation objects",
            ));
        }
    };
    let mut observations = Vec::with_capacity(obs_arr.len());
    for item in obs_arr {
        let obj = item
            .object()
            .ok_or((-32602, "observation entry must be an object"))?;
        allow_only(
            obj,
            &[
                "sensor_id",
                "zone_id",
                "track_id",
                "class_label",
                "score_ppm",
                "earliest_ns",
                "latest_ns",
            ],
        )?;
        observations.push(CorroborateObservationSpec {
            sensor_id: required_clean_text(obj, "sensor_id", 128)?,
            zone_id: required_clean_text(obj, "zone_id", 128)?,
            track_id: required_u64(obj, "track_id", 0, u64::MAX)?,
            class_label: required_clean_text(obj, "class_label", 64)?,
            score_ppm: required_u64(obj, "score_ppm", 0, 1_000_000)? as u32,
            earliest_ns: required_i128(obj, "earliest_ns")?,
            latest_ns: required_i128(obj, "latest_ns")?,
        });
    }
    Ok(OpsDispatch::ProbeCorroborate(ProbeCorroborateRequest {
        root: root.to_path_buf(),
        principal: principal.clone(),
        session_id: required_session(args)?,
        case_id: optional_clean_text(args, "case_id", 128)?,
        hypothesis_id: optional_clean_text(args, "hypothesis_id", 128)?,
        cameras,
        corridors,
        observations,
        max_clock_uncertainty_ns: optional_u64(args, "max_clock_uncertainty_ns", 1, u64::MAX)?
            .unwrap_or(500_000_000),
        shared_zone_max_separation_ns: optional_u64(
            args,
            "shared_zone_max_separation_ns",
            1,
            u64::MAX,
        )?
        .unwrap_or(5_000_000_000),
        use_probe_calibration: optional_bool(args, "use_probe_calibration")?.unwrap_or(true),
        granted_capabilities: grants,
    }))
}

fn parse_intent_privacy_mask(
    args: &BTreeMap<String, Value>,
    is_commit: bool,
) -> Result<OpsIntentKind, Refusal> {
    let mut allowed = vec!["intent", "session", "sensor", "resolution", "rectangles"];
    if is_commit {
        allowed.extend(["approval_digest", "approve"]);
    }
    allow_only(args, &allowed)?;
    let resolution = match args.get("resolution") {
        Some(Value::Array(pair)) if pair.len() == 2 => [
            parse_u64_val(&pair[0], 1, u64::from(u32::MAX))? as u32,
            parse_u64_val(&pair[1], 1, u64::from(u32::MAX))? as u32,
        ],
        _ => {
            return Err((
                -32602,
                "resolution must be [width, height] positive integers",
            ));
        }
    };
    let rectangles = match args.get("rectangles") {
        Some(Value::Array(items)) if (1..=32).contains(&items.len()) => {
            let mut rects = Vec::with_capacity(items.len());
            for item in items {
                let Value::Array(q) = item else {
                    return Err((-32602, "each rectangle must be [x, y, width, height]"));
                };
                if q.len() != 4 {
                    return Err((-32602, "each rectangle must have 4 integers"));
                }
                rects.push([
                    parse_u64_val(&q[0], 0, u64::from(u32::MAX))? as u32,
                    parse_u64_val(&q[1], 0, u64::from(u32::MAX))? as u32,
                    parse_u64_val(&q[2], 1, u64::from(u32::MAX))? as u32,
                    parse_u64_val(&q[3], 1, u64::from(u32::MAX))? as u32,
                ]);
            }
            rects
        }
        _ => {
            return Err((
                -32602,
                "rectangles must be 1..=32 [x, y, width, height] arrays",
            ));
        }
    };
    Ok(OpsIntentKind::PrivacyMask {
        sensor: required_sensor(args, "sensor")?,
        resolution,
        rectangles,
    })
}

fn parse_intent_evidence_hold(
    args: &BTreeMap<String, Value>,
    is_commit: bool,
) -> Result<OpsIntentKind, Refusal> {
    let mut allowed = vec![
        "intent",
        "session",
        "action",
        "hold_id",
        "import_id",
        "reason",
        "until_ns",
        "attested_earliest_ns",
        "attested_latest_ns",
    ];
    if is_commit {
        allowed.extend(["approval_digest", "approve"]);
    }
    allow_only(args, &allowed)?;
    Ok(OpsIntentKind::EvidenceHold {
        action: optional_clean_text(args, "action", 32)?.unwrap_or_else(|| "place".to_owned()),
        hold_id: required_clean_text(args, "hold_id", 128)?,
        import_id: parse_sha256_value(
            args.get("import_id")
                .ok_or((-32602, "evidence-hold requires import_id"))?,
        )?,
        reason: required_clean_text(args, "reason", 512)?,
        until_ns: args.get("until_ns").map(parse_i128_val).transpose()?,
        attested_now_ns: parse_optional_interval(
            args,
            "attested_earliest_ns",
            "attested_latest_ns",
        )?,
    })
}

fn parse_intent_retention_policy(
    args: &BTreeMap<String, Value>,
    is_commit: bool,
) -> Result<OpsIntentKind, Refusal> {
    let mut allowed = vec![
        "intent",
        "session",
        "sensor",
        "enabled",
        "retain_for_ns",
        "max_retained_source_bytes",
        "expected_policy",
        "attested_earliest_ns",
        "attested_latest_ns",
        "reason",
    ];
    if is_commit {
        allowed.extend(["approval_digest", "approve"]);
    }
    allow_only(args, &allowed)?;
    Ok(OpsIntentKind::RetentionPolicy {
        sensor: required_sensor(args, "sensor")?,
        enabled: optional_bool(args, "enabled")?.unwrap_or(true),
        retain_for_ns: required_u64(args, "retain_for_ns", 1, u64::MAX)?,
        max_retained_source_bytes: optional_u64(args, "max_retained_source_bytes", 1, u64::MAX)?,
        expected_policy: args
            .get("expected_policy")
            .map(parse_sha256_value)
            .transpose()?,
        attested_now_ns: (
            required_i128(args, "attested_earliest_ns")?,
            required_i128(args, "attested_latest_ns")?,
        ),
        reason: required_clean_text(args, "reason", 512)?,
    })
}

fn parse_intent_camera_supervision(
    args: &BTreeMap<String, Value>,
    is_commit: bool,
) -> Result<OpsIntentKind, Refusal> {
    let mut allowed = vec!["intent", "session", "op", "camera_id", "site_id", "idempotency_key"];
    if is_commit {
        allowed.extend(["approval_digest", "approve"]);
    }
    allow_only(args, &allowed)?;
    let op = match required_clean_text(args, "op", 64)?.as_str() {
        "start_camera" => BoundedControlOp::StartCamera,
        "stop_camera" => BoundedControlOp::StopCamera,
        "snapshot_camera" => BoundedControlOp::SnapshotCamera,
        "reload_manifest" => BoundedControlOp::ReloadManifest,
        "probe_detect" => BoundedControlOp::ProbeDetect,
        "trigger_scrub" => BoundedControlOp::TriggerScrub,
        _ => return Err((-32602, "Unsupported bounded camera-supervision op")),
    };
    Ok(OpsIntentKind::CameraSupervision {
        op,
        camera_id: optional_clean_text(args, "camera_id", 128)?,
        site_id: optional_clean_text(args, "site_id", 128)?,
        idempotency_key: args.get("idempotency_key").map(parse_sha256_value).transpose()?,
    })
}

fn allow_only(fields: &BTreeMap<String, Value>, allowed: &[&str]) -> Result<(), Refusal> {
    if fields.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(INVALID_ARGS)
    }
}

fn parse_principal(raw: &str) -> Result<PrincipalId, Refusal> {
    PrincipalId::parse(raw.to_owned()).map_err(|_| (-32603, "Invalid server principal identity"))
}

fn required_clean_text(
    args: &BTreeMap<String, Value>,
    key: &str,
    max: usize,
) -> Result<String, Refusal> {
    optional_clean_text(args, key, max)?.ok_or((-32602, "Missing required bounded text argument"))
}

fn optional_clean_text(
    args: &BTreeMap<String, Value>,
    key: &str,
    max: usize,
) -> Result<Option<String>, Refusal> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => v
            .text()
            .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
            .map(|s| Some(s.to_owned()))
            .ok_or((-32602, "Expected bounded control-free non-empty string")),
    }
}

fn required_session(args: &BTreeMap<String, Value>) -> Result<SessionId, Refusal> {
    optional_session(args)?.ok_or((-32602, "Expected owning session identity"))
}

fn optional_session(args: &BTreeMap<String, Value>) -> Result<Option<SessionId>, Refusal> {
    optional_clean_text(args, "session", 128)?
        .map(|s| SessionId::parse(s).map_err(|_| (-32602, "Invalid session identity")))
        .transpose()
}

fn required_sensor(args: &BTreeMap<String, Value>, key: &str) -> Result<SensorId, Refusal> {
    optional_sensor(args, key)?.ok_or((-32602, "Expected sensor identity"))
}

fn optional_sensor(args: &BTreeMap<String, Value>, key: &str) -> Result<Option<SensorId>, Refusal> {
    optional_clean_text(args, key, 128)?
        .map(|s| SensorId::parse(s).map_err(|_| (-32602, "Invalid sensor identity")))
        .transpose()
}

fn parse_sha256_value(val: &Value) -> Result<ContentDigest, Refusal> {
    let raw = val
        .text()
        .ok_or((-32602, "Expected canonical SHA-256 digest string"))?;
    let digest = ContentDigest::parse(raw)
        .map_err(|_| (-32602, "Expected canonical SHA-256 digest string"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || !digest.bytes().iter().any(|&b| b != 0) {
        return Err((-32602, "Digest must be a nonzero SHA-256 digest"));
    }
    Ok(digest)
}

fn parse_u64_val(val: &Value, min: u64, max: u64) -> Result<u64, Refusal> {
    let raw = match val {
        Value::Number(n) | Value::Text(n) => n.as_str(),
        _ => return Err((-32602, "Expected canonical nonnegative integer")),
    };
    raw.parse::<u64>()
        .ok()
        .filter(|n| (min..=max).contains(n) && n.to_string() == raw)
        .ok_or((
            -32602,
            "Integer outside admitted bounds or non-canonical spelling",
        ))
}

fn required_u64(
    args: &BTreeMap<String, Value>,
    key: &str,
    min: u64,
    max: u64,
) -> Result<u64, Refusal> {
    optional_u64(args, key, min, max)?.ok_or((-32602, "Missing required integer argument"))
}

fn optional_u64(
    args: &BTreeMap<String, Value>,
    key: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, Refusal> {
    args.get(key)
        .map(|v| parse_u64_val(v, min, max))
        .transpose()
}

fn optional_i64(
    args: &BTreeMap<String, Value>,
    key: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, Refusal> {
    args.get(key)
        .map(|val| {
            let raw = match val {
                Value::Number(n) | Value::Text(n) => n.as_str(),
                _ => return Err((-32602, "Expected canonical signed integer")),
            };
            raw.parse::<i64>()
                .ok()
                .filter(|n| (min..=max).contains(n) && n.to_string() == raw)
                .ok_or((
                    -32602,
                    "Signed integer outside bounds or non-canonical spelling",
                ))
        })
        .transpose()
}

fn parse_i128_val(val: &Value) -> Result<i128, Refusal> {
    let raw = match val {
        Value::Number(n) | Value::Text(n) => n.as_str(),
        _ => {
            return Err((
                -32602,
                "Expected canonical signed 128-bit integer or decimal string",
            ));
        }
    };
    raw.parse::<i128>()
        .ok()
        .filter(|n| n.to_string() == raw)
        .ok_or((-32602, "Invalid canonical decimal i128 timestamp"))
}

fn required_i128(args: &BTreeMap<String, Value>, key: &str) -> Result<i128, Refusal> {
    parse_i128_val(
        args.get(key)
            .ok_or((-32602, "Missing required timestamp argument"))?,
    )
}

fn parse_optional_interval(
    args: &BTreeMap<String, Value>,
    e: &str,
    l: &str,
) -> Result<Option<(i128, i128)>, Refusal> {
    match (args.get(e), args.get(l)) {
        (Some(a), Some(b)) => Ok(Some((parse_i128_val(a)?, parse_i128_val(b)?))),
        (None, None) => Ok(None),
        _ => Err((
            -32602,
            "Both earliest and latest attested timestamps must be supplied together",
        )),
    }
}

fn optional_bool(args: &BTreeMap<String, Value>, key: &str) -> Result<Option<bool>, Refusal> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Boolean(b)) => Ok(Some(*b)),
        _ => Err((-32602, "Expected boolean argument")),
    }
}

fn optional_string_vec(
    args: &BTreeMap<String, Value>,
    key: &str,
    max_items: usize,
    max_len: usize,
) -> Result<Vec<String>, Refusal> {
    match args.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) if items.len() <= max_items => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let text = item
                    .text()
                    .filter(|s| {
                        !s.is_empty() && s.len() <= max_len && !s.chars().any(char::is_control)
                    })
                    .ok_or((
                        -32602,
                        "Expected bounded control-free non-empty strings in array",
                    ))?;
                out.push(text.to_owned());
            }
            Ok(out)
        }
        _ => Err((-32602, "Expected bounded string array")),
    }
}

#[cfg(test)]
mod control_key_tests {
    use super::*;

    fn arguments(key: Option<&str>) -> BTreeMap<String, Value> {
        let mut args = BTreeMap::from([
            ("intent".to_owned(), Value::Text("camera-supervision".to_owned())),
            ("op".to_owned(), Value::Text("snapshot_camera".to_owned())),
            ("camera_id".to_owned(), Value::Text("sensor:front".to_owned())),
        ]);
        if let Some(key) = key {
            args.insert("idempotency_key".to_owned(), Value::Text(key.to_owned()));
        }
        args
    }

    #[test]
    fn control_key_is_preserved_and_invalid_or_authority_arguments_are_refused() {
        let key = ContentDigest::sha256(b"mcp-control-request");
        for is_commit in [false, true] {
            let args = arguments(Some(&key.to_text()));
            assert!(matches!(
                parse_intent_camera_supervision(&args, is_commit),
                Ok(OpsIntentKind::CameraSupervision { idempotency_key: Some(found), .. })
                    if found == key
            ));
            for raw in [
                "invalid".to_owned(),
                format!("sha256:{}", "0".repeat(64)),
                format!("blake3:{}", "1".repeat(64)),
            ] {
                assert!(parse_intent_camera_supervision(
                    &arguments(Some(&raw)), is_commit
                ).is_err());
            }
            for forbidden in ["principal", "root", "command", "capabilities"] {
                let mut poisoned = arguments(Some(&key.to_text()));
                poisoned.insert(forbidden.to_owned(), Value::Text("override".to_owned()));
                assert!(parse_intent_camera_supervision(&poisoned, is_commit).is_err());
            }
        }
    }

    #[test]
    fn advertised_control_commit_requires_a_request_key() -> Result<(), &'static str> {
        for (schema, required) in [
            (crate::control::PLAN_TOOL, false),
            (crate::control::COMMIT_TOOL, true),
        ] {
            let value = fss_cli::json_input::parse(schema).map_err(|_| "schema json")?;
            let branches = value.object().and_then(|v| v.get("inputSchema"))
                .and_then(|v| v.object()).and_then(|v| v.get("oneOf"))
                .and_then(|v| v.array()).ok_or("branches")?;
            let branch = branches.iter().find(|branch| {
                branch.object().and_then(|v| v.get("properties"))
                    .and_then(|v| v.object()).and_then(|v| v.get("intent"))
                    .and_then(|v| v.object()).and_then(|v| v.get("const"))
                    .and_then(|v| v.text()) == Some("camera-supervision")
            }).ok_or("control branch")?;
            let fields = branch.object().ok_or("branch object")?;
            let properties = fields.get("properties").and_then(|v| v.object())
                .ok_or("properties")?;
            assert!(properties.contains_key("idempotency_key"));
            let is_required = fields.get("required").and_then(|v| v.array())
                .ok_or("required")?.iter().any(|v| v.text() == Some("idempotency_key"));
            assert_eq!(is_required, required);
        }
        Ok(())
    }
}
