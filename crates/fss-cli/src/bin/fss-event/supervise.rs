#![forbid(unsafe_code)]
//! Explicit or discovered retained native class advice and legacy caller-score simulation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::json_input::{Value, read_document};
use fss_cli::supervisor::{
    SupervisorCameraSpec, SupervisorError, SupervisorPlan, SupervisorWindowObservation,
    SupervisorWindowSpec, run_supervisor,
};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, PrincipalId};
use fss_fusion::{EProcessConfig, ScoreCalibration};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "supervise/retained.rs"]
mod retained;

const HELP: &str = "fss-event supervise --root DIR --site SITE\n\
  (--retained-plan FILE --retained-digest sha256:HEX |\n\
   --discover-plan FILE --discover-digest sha256:HEX | --plan FILE)\n\
  [--principal ID] [--report-out FILE]\n\
\n\
  Retained mode reads a digest-pinned fss.retained_supervisor_plan.v1 from a regular file\n\
  and reopens exact published package events from an existing deployment. Camera bindings\n\
  pin native sensor, package, model, head contract and class. Each cumulative time window\n\
  selects exact source capsules and detection rows; repeated selections add no evidence.\n\
  Current privacy and deletion restrictions apply. Calibration is an explicit owner\n\
  applicability assertion. No original media/model file or model execution is needed.\n\
  Advice preserves shared failure domains and uncertainty. It establishes no coverage,\n\
  class absence, physical identity, zone entry, anytime false-alarm guarantee or effect\n\
  authorization. Retained mode never accepts caller-supplied detector scores.\n\
\n\
  Discovery mode reads fss.retained_supervisor_discovery.v1: an explicit catalog event\n\
  bound and the same retained plan with empty events and window observations. It verifies\n\
  published package events, selects matching native detections into their first enclosing\n\
  windows, and immediately supervises them under one shared read allowance. Its complete\n\
  report includes an executable selected_plan, explicit exclusions and source-read costs.\n\
\n\
  Durable discovery uses an existing fss session open identity:\n\
    --session ID --subscription LABEL --authority-root sha256:CURRENT_ROOT\n\
    --max-poll-attempts N [--inspect yes | --acknowledge RECEIPT | --discard RECEIPT]\n\
  One invocation performs one finite inspect, poll, exact ACK or explicit discard. The original\n\
  discovery file and all read/attempt limits remain immutable for that subscription.\n\
  Every native evaluation or source revalidation durably reserves its full read caps\n\
  before work, including failed or interrupted attempts. A complete report is retained\n\
  before output. Pending retries revalidate all original sources against current authority\n\
  and preserve the exact historical report bytes and delivery receipt. ACK revalidates\n\
  sources and consumes only its exact receipt; discard claims no ACK. The next evaluation\n\
  requires a separate command. --inspect yes recovers existing pending receipts and budget\n\
  counters without source reads, private report output or another charged attempt; unknown\n\
  subscriptions are refused. No background loop, source publication or effect is started.\n\
\n\
  --resume yes recovers an existing subscription's exact native configuration and lifetime\n\
  ceilings from its admitted session journal, so the original plan file is not needed. Supply\n\
  --session, --subscription and the explicit current --authority-root. Do not supply any plan\n\
  flags, --max-poll-attempts or --schedule. Poll, inspect, ACK, discard and advancement retain\n\
  their normal source checks and charges; resume cannot create a missing subscription.\n\
\n\
  Before the first attempt, --schedule yes atomically enables the exact configured window\n\
  schedule with only window 0 active. Normal polls then recompute its full active cumulative\n\
  prefix from original native evidence. After an exact ACK or explicit discard, use\n\
  --advance-window NEXT_ZERO_BASED_INDEX --after-receipt EXACT_TERMINAL_RECEIPT to activate\n\
  exactly the next window. Scheduling and advancement return status only; a poll is separate.\n\
  Pending reports block advancement; retries preserve their original window prefix and bytes.\n\
  No attempt allowance is refunded or reset. Advancing a requested capture bound establishes\n\
  no completed acquisition, synchronized clock, class absence or anytime guarantee. Without\n\
  --schedule yes the existing all-window behavior remains unchanged.\n\
\n\
  --plan selects the legacy fss.supervisor_plan.v1 caller-score simulation. Its\n\
  fss.supervisor_report.v1 explicitly labels unverified source custody and statistical\n\
  assumptions. Its numeric Ville fields do not establish an anytime false-alarm guarantee.\n";

fn field<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, String> {
    map.get(key)
        .ok_or_else(|| format!("supervisor plan missing required field {key}"))
}

fn text<'a>(value: &'a Value, what: &str) -> Result<&'a str, String> {
    value
        .text()
        .ok_or_else(|| format!("expected string for {what}"))
}

fn int_i64(value: &Value, what: &str) -> Result<i64, String> {
    value
        .integer()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| format!("expected i64 integer for {what}"))
}

fn uint_u64(value: &Value, what: &str) -> Result<u64, String> {
    value
        .integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| format!("expected u64 integer for {what}"))
}

fn uint_u32(value: &Value, what: &str) -> Result<u32, String> {
    value
        .integer()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("expected u32 integer for {what}"))
}

fn parse_calibration(cal_obj: &BTreeMap<String, Value>) -> Result<ScoreCalibration, String> {
    if cal_obj.get("schema").and_then(Value::text) != Some("fss.score_calibration.v1") {
        return Err("score_calibration schema must be fss.score_calibration.v1".to_owned());
    }
    let generation = text(field(cal_obj, "generation")?, "score_calibration.generation")?;
    let bins_arr = field(cal_obj, "bins")?
        .array()
        .ok_or_else(|| "score_calibration.bins must be an array".to_owned())?;
    let mut edges = Vec::with_capacity(bins_arr.len());
    let mut counts = Vec::with_capacity(bins_arr.len());
    for bin_val in bins_arr {
        let bin = bin_val
            .object()
            .ok_or_else(|| "calibration bin must be an object".to_owned())?;
        edges.push(uint_u32(field(bin, "lo_ppm")?, "bin.lo_ppm")?);
        counts.push((
            uint_u64(field(bin, "true_positives")?, "bin.true_positives")?,
            uint_u64(field(bin, "false_positives")?, "bin.false_positives")?,
        ));
    }
    let calibration = ScoreCalibration::from_counts(generation, &edges, &counts)
        .map_err(|e| format!("invalid score calibration counts: {e}"))?;
    let declared = text(field(cal_obj, "digest")?, "score_calibration.digest")?;
    if declared != calibration.digest.to_text() {
        return Err("score_calibration digest mismatch".to_owned());
    }
    Ok(calibration)
}

fn parse_observation(obs_obj: &BTreeMap<String, Value>) -> Result<SupervisorWindowObservation, String> {
    let kind = text(field(obs_obj, "kind")?, "observation.kind")?;
    match kind {
        "calibrated_detection" => {
            let score_ppm = uint_u32(field(obs_obj, "score_ppm")?, "observation.score_ppm")?;
            let label = text(field(obs_obj, "label")?, "observation.label")?.to_owned();
            let digest_str = text(
                field(obs_obj, "evidence_digest")?,
                "observation.evidence_digest",
            )?;
            let evidence_digest = ContentDigest::parse(digest_str)
                .map_err(|_| "invalid observation.evidence_digest".to_owned())?;
            Ok(SupervisorWindowObservation::CalibratedDetection {
                score_ppm,
                label,
                evidence_digest,
            })
        }
        "no_detection" => Ok(SupervisorWindowObservation::NoDetection),
        "occluded" => {
            let reason = text(field(obs_obj, "reason")?, "observation.reason")?.to_owned();
            Ok(SupervisorWindowObservation::Occluded { reason })
        }
        "health_degraded" => {
            let reason = text(field(obs_obj, "reason")?, "observation.reason")?.to_owned();
            Ok(SupervisorWindowObservation::HealthDegraded { reason })
        }
        "clock_discontinuity" => {
            let gap_ns = uint_u64(field(obs_obj, "gap_ns")?, "observation.gap_ns")?;
            Ok(SupervisorWindowObservation::ClockDiscontinuity { gap_ns })
        }
        "corrupt_segment" => {
            let reason = text(field(obs_obj, "reason")?, "observation.reason")?.to_owned();
            Ok(SupervisorWindowObservation::CorruptSegment { reason })
        }
        other => Err(format!("unknown observation kind {other}")),
    }
}

fn load_plan(path: &Path, site: &str) -> Result<SupervisorPlan, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| "--plan path requires UTF-8".to_owned())?;
    let doc = read_document(path_str)
        .map_err(|_| "supervisor plan file is unreadable or malformed JSON".to_owned())?;
    let top = doc
        .object()
        .ok_or_else(|| "supervisor plan must be a JSON object".to_owned())?;
    if top.get("schema").and_then(Value::text) != Some("fss.supervisor_plan.v1") {
        return Err("supervisor plan schema must be fss.supervisor_plan.v1".to_owned());
    }
    let hypothesis_id = text(field(top, "hypothesis_id")?, "hypothesis_id")?.to_owned();
    let expected_authority_root = match top.get("expected_authority_root") {
        Some(Value::Text(s)) => Some(
            ContentDigest::parse(s)
                .map_err(|_| "invalid expected_authority_root digest".to_owned())?,
        ),
        Some(Value::Null) | None => None,
        _ => return Err("expected_authority_root must be a string or null".to_owned()),
    };

    let cal_obj = field(top, "score_calibration")?
        .object()
        .ok_or_else(|| "score_calibration must be an object".to_owned())?;
    let calibration = parse_calibration(cal_obj)?;

    let eprocess_config = match top.get("eprocess") {
        Some(val) => {
            let obj = val
                .object()
                .ok_or_else(|| "eprocess must be an object".to_owned())?;
            EProcessConfig {
                alert_threshold_mban: obj
                    .get("alert_threshold_mban")
                    .map(|v| int_i64(v, "alert_threshold_mban"))
                    .transpose()?
                    .unwrap_or(1_800),
                floor_mban: obj
                    .get("floor_mban")
                    .map(|v| int_i64(v, "floor_mban"))
                    .transpose()?
                    .unwrap_or(0),
                ceiling_mban: obj
                    .get("ceiling_mban")
                    .map(|v| int_i64(v, "ceiling_mban"))
                    .transpose()?
                    .unwrap_or(10_000),
                min_independent_clusters: obj
                    .get("min_independent_clusters")
                    .map(|v| uint_u32(v, "min_independent_clusters"))
                    .transpose()?
                    .unwrap_or(2),
            }
        }
        None => EProcessConfig::default(),
    };

    let max_work_units = top
        .get("max_work_units")
        .map(|v| uint_u64(v, "max_work_units"))
        .transpose()?
        .unwrap_or(10_000);
    let work_units_per_camera_window = top
        .get("work_units_per_camera_window")
        .map(|v| uint_u64(v, "work_units_per_camera_window"))
        .transpose()?
        .unwrap_or(10);
    let tolerate_corrupt_segments = match top.get("tolerate_corrupt_segments") {
        Some(Value::Bool(b)) => *b,
        None => false,
        _ => return Err("tolerate_corrupt_segments must be a boolean".to_owned()),
    };
    let cancel_after_window = match top.get("cancel_after_window") {
        Some(Value::Null) | None => None,
        Some(v) => Some(usize::try_from(uint_u64(v, "cancel_after_window")?).unwrap_or(usize::MAX)),
    };
    let stop_on_corroborated_alert = match top.get("stop_on_corroborated_alert") {
        Some(Value::Bool(b)) => *b,
        None => true,
        _ => return Err("stop_on_corroborated_alert must be a boolean".to_owned()),
    };

    let cameras_arr = field(top, "cameras")?
        .array()
        .ok_or_else(|| "cameras must be an array".to_owned())?;
    let mut cameras = Vec::with_capacity(cameras_arr.len());
    for cam_val in cameras_arr {
        let cam_obj = cam_val
            .object()
            .ok_or_else(|| "camera entry must be an object".to_owned())?;
        let camera_id = text(field(cam_obj, "camera_id")?, "camera_id")?.to_owned();
        let sensor_id = text(field(cam_obj, "sensor_id")?, "sensor_id")?.to_owned();
        let mut failure_domains = BTreeSet::new();
        if let Some(domains_val) = cam_obj.get("failure_domains") {
            let arr = domains_val
                .array()
                .ok_or_else(|| "failure_domains must be an array".to_owned())?;
            for item in arr {
                failure_domains.insert(text(item, "failure_domain")?.to_owned());
            }
        }
        cameras.push(SupervisorCameraSpec {
            camera_id,
            sensor_id,
            failure_domains,
        });
    }

    let windows_arr = field(top, "windows")?
        .array()
        .ok_or_else(|| "windows must be an array".to_owned())?;
    let mut windows = Vec::with_capacity(windows_arr.len());
    for win_val in windows_arr {
        let win_obj = win_val
            .object()
            .ok_or_else(|| "window entry must be an object".to_owned())?;
        let window_index = uint_u64(field(win_obj, "window_index")?, "window_index")?;
        let timestamp_ns = uint_u64(field(win_obj, "timestamp_ns")?, "timestamp_ns")?;
        let obs_map_val = field(win_obj, "observations")?
            .object()
            .ok_or_else(|| "window.observations must be an object".to_owned())?;
        let mut observations = BTreeMap::new();
        for (cam_id, obs_val) in obs_map_val {
            let obs_obj = obs_val
                .object()
                .ok_or_else(|| "observation must be an object".to_owned())?;
            observations.insert(cam_id.clone(), parse_observation(obs_obj)?);
        }
        windows.push(SupervisorWindowSpec {
            window_index,
            timestamp_ns,
            observations,
        });
    }

    Ok(SupervisorPlan {
        site_lineage: site.to_owned(),
        hypothesis_id,
        expected_authority_root,
        cameras,
        windows,
        calibration,
        eprocess_config,
        max_work_units,
        work_units_per_camera_window,
        tolerate_corrupt_segments,
        cancel_after_window,
        stop_on_corroborated_alert,
    })
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("help" | "--help" | "-h"))) {
        let _ = io::stdout().lock().write_all(HELP.as_bytes());
        return ExitCode::from(0);
    }
    if args.len() > 32 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: supervise argument bounds");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    }
    let mut values: BTreeMap<String, OsString> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: option name requires UTF-8");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        };
        if !matches!(
            flag,
            "--root"
                | "--site"
                | "--principal"
                | "--plan"
                | "--retained-plan"
                | "--retained-digest"
                | "--discover-plan"
                | "--discover-digest"
                | "--session"
                | "--subscription"
                | "--authority-root"
                | "--max-poll-attempts"
                | "--acknowledge"
                | "--discard"
                | "--inspect"
                | "--schedule"
                | "--advance-window"
                | "--after-receipt"
                | "--resume"
                | "--report-out"
        ) {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: unknown supervise option {flag}");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
        if i + 1 >= args.len() {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: missing value for {flag}");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
        if values.insert(flag.to_owned(), args[i + 1].clone()).is_some() {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: duplicate option {flag}");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
        i += 2;
    }

    if values.contains_key("--retained-plan")
        || values.contains_key("--retained-digest")
        || values.contains_key("--discover-plan")
        || values.contains_key("--discover-digest")
        || values.contains_key("--session")
        || values.contains_key("--subscription")
        || values.contains_key("--authority-root")
        || values.contains_key("--max-poll-attempts")
        || values.contains_key("--acknowledge")
        || values.contains_key("--discard")
        || values.contains_key("--inspect")
        || values.contains_key("--schedule")
        || values.contains_key("--advance-window")
        || values.contains_key("--after-receipt")
        || values.contains_key("--resume")
    {
        return retained::main(&values);
    }

    let Some(root_os) = values.get("--root") else {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: required option --root");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    };
    let Some(site) = values.get("--site").and_then(|s| s.to_str()) else {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: required UTF-8 option --site");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    };
    let Some(plan_os) = values.get("--plan") else {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: required option --plan");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    };
    let principal = values
        .get("--principal")
        .and_then(|s| s.to_str())
        .unwrap_or("principal:local-operator");

    let root = PathBuf::from(root_os);
    let plan_path = PathBuf::from(plan_os);
    let plan = match load_plan(&plan_path, site) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };

    if PrincipalId::parse(principal).is_err() {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: invalid --principal");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    }
    let Ok(operation_id) = OperationId::parse("operation:event-supervise") else {
        return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
    };
    let Ok(budgets) = BudgetVector::builder().bytes(64 * 1024 * 1024).build() else {
        return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
    };
    let Ok(authority) = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-supervise".into(),
        operation_id,
        principal: principal.to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    }) else {
        return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
    };
    let Ok(cx) = ReplayCx::from_context_authority(&authority, root.clone()) else {
        return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
    };
    let deployment = match ReferenceDeployment::open(&root, site, &cx) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {e}");
            return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
        }
    };

    match run_supervisor(&deployment, Some(&root), &cx, &plan) {
        Ok(report) => {
            let rendered = format!("{}\n", report.to_json());
            if let Some(out_os) = values.get("--report-out") {
                let out_path = PathBuf::from(out_os);
                if let Err(e) = super::export(&out_path, rendered.as_bytes(), &root, &cx) {
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {e}");
                    return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
                }
            }
            if io::stdout().lock().write_all(rendered.as_bytes()).is_err() {
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
            ExitCode::from(0)
        }
        Err(err) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {err}");
            eprintln!("refusal_id={}", err.stable_id());
            let _ = SupervisorError::stable_id(&err);
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
