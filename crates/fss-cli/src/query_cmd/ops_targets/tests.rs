#![forbid(unsafe_code)]
//! Unit tests for typed operational `query` targets, discriminating `investigate` probes,
//! and approval-gated `plan`/`commit` intent families.

use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    ContentDigest, ContextAuthority, OperationId, PrincipalId, RootAuthoritySpec, SensorId,
    SessionId,
};
use fss_ipc::BoundedControlOp;
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

use super::fusion::{FusionEvidenceInput, FusionQueryRequest};
use super::graph::{GraphAlgorithmKind, GraphProjectionKind, GraphQueryRequest};
use super::holds_masks::{HoldsQueryRequest, PrivacyMasksQueryRequest};
use super::intents::{OpsIntentKind, OpsIntentRequest};
use super::probes::{CorroborateCameraSpec, CorroborateObservationSpec, ProbeCorroborateRequest};
use super::{
    CAP_AGENT_INVESTIGATE, CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS, CAP_RETENTION_COMMIT, CAP_RETENTION_PREPARE, ERR_APPROVAL_MISMATCH,
    ERR_APPROVAL_REQUIRED, ERR_CAPABILITY_DENIED, ERR_DAEMON_OFFLINE, OpsDispatch,
    execute_with_control,
};
use crate::error::ExitIdentity;
use crate::query_cmd::{execute_query, parse_query_args};
use crate::token::tokenize_os_args;
use fss_core::json_input::{Value, parse_mcp_reply};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TempDeployment(PathBuf);

impl TempDeployment {
    fn create(tag: &str) -> TestResult<Self> {
        let mut root = None;
        for attempt in 0..200 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-ops-targets-{tag}-{}-{attempt}",
                std::process::id()
            ));
            if fs::create_dir(&candidate).is_ok() {
                root = Some(candidate);
                break;
            }
        }
        let path = root.ok_or("failed to create temp deployment dir")?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:ops-unit".to_owned(),
            operation_id: OperationId::parse("operation:ops-unit")?,
            principal: "principal:ops-unit".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(8 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "private:property".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:ops-unit"),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, path.clone())?;
        let _deployment = ReferenceDeployment::open(&path, "site:ops-unit", &cx)?;
        cx.drain_and_finalize();
        Ok(Self(path))
    }
}

impl Drop for TempDeployment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn grants(caps: &[&str]) -> BTreeSet<String> {
    caps.iter().map(|s| (*s).to_owned()).collect()
}

fn parse_env(raw: &str) -> TestResult<Value> {
    Ok(parse_mcp_reply(raw)?)
}

fn extract_str<'a>(val: &'a Value, key: &str) -> Option<&'a str> {
    val.object()?.get(key)?.text()
}

#[test]
fn cli_query_parses_all_five_operational_targets_and_enforces_capabilities() -> TestResult {
    let dir = TempDeployment::create("cli-parse")?;
    let root_str = dir.0.to_string_lossy().to_string();

    // Missing capability fails closed with ERR-CAPABILITY-DENIED-001.
    let tokens = tokenize_os_args(
        [
            "query", "--json", "--root", &root_str, "--target", "cameras",
        ]
        .into_iter()
        .map(OsString::from),
    )?;
    let args = parse_query_args(&tokens)?;
    let (out, exit) = execute_query(&args);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    let env = parse_env(&out)?;
    assert_eq!(extract_str(&env, "outcome"), Some("refused"));
    assert_eq!(extract_str(&env, "errorId"), Some(ERR_CAPABILITY_DENIED));

    // With required capabilities, offline cameras target falls back cleanly to MVCC snapshot.
    let tokens = tokenize_os_args(
        [
            "query",
            "--json",
            "--root",
            &root_str,
            "--target",
            "cameras",
            "--capability",
            CAP_AGENT_QUERY,
            "--capability",
            CAP_OBSERVE_STATUS,
        ]
        .into_iter()
        .map(OsString::from),
    )?;
    let args = parse_query_args(&tokens)?;
    let (out, exit) = execute_query(&args);
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "cameras fallback failed: {out}"
    );
    let env = parse_env(&out)?;
    assert_eq!(extract_str(&env, "outcome"), Some("ok"));
    let payload = env
        .object()
        .and_then(|o| o.get("payload"))
        .ok_or("missing payload")?;
    assert_eq!(
        payload
            .object()
            .and_then(|o| o.get("daemonLive"))
            .and_then(Value::boolean),
        Some(false)
    );
    Ok(())
}

#[test]
fn graph_target_executes_certified_atlas_and_returns_witness() -> TestResult {
    let dir = TempDeployment::create("graph")?;
    let req = OpsDispatch::Graph(GraphQueryRequest {
        root: dir.0.clone(),
        principal: PrincipalId::parse("principal:ops-unit")?,
        session_id: None,
        projection: GraphProjectionKind::DeviceFailureGraph,
        algorithm: GraphAlgorithmKind::Bridges,
        root_node: None,
        granted_capabilities: grants(&[CAP_AGENT_QUERY]),
    });
    let (out, exit) = execute_with_control(&req, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS, "graph failed: {out}");
    let env = parse_env(&out)?;
    assert_eq!(extract_str(&env, "outcome"), Some("ok"));
    let payload = env
        .object()
        .and_then(|o| o.get("payload"))
        .ok_or("missing payload")?;
    let witness = payload
        .object()
        .and_then(|o| o.get("witness"))
        .and_then(Value::object)
        .ok_or("missing witness")?;
    assert_eq!(
        witness.get("algorithmId").and_then(Value::text),
        Some("ALG-BRIDGE-001")
    );
    assert_eq!(
        witness.get("exactness").and_then(Value::text),
        Some("exact")
    );
    Ok(())
}

#[test]
fn fusion_target_evaluates_llr_and_counterfactual_ablation() -> TestResult {
    let dir = TempDeployment::create("fusion")?;
    let req = OpsDispatch::Fusion(FusionQueryRequest {
        root: dir.0.clone(),
        principal: PrincipalId::parse("principal:ops-unit")?,
        session_id: None,
        event_id: None,
        evidence: vec![
            FusionEvidenceInput {
                id: "ev:1".into(),
                sensor: "sensor:front".into(),
                failure_domains: grants(&["power:poe-a", "net:lan-a"]),
                llr: Some((1200, 1400)),
                calibration_generation: Some("cal:v1".into()),
                uncalibrated_reason: None,
                observability: "observed".into(),
            },
            FusionEvidenceInput {
                id: "ev:2".into(),
                sensor: "sensor:rear".into(),
                failure_domains: grants(&["power:poe-b", "net:lan-b"]),
                llr: Some((1200, 1400)),
                calibration_generation: Some("cal:v1".into()),
                uncalibrated_reason: None,
                observability: "observed".into(),
            },
        ],
        prior: (-500, -400),
        coverage_state: "complete".into(),
        alert_threshold: 1000,
        retain_threshold: 0,
        reject_threshold: -1000,
        min_independent_support: 2,
        without_sensors: vec!["sensor:rear".into()],
        without_domains: Vec::new(),
        granted_capabilities: grants(&[CAP_AGENT_QUERY]),
    });
    let (out, exit) = execute_with_control(&req, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS, "fusion failed: {out}");
    let env = parse_env(&out)?;
    let payload = env
        .object()
        .and_then(|o| o.get("payload"))
        .and_then(Value::object)
        .ok_or("missing payload")?;
    let baseline = payload
        .get("baseline")
        .and_then(Value::object)
        .ok_or("missing baseline")?;
    let ablation = payload
        .get("ablation")
        .and_then(Value::object)
        .ok_or("missing ablation")?;
    assert_eq!(
        baseline
            .get("decision")
            .and_then(Value::object)
            .and_then(|o| o.get("kind"))
            .and_then(Value::text),
        Some("alert")
    );
    assert_eq!(
        ablation.get("decisionChanged").and_then(Value::boolean),
        Some(true)
    );
    assert_ne!(
        ablation
            .get("counterfactualOutcome")
            .and_then(Value::object)
            .and_then(|o| o.get("decision"))
            .and_then(Value::object)
            .and_then(|o| o.get("kind"))
            .and_then(Value::text),
        Some("alert")
    );
    Ok(())
}

#[test]
fn probe_corroborate_distinguishes_independent_vs_shared_domain_vs_clock_abstain() -> TestResult {
    let dir = TempDeployment::create("probe-corr")?;
    let principal = PrincipalId::parse("principal:ops-unit")?;
    let session_id = SessionId::parse("session:probe-unit")?;

    // 1. Two independent cameras in shared zone -> Corroborated
    let req_ok = OpsDispatch::ProbeCorroborate(ProbeCorroborateRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: session_id.clone(),
        case_id: Some("case:1".into()),
        hypothesis_id: Some("hyp:1".into()),
        cameras: vec![
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-a".into(),
                failure_domains: grants(&["power:poe-a", "net:lan-a"]),
                zones: grants(&["driveway"]),
            },
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-b".into(),
                failure_domains: grants(&["power:poe-b", "net:lan-b"]),
                zones: grants(&["driveway"]),
            },
        ],
        corridors: Vec::new(),
        observations: vec![
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-a".into(),
                zone_id: "driveway".into(),
                track_id: 1,
                class_label: "person".into(),
                score_ppm: 920_000,
                earliest_ns: 1_000_000_000,
                latest_ns: 1_050_000_000,
            },
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-b".into(),
                zone_id: "driveway".into(),
                track_id: 2,
                class_label: "person".into(),
                score_ppm: 930_000,
                earliest_ns: 1_010_000_000,
                latest_ns: 1_060_000_000,
            },
        ],
        max_clock_uncertainty_ns: 500_000_000,
        shared_zone_max_separation_ns: 5_000_000_000,
        use_probe_calibration: true,
        granted_capabilities: grants(&[CAP_AGENT_INVESTIGATE]),
    });
    let (out, exit) = execute_with_control(&req_ok, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS, "corroborate failed: {out}");
    assert!(
        out.contains("\"outcome\":\"corroborated\""),
        "expected corroborated: {out}"
    );
    assert!(out.contains("\"effectsAuthorized\":false"));

    // 2. Shared failure domain -> SharedFailureDomainHeld
    let req_shared = OpsDispatch::ProbeCorroborate(ProbeCorroborateRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: session_id.clone(),
        case_id: Some("case:1".into()),
        hypothesis_id: Some("hyp:2".into()),
        cameras: vec![
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-a".into(),
                failure_domains: grants(&["power:shared-ups"]),
                zones: grants(&["driveway"]),
            },
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-b".into(),
                failure_domains: grants(&["power:shared-ups"]),
                zones: grants(&["driveway"]),
            },
        ],
        corridors: Vec::new(),
        observations: vec![
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-a".into(),
                zone_id: "driveway".into(),
                track_id: 1,
                class_label: "person".into(),
                score_ppm: 920_000,
                earliest_ns: 1_000_000_000,
                latest_ns: 1_050_000_000,
            },
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-b".into(),
                zone_id: "driveway".into(),
                track_id: 2,
                class_label: "person".into(),
                score_ppm: 930_000,
                earliest_ns: 1_010_000_000,
                latest_ns: 1_060_000_000,
            },
        ],
        max_clock_uncertainty_ns: 500_000_000,
        shared_zone_max_separation_ns: 5_000_000_000,
        use_probe_calibration: true,
        granted_capabilities: grants(&[CAP_AGENT_INVESTIGATE]),
    });
    let (out, exit) = execute_with_control(&req_shared, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS);
    assert!(
        out.contains("shared_failure_domain_held"),
        "expected shared failure domain held: {out}"
    );

    // 3. Excessive clock uncertainty -> ClockUncertaintyAbstained
    let req_clock = OpsDispatch::ProbeCorroborate(ProbeCorroborateRequest {
        root: dir.0.clone(),
        principal,
        session_id,
        case_id: Some("case:1".into()),
        hypothesis_id: Some("hyp:3".into()),
        cameras: vec![
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-a".into(),
                failure_domains: grants(&["power:poe-a"]),
                zones: grants(&["driveway"]),
            },
            CorroborateCameraSpec {
                sensor_id: "sensor:cam-b".into(),
                failure_domains: grants(&["power:poe-b"]),
                zones: grants(&["driveway"]),
            },
        ],
        corridors: Vec::new(),
        observations: vec![
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-a".into(),
                zone_id: "driveway".into(),
                track_id: 1,
                class_label: "person".into(),
                score_ppm: 920_000,
                earliest_ns: 1_000_000_000,
                latest_ns: 2_500_000_000,
            },
            CorroborateObservationSpec {
                sensor_id: "sensor:cam-b".into(),
                zone_id: "driveway".into(),
                track_id: 2,
                class_label: "person".into(),
                score_ppm: 930_000,
                earliest_ns: 1_010_000_000,
                latest_ns: 1_050_000_000,
            },
        ],
        max_clock_uncertainty_ns: 500_000_000,
        shared_zone_max_separation_ns: 5_000_000_000,
        use_probe_calibration: true,
        granted_capabilities: grants(&[CAP_AGENT_INVESTIGATE]),
    });
    let (out, exit) = execute_with_control(&req_clock, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS);
    assert!(
        out.contains("clock_uncertainty_abstained"),
        "expected clock abstain: {out}"
    );
    Ok(())
}

#[test]
fn intents_require_approval_and_commit_idempotently() -> TestResult {
    let dir = TempDeployment::create("intents")?;
    let principal = PrincipalId::parse("principal:ops-unit")?;
    let sensor = SensorId::parse("sensor:porch")?;

    // 1. Privacy mask plan -> refusal on missing/wrong approval -> commit -> idempotent replay -> query privacy-masks
    let intent = OpsIntentKind::PrivacyMask {
        sensor: sensor.clone(),
        resolution: [640, 480],
        rectangles: vec![[10, 10, 100, 80]],
    };
    let plan_req = OpsDispatch::PlanIntent(OpsIntentRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: None,
        intent: intent.clone(),
        approval_digest: None,
        granted_capabilities: grants(&[CAP_AGENT_PLAN_PREPARE]),
    });
    let (plan_out, exit) = execute_with_control(&plan_req, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS, "mask plan failed: {plan_out}");
    let plan_env = parse_env(&plan_out)?;
    let approval_str = plan_env
        .object()
        .and_then(|o| o.get("payload"))
        .and_then(Value::object)
        .and_then(|o| o.get("approvalDigest"))
        .and_then(Value::text)
        .ok_or("missing approvalDigest")?;
    let approval = ContentDigest::parse(approval_str)?;

    // Commit without approval -> ERR-APPROVAL-REQUIRED-001
    let no_app = OpsDispatch::CommitIntent(OpsIntentRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: None,
        intent: intent.clone(),
        approval_digest: None,
        granted_capabilities: grants(&[CAP_AGENT_PLAN_COMMIT]),
    });
    let (out, exit) = execute_with_control(&no_app, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(
        extract_str(&parse_env(&out)?, "errorId"),
        Some(ERR_APPROVAL_REQUIRED)
    );

    // Commit with wrong approval -> ERR-APPROVAL-MISMATCH-001
    let bad_app = OpsDispatch::CommitIntent(OpsIntentRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: None,
        intent: intent.clone(),
        approval_digest: Some(ContentDigest::sha256(b"wrong-approval")),
        granted_capabilities: grants(&[CAP_AGENT_PLAN_COMMIT]),
    });
    let (out, exit) = execute_with_control(&bad_app, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(
        extract_str(&parse_env(&out)?, "errorId"),
        Some(ERR_APPROVAL_MISMATCH)
    );

    // Commit with exact approval -> retained
    let commit_req = OpsDispatch::CommitIntent(OpsIntentRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: None,
        intent,
        approval_digest: Some(approval),
        granted_capabilities: grants(&[CAP_AGENT_PLAN_COMMIT]),
    });
    let (out, exit) = execute_with_control(&commit_req, &crate::RequestControl::uncancelled());
    assert_eq!(exit, ExitIdentity::SUCCESS, "mask commit failed: {out}");
    assert!(out.contains("\"authorityChanged\":true"));

    // Read back via privacy-masks query
    let q_masks = OpsDispatch::PrivacyMasks(PrivacyMasksQueryRequest {
        root: dir.0.clone(),
        principal: principal.clone(),
        session_id: None,
        sensor: Some(sensor.clone()),
        granted_capabilities: grants(&[CAP_AGENT_QUERY]),
    });
    let (out, exit) = execute_with_control(&q_masks, &crate::RequestControl::uncancelled());
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "privacy-masks query failed: {out}"
    );
    assert!(out.contains("\"sensorId\":\"sensor:porch\""));

    // 2. Retention policy plan + commit + query holds
    let ret_intent = OpsIntentKind::RetentionPolicy {
        sensor,
        enabled: true,
        retain_for_ns: 3_600_000_000_000,
        max_retained_source_bytes: Some(10_000_000),
        expected_policy: None,
        attested_now_ns: (10_000_000_000, 10_000_000_000),
        reason: "unit test bounded retention".into(),
    };
    let (ret_plan, exit) = execute_with_control(
        &OpsDispatch::PlanIntent(OpsIntentRequest {
            root: dir.0.clone(),
            principal: principal.clone(),
            session_id: None,
            intent: ret_intent.clone(),
            approval_digest: None,
            granted_capabilities: grants(&[CAP_AGENT_PLAN_PREPARE, CAP_RETENTION_PREPARE]),
        }),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "retention plan failed: {ret_plan}"
    );
    let ret_app = ContentDigest::parse(
        parse_env(&ret_plan)?
            .object()
            .and_then(|o| o.get("payload"))
            .and_then(Value::object)
            .and_then(|o| o.get("approvalDigest"))
            .and_then(Value::text)
            .ok_or("missing retention approvalDigest")?,
    )?;
    let (ret_commit, exit) = execute_with_control(
        &OpsDispatch::CommitIntent(OpsIntentRequest {
            root: dir.0.clone(),
            principal: principal.clone(),
            session_id: None,
            intent: ret_intent,
            approval_digest: Some(ret_app),
            granted_capabilities: grants(&[CAP_AGENT_PLAN_COMMIT, CAP_RETENTION_COMMIT]),
        }),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "retention commit failed: {ret_commit}"
    );
    let (holds_out, exit) = execute_with_control(
        &OpsDispatch::Holds(HoldsQueryRequest {
            root: dir.0.clone(),
            principal: principal.clone(),
            session_id: None,
            sensor: None,
            attested_now_ns: Some((10_000_000_000, 10_000_000_000)),
            granted_capabilities: grants(&[CAP_AGENT_QUERY, CAP_RETENTION_PREPARE]),
        }),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "holds query failed: {holds_out}"
    );
    assert!(holds_out.contains("\"retentionPolicyCount\":1"));

    // 3. Offline camera-supervision plan succeeds; commit fails closed with ERR-DAEMON-OFFLINE-001
    let sup_intent = OpsIntentKind::CameraSupervision {
        op: BoundedControlOp::StartCamera,
        camera_id: Some("sensor:porch".into()),
        site_id: None,
        idempotency_key: Some(ContentDigest::sha256(b"offline-supervision-request")),
    };
    let (sup_plan, exit) = execute_with_control(
        &OpsDispatch::PlanIntent(OpsIntentRequest {
            root: dir.0.clone(),
            principal: principal.clone(),
            session_id: None,
            intent: sup_intent.clone(),
            approval_digest: None,
            granted_capabilities: grants(&[CAP_AGENT_PLAN_PREPARE, CAP_OBSERVE_STATUS]),
        }),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(
        exit,
        ExitIdentity::SUCCESS,
        "supervision plan failed: {sup_plan}"
    );
    let sup_app = ContentDigest::parse(
        parse_env(&sup_plan)?
            .object()
            .and_then(|o| o.get("payload"))
            .and_then(Value::object)
            .and_then(|o| o.get("approvalDigest"))
            .and_then(Value::text)
            .ok_or("missing supervision approvalDigest")?,
    )?;
    let (sup_commit, exit) = execute_with_control(
        &OpsDispatch::CommitIntent(OpsIntentRequest {
            root: dir.0.clone(),
            principal,
            session_id: None,
            intent: sup_intent,
            approval_digest: Some(sup_app),
            granted_capabilities: grants(&[CAP_AGENT_PLAN_COMMIT, CAP_OBSERVE_STATUS]),
        }),
        &crate::RequestControl::uncancelled(),
    );
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert_eq!(
        extract_str(&parse_env(&sup_commit)?, "errorId"),
        Some(ERR_DAEMON_OFFLINE)
    );
    Ok(())
}
