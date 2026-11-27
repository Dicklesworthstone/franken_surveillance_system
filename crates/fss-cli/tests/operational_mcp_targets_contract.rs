#![forbid(unsafe_code)]
//! End-to-end contract tests for bead `fss-x4a.31.4.2`:
//! 1. Dynamic `affordance:orient:plan` across empty, single-camera, and corroborated deployments.
//! 2. Pure-MCP (`fss-mcp` JSON-RPC 2.0 stdio, zero shell commands!) operational session covering:
//!    - `query` `cameras` (live `ControlPlaneServer` via UDS `fss-ipc` AND stopped MVCC fallback)
//!    - `query` `graph` (Certified Graph Atlas returning verified `GraphAlgorithmWitness`)
//!    - `query` `fusion` (milliban LLR evaluation + sensor/domain counterfactual ablation)
//!    - `query` `holds` and `query` `privacy-masks`
//!    - `investigate` `probe-detect` (`TwoStageCascade` + `ResidentModelPool` on masked MJPEG)
//!    - `investigate` `probe-corroborate` (`corroborated`, `shared_failure_domain_held`, `clock_uncertainty_abstained`)
//!    - `plan` -> `commit` for `privacy-mask`, `evidence-hold`, `retention-policy`, `camera-supervision`
//!      (preview/mismatch/missing-approval refusals, idempotency, capability denials, `-32602` escape-hatch refusals).

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_cli::escape_json_str;
use fss_cli::query_cmd::ops_targets::{
    CAP_AGENT_INVESTIGATE, CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS, CAP_RETENTION_COMMIT, CAP_RETENTION_PREPARE, ERR_APPROVAL_MISMATCH,
    ERR_APPROVAL_REQUIRED, ERR_CAPABILITY_DENIED, ERR_DAEMON_OFFLINE,
};
use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{
    AffordanceClass, AgentView, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    DecisionPath, EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass,
    EvidenceEdgeRelation, OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_daemon::control::{
    ControlPlaneServer, ControlPlaneShared, ControlStatusSnapshot, ForwardBatchWriter,
};
use fss_daemon::error::DaemonError;
use fss_ipc::{
    ActiveScrubStatus, CameraLiveStatus, RingWatermarkStatus,
    deployment_root_digest,
};
use fss_reference::agent_orient::{
    AFFORDANCE_PLAN, OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::ingest::file_adapter::{FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, ReplayIoAuthority,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;
static SEQ: AtomicU64 = AtomicU64::new(0);

const PRINCIPAL: &str = "principal:ops-mcp-owner";
const SITE: &str = "site:ops-mcp-contract";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ops-mcp-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const ALL_CAPS: &[&str] = &[
    CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS,
    CAP_RETENTION_PREPARE,
    CAP_RETENTION_COMMIT,
    CAP_AGENT_INVESTIGATE,
    CAP_AGENT_PLAN_PREPARE,
    CAP_AGENT_PLAN_COMMIT,
];

struct NoopForwardWriter;
impl ForwardBatchWriter for NoopForwardWriter {
    fn forward_delta_batch(
        &self,
        _: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        Err(DaemonError::InvalidConfig {
            detail: "contract test forward writer unused".into(),
        })
    }
}

struct OpsFixture {
    dir: PathBuf,
    root: PathBuf,
    import_id: ContentDigest,
}
impl Drop for OpsFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn encode_motion_frame(frame_idx: u32) -> Test<Vec<u8>> {
    let (w, h) = (96_u32, 64_u32);
    let mut rgb = vec![0_u8; (w as usize) * (h as usize) * 3];
    for y in 0..h {
        for x in 0..w {
            let idx = ((y as usize) * (w as usize) + (x as usize)) * 3;
            let px = if frame_idx >= 2 && (36..68).contains(&x) && (20..48).contains(&y) {
                [240, 230, 220]
            } else {
                [80, 95, 70]
            };
            rgb[idx..idx + 3].copy_from_slice(&px);
        }
    }
    let limits = EncodeLimits::default();
    let mut budget = EncodeBudget::new(limits.work_bound(PixelFormat::Rgb));
    let digest = ContentDigest::sha256(&rgb).bytes();
    Ok(encode_jpeg(
        w,
        h,
        &rgb,
        digest,
        EncodeConfig {
            quality: 85,
            format: PixelFormat::Rgb,
        },
        &limits,
        &mut budget,
    )?
    .into_bytes())
}

fn write_authority(root: &Path) -> Test<(ContextAuthority, ReplayCx)> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:ops-mcp-contract".into(),
        operation_id: OperationId::parse("operation:ops-mcp-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec![ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(100_000)
            .build()?,
        privacy_scope: "private:property".into(),
        retention_scope: "retention:current-deletion-restrictions".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?);
    Ok((authority, cx))
}

impl OpsFixture {
    fn build(tag: &str) -> Test<Self> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        // Short path keeps `<root>/run/daemon.sock` well under macOS SUN_LEN (104 bytes).
        let dir = PathBuf::from(format!("/tmp/fss-o-{tag}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let root = dir.join("d");
        let (_, cx) = write_authority(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;

        let mut mjpeg = Vec::new();
        for idx in 0..8_u32 {
            mjpeg.extend_from_slice(&encode_motion_frame(idx)?);
        }
        let mjpeg_path = dir.join("driveway.mjpeg");
        fs::write(&mjpeg_path, &mjpeg)?;
        let ingest_req = FileIngestRequest::new(
            &mjpeg_path,
            SensorId::parse("sensor:driveway-cam")?,
            StreamId::parse("stream:main")?,
        )
        .with_receive_time(TimestampNs(1_700_000_000_000_000_000));
        let receipt = FileIngestAdapter::ingest(ingest_req, &cx, &mut deployment)?;

        let watch_plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::YCbCr,
            first_segment: 0,
            segment_count: 8,
            zones: vec![WatchZone {
                zone_id: "driveway".to_owned(),
                x: 32,
                y: 16,
                width: 40,
                height: 36,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig {
                confirmation_hits: 2,
                maximum_missed_frames: 2,
                minimum_iou_ppm: 100_000,
            },
        };
        let mut report =
            WatchReport::analyze(&deployment, &watch_plan, &WatchLimits::default(), &cx)?;
        let cov_approval = report.coverage_approval();
        let _ = report.retain_coverage(&mut deployment, cov_approval, &cx)?;
        cx.drain_and_finalize();
        Ok(Self {
            dir,
            root: root.canonicalize()?,
            import_id: receipt.import_identity,
        })
    }

    fn run_mcp_session(&self, grants: &[&str], calls: &[(u64, &str, String)]) -> Test<Vec<Value>> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
        cmd.arg("--root")
            .arg(&self.root)
            .arg("--principal")
            .arg(PRINCIPAL);
        for cap in grants {
            cmd.arg("--grant-capability").arg(cap);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let mut stdin = child.stdin.take().ok_or("missing stdin")?;
        writeln!(stdin, "{INIT}")?;
        writeln!(stdin, "{READY}")?;
        for (id, tool, args_json) in calls {
            writeln!(
                stdin,
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{}","arguments":{args_json}}}}}"#,
                escape_json_str(tool)
            )?;
        }
        drop(stdin);
        let output = child.wait_with_output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            output.status.success(),
            "fss-mcp failed ({:?}): stderr={stderr} stdout={stdout}",
            output.status
        );
        let mut by_id = BTreeMap::<u64, Value>::new();
        for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
            let parsed = parse_mcp_reply(line)?;
            let id = parsed
                .object()
                .and_then(|o| o.get("id"))
                .and_then(|v| match v {
                    Value::Number(n) => n.parse::<u64>().ok(),
                    _ => None,
                })
                .ok_or_else(|| format!("missing numeric id in reply: {line}"))?;
            by_id.insert(id, parsed);
        }
        assert!(by_id.contains_key(&1), "missing initialize reply: {stdout}");
        calls
            .iter()
            .map(|(id, _, _)| {
                by_id
                    .remove(id)
                    .ok_or_else(|| format!("missing reply {id}").into())
            })
            .collect()
    }
}

fn field<'a>(v: &'a Value, name: &str) -> Test<&'a Value> {
    v.object()
        .and_then(|o| o.get(name))
        .ok_or_else(|| format!("missing field `{name}`").into())
}
fn text<'a>(v: &'a Value, name: &str) -> Test<&'a str> {
    field(v, name)?
        .text()
        .ok_or_else(|| format!("field `{name}` is not string").into())
}
fn bool_field(v: &Value, name: &str) -> Test<bool> {
    field(v, name)?
        .boolean()
        .ok_or_else(|| format!("field `{name}` is not boolean").into())
}
fn extract_envelope(reply: &Value) -> Test<(bool, Value)> {
    let result = field(reply, "result").map_err(|err| format!("{err}; reply={reply:?}"))?;
    let is_error = result
        .object()
        .and_then(|o| o.get("isError"))
        .and_then(Value::boolean)
        .unwrap_or(false);
    let raw_text = field(result, "content")?
        .array()
        .ok_or("content not array")?
        .first()
        .and_then(Value::object)
        .and_then(|o| o.get("text"))
        .and_then(Value::text)
        .ok_or("missing content[0].text")?;
    Ok((is_error, parse_mcp_reply(raw_text)?))
}

fn make_evidence(seed: &[u8], domain: &str, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest: ContentDigest::sha256(seed),
        class: EvidenceClass::Derived,
        failure_domain: domain.to_owned(),
        supports: matches!(relation, EvidenceEdgeRelation::Supports),
        relation,
        capsule_digest: None,
        identity_digest: None,
    }
}

#[test]
fn dynamic_orient_plan_affordance_tracks_real_deployment_corroboration() -> Test {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("fss-orient-plan-dyn-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let root = dir.join("deployment");
    let (_, cx) = write_authority(&root)?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let req = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse(PRINCIPAL)?,
        budget_tokens: None,
    };
    let limits = OrientLimits::default();

    // 1. Empty deployment -> Unavailable.
    let orient_empty = orient_deployment(&read_deployment(&root, &limits)?, &req, &limits)?;
    let plan_empty = orient_empty
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing plan")?;
    assert_eq!(plan_empty.class, AffordanceClass::Unavailable);

    // 2. Single-camera uncorroborated event -> Blocked.
    let window = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_000_001_000_000_000),
    )?;
    let single_ev = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:dyn:single")?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::UnknownPresence,
        interval: window,
        uncertainty_reason: Some("single sensor only".to_owned()),
        zone_ids: vec!["zone:driveway".to_owned()],
        track_ids: vec!["track:1".to_owned()],
        probability: ProbabilityInterval::new(0.65, 0.85)?,
        evidence: vec![make_evidence(
            b"cam-a",
            "domain:cam-a",
            EvidenceEdgeRelation::Supports,
        )],
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:dyn-test"),
            fingerprint: ContentDigest::sha256(b"event:dyn:single"),
            abstained: true,
            abstention_reason: Some("requires independent corroboration".to_owned()),
        },
    };
    dep.publish_event(
        &ReferencePolicyDecision {
            event: single_ev,
            action: ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    let orient_single = orient_deployment(&read_deployment(&root, &limits)?, &req, &limits)?;
    let plan_single = orient_single
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing single plan")?;
    assert_eq!(plan_single.class, AffordanceClass::Blocked);
    assert!(plan_single.rationale.contains("corroboration"));

    // 3. 2-camera independently corroborated event -> Conditional / Robust with decomposed frontier.
    let corr_ev = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:dyn:corr")?,
        revision: 1,
        supersedes: None,
        state: EventState::Corroborated,
        kind: EventKind::PerimeterBreach,
        interval: window,
        uncertainty_reason: None,
        zone_ids: vec!["zone:driveway".to_owned()],
        track_ids: vec!["track:2".to_owned()],
        probability: ProbabilityInterval::new(0.88, 0.98)?,
        evidence: vec![
            make_evidence(b"cam-a-2", "domain:cam-a", EvidenceEdgeRelation::Supports),
            make_evidence(b"cam-b-2", "domain:cam-b", EvidenceEdgeRelation::Supports),
        ],
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:dyn-test"),
            fingerprint: ContentDigest::sha256(b"event:dyn:corr"),
            abstained: false,
            abstention_reason: None,
        },
    };
    dep.publish_event(
        &ReferencePolicyDecision {
            event: corr_ev,
            action: ReferencePolicyAction::PrepareAlert,
        },
        &cx,
    )?;
    cx.drain_and_finalize();
    let orient_corr = orient_deployment(&read_deployment(&root, &limits)?, &req, &limits)?;
    orient_corr.capsule().validate()?;
    let plan_corr = orient_corr
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing corr plan")?;
    assert!(matches!(
        plan_corr.class,
        AffordanceClass::Conditional | AffordanceClass::Robust
    ));
    assert_eq!(plan_corr.target, "fss://event/event:dyn:corr");
    assert!(
        orient_corr
            .capsule()
            .frame
            .next
            .contains(&AFFORDANCE_PLAN.to_owned())
    );
    assert!(
        plan_corr
            .rationale
            .contains("never grants effect authority")
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn pure_mcp_operational_session_queries_probes_and_approval_gated_intents() -> Test {
    let fixture = OpsFixture::build("e2e")?;
    let import_hex = fixture.import_id.to_text();

    let session_replies = fixture.run_mcp_session(ALL_CAPS, &[(
        10, "session_open",
        r#"{"mission":"Operational MCP audit","objective":"Exercise typed targets, probes, and intents","budget_tokens":100000}"#.to_owned(),
    )])?;
    let (is_err, open_env) = extract_envelope(&session_replies[0])?;
    assert!(!is_err, "session_open failed: {:?}", open_env);
    let session_id = text(&open_env, "sessionId")?.to_owned();

    // Phase 1: Offline queries + discriminating probes + initial previews.
    let p1 = fixture.run_mcp_session(ALL_CAPS, &[
        (11, "query", r#"{"target":"cameras"}"#.to_owned()),
        (12, "query", r#"{"target":"graph","projection":"SensorCoverageGraph","algorithm":"ALG-BRIDGE-001"}"#.to_owned()),
        (13, "query", r#"{"target":"fusion","evidence":[{"id":"e1","sensor":"sensor:cam-a","failure_domains":["poe:a"],"llr_lo":1300,"llr_hi":1500,"calibration_generation":"cal:v1"},{"id":"e2","sensor":"sensor:cam-b","failure_domains":["poe:b"],"llr_lo":1300,"llr_hi":1500,"calibration_generation":"cal:v1"}],"without_sensors":["sensor:cam-b"]}"#.to_owned()),
        (14, "query", r#"{"target":"holds"}"#.to_owned()),
        (15, "query", r#"{"target":"privacy-masks"}"#.to_owned()),
        (16, "investigate", format!(r#"{{"transition":"probe-detect","session":"{session_id}","case_id":"case:mcp:1","hypothesis_id":"hyp:mcp:1","import_id":"{import_hex}","max_frames":3}}"#)),
        (17, "investigate", format!(r#"{{"transition":"probe-corroborate","session":"{session_id}","case_id":"case:mcp:1","hypothesis_id":"hyp:corr:ok","cameras":[{{"sensor_id":"cam-a","failure_domains":["poe:a"],"zones":["driveway"]}},{{"sensor_id":"cam-b","failure_domains":["poe:b"],"zones":["driveway"]}}],"observations":[{{"sensor_id":"cam-a","zone_id":"driveway","track_id":1,"class_label":"person","score_ppm":930000,"earliest_ns":1000000000,"latest_ns":1050000000}},{{"sensor_id":"cam-b","zone_id":"driveway","track_id":2,"class_label":"person","score_ppm":940000,"earliest_ns":1010000000,"latest_ns":1060000000}}]}}"#)),
        (18, "investigate", format!(r#"{{"transition":"probe-corroborate","session":"{session_id}","cameras":[{{"sensor_id":"cam-a","failure_domains":["poe:shared"],"zones":["driveway"]}},{{"sensor_id":"cam-b","failure_domains":["poe:shared"],"zones":["driveway"]}}],"observations":[{{"sensor_id":"cam-a","zone_id":"driveway","track_id":1,"class_label":"person","score_ppm":930000,"earliest_ns":1000000000,"latest_ns":1050000000}},{{"sensor_id":"cam-b","zone_id":"driveway","track_id":2,"class_label":"person","score_ppm":940000,"earliest_ns":1010000000,"latest_ns":1060000000}}]}}"#)),
        (19, "investigate", format!(r#"{{"transition":"probe-corroborate","session":"{session_id}","cameras":[{{"sensor_id":"cam-a","failure_domains":["poe:a"],"zones":["driveway"]}},{{"sensor_id":"cam-b","failure_domains":["poe:b"],"zones":["driveway"]}}],"observations":[{{"sensor_id":"cam-a","zone_id":"driveway","track_id":1,"class_label":"person","score_ppm":930000,"earliest_ns":1000000000,"latest_ns":2500000000}},{{"sensor_id":"cam-b","zone_id":"driveway","track_id":2,"class_label":"person","score_ppm":940000,"earliest_ns":1010000000,"latest_ns":1050000000}}]}}"#)),
        (20, "plan", r#"{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]]}"#.to_owned()),
        (21, "plan", r#"{"intent":"camera-supervision","op":"start_camera","camera_id":"sensor:driveway-cam"}"#.to_owned()),
    ])?;

    // Verify 11-15: cameras MVCC fallback, graph witness, fusion+ablation, holds, privacy-masks
    let (is_err, env) = extract_envelope(&p1[0])?;
    assert!(!is_err && !bool_field(field(&env, "payload")?, "daemonLive")?);
    assert_eq!(
        text(field(&env, "payload")?, "fallbackMode")?,
        "readonly_mvcc_deployment_snapshot"
    );
    let (is_err, env) = extract_envelope(&p1[1])?;
    let witness = field(field(&env, "payload")?, "witness")?;
    assert!(
        !is_err
            && text(witness, "schema")? == "fss.graph_algorithm_witness.v1"
            && text(witness, "exactness")? == "exact"
    );
    let (is_err, env) = extract_envelope(&p1[2])?;
    let fp = field(&env, "payload")?;
    assert!(!is_err && text(field(field(fp, "baseline")?, "decision")?, "kind")? == "alert");
    assert!(bool_field(field(fp, "ablation")?, "decisionChanged")?);
    assert!(!extract_envelope(&p1[3])?.0 && !extract_envelope(&p1[4])?.0);

    // Verify 16: probe-detect uncalibrated cognition-only proposal
    let (is_err, env) = extract_envelope(&p1[5])?;
    let pd = field(&env, "payload")?;
    assert!(
        !is_err
            && !bool_field(pd, "calibrated")?
            && !bool_field(pd, "effectsAuthorized")?
            && !bool_field(pd, "policyMutated")?
    );
    assert!(text(pd, "proposalDigest")?.starts_with("sha256:"));

    // Verify 17-19: probe-corroborate 3 distinct outcomes
    for (idx, expected) in [
        (6, "corroborated"),
        (7, "shared_failure_domain_held"),
        (8, "clock_uncertainty_abstained"),
    ] {
        let (is_err, env) = extract_envelope(&p1[idx])?;
        let pc = field(&env, "payload")?;
        assert!(!is_err && !bool_field(pc, "effectsAuthorized")?);
        let decisions = field(pc, "decisions")?.array().ok_or("decisions array")?;
        assert_eq!(text(&decisions[0], "outcome")?, expected);
    }

    let mask_app = text(
        field(&extract_envelope(&p1[9])?.1, "payload")?,
        "approvalDigest",
    )?
    .to_owned();
    let sup_app = text(
        field(&extract_envelope(&p1[10])?.1, "payload")?,
        "approvalDigest",
    )?
    .to_owned();
    let sup_key = text(
        field(&extract_envelope(&p1[10])?.1, "payload")?,
        "idempotencyKey",
    )?
    .to_owned();
    let wrong_app = ContentDigest::sha256(b"wrong-approval-digest").to_text();

    // Phase 2a: Missing/wrong approval refusals + privacy-mask commit + idempotent replay + fresh evidence-hold plan
    let r2a = fixture.run_mcp_session(ALL_CAPS, &[
        (30, "commit", r#"{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]]}"#.to_owned()),
        (31, "commit", format!(r#"{{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]],"approval_digest":"{wrong_app}"}}"#)),
        (32, "commit", format!(r#"{{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]],"approval_digest":"{mask_app}"}}"#)),
        (33, "commit", format!(r#"{{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]],"approval_digest":"{mask_app}"}}"#)),
        (34, "plan", format!(r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-mcp-1","import_id":"{import_hex}","reason":"preserve driveway capture"}}"#)),
    ])?;
    assert_eq!(
        text(&extract_envelope(&r2a[0])?.1, "errorId")?,
        ERR_APPROVAL_REQUIRED
    );
    assert_eq!(
        text(&extract_envelope(&r2a[1])?.1, "errorId")?,
        ERR_APPROVAL_MISMATCH
    );
    assert!(bool_field(
        field(&extract_envelope(&r2a[2])?.1, "payload")?,
        "authorityChanged"
    )?);
    assert!(!bool_field(
        field(&extract_envelope(&r2a[3])?.1, "payload")?,
        "authorityChanged"
    )?);
    let hold_app = text(
        field(&extract_envelope(&r2a[4])?.1, "payload")?,
        "approvalDigest",
    )?
    .to_owned();

    // Phase 2b: Evidence-hold commit + idempotent replay + fresh retention-policy plan
    let r2b = fixture.run_mcp_session(ALL_CAPS, &[
        (35, "commit", format!(r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-mcp-1","import_id":"{import_hex}","reason":"preserve driveway capture","approval_digest":"{hold_app}"}}"#)),
        (36, "commit", format!(r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-mcp-1","import_id":"{import_hex}","reason":"preserve driveway capture","approval_digest":"{hold_app}"}}"#)),
        (37, "plan", r#"{"intent":"retention-policy","sensor":"sensor:driveway-cam","enabled":true,"retain_for_ns":3600000000000,"max_retained_source_bytes":50000000,"attested_earliest_ns":1700000010000000000,"attested_latest_ns":1700000010000000000,"reason":"bounded ring cap"}"#.to_owned()),
    ])?;
    assert!(bool_field(
        field(&extract_envelope(&r2b[0])?.1, "payload")?,
        "authorityChanged"
    )?);
    assert!(!bool_field(
        field(&extract_envelope(&r2b[1])?.1, "payload")?,
        "authorityChanged"
    )?);
    let ret_app = text(
        field(&extract_envelope(&r2b[2])?.1, "payload")?,
        "approvalDigest",
    )?
    .to_owned();

    // Phase 2c: Retention-policy commit + idempotent replay + offline camera-supervision refusal + readback queries
    let r2c = fixture.run_mcp_session(ALL_CAPS, &[
        (38, "commit", format!(r#"{{"intent":"retention-policy","sensor":"sensor:driveway-cam","enabled":true,"retain_for_ns":3600000000000,"max_retained_source_bytes":50000000,"attested_earliest_ns":1700000010000000000,"attested_latest_ns":1700000010000000000,"reason":"bounded ring cap","approval_digest":"{ret_app}"}}"#)),
        (39, "commit", format!(r#"{{"intent":"retention-policy","sensor":"sensor:driveway-cam","enabled":true,"retain_for_ns":3600000000000,"max_retained_source_bytes":50000000,"attested_earliest_ns":1700000010000000000,"attested_latest_ns":1700000010000000000,"reason":"bounded ring cap","approval_digest":"{ret_app}"}}"#)),
        (40, "commit", format!(r#"{{"intent":"camera-supervision","op":"start_camera","camera_id":"sensor:driveway-cam","approval_digest":"{sup_app}","idempotency_key":"{sup_key}"}}"#)),
        (41, "query", r#"{"target":"privacy-masks","sensor":"sensor:driveway-cam"}"#.to_owned()),
        (42, "query", r#"{"target":"holds"}"#.to_owned()),
    ])?;
    assert!(bool_field(
        field(&extract_envelope(&r2c[0])?.1, "payload")?,
        "authorityChanged"
    )?);
    assert!(!bool_field(
        field(&extract_envelope(&r2c[1])?.1, "payload")?,
        "authorityChanged"
    )?);
    assert_eq!(
        text(&extract_envelope(&r2c[2])?.1, "errorId")?,
        ERR_DAEMON_OFFLINE
    );
    assert_eq!(
        field(field(&extract_envelope(&r2c[3])?.1, "payload")?, "masks")?
            .array()
            .map(<[Value]>::len),
        Some(1)
    );
    assert_eq!(
        field(field(&extract_envelope(&r2c[4])?.1, "payload")?, "holds")?
            .array()
            .map(<[Value]>::len),
        Some(1)
    );
    assert_eq!(
        field(
            field(&extract_envelope(&r2c[4])?.1, "payload")?,
            "retentionPolicies"
        )?
        .array()
        .map(<[Value]>::len),
        Some(1)
    );

    // Phase 3: Live `ControlPlaneServer` over real UDS `fss-ipc` -> live cameras + approved supervision dispatch
    let shared = ControlPlaneShared::new(
        SITE,
        deployment_root_digest(&fixture.root),
        vec!["sensor:driveway-cam".to_owned()],
        ControlStatusSnapshot {
            head_commit_sequence: 42,
            history_root: ContentDigest::sha256(b"live-hist-root"),
            state_root: ContentDigest::sha256(b"live-state-root"),
            cameras: vec![CameraLiveStatus {
                camera_id: "sensor:driveway-cam".to_owned(),
                running: true,
                fps_milli: 24_970,
                reconnect_count: 1,
                queue_depth: 3,
                frames_ingested: 12_345,
            }],
            ring: RingWatermarkStatus {
                used_bytes: 7_500_000,
                capacity_bytes: 10_000_000,
                watermark_percent: 75,
            },
            scrub: ActiveScrubStatus::Idle,
        },
        Arc::new(NoopForwardWriter),
    );
    let server = ControlPlaneServer::start(
        fixture.root.clone(),
        SITE.to_owned(),
        "daemon:ops-mcp-test".to_owned(),
        ContentDigest::sha256(b"live-manifest"),
        1_700_000_000_000_000_000,
        Arc::clone(&shared),
    )?;
    let p3 = fixture.run_mcp_session(ALL_CAPS, &[
        (50, "query", r#"{"target":"cameras"}"#.to_owned()),
        (51, "commit", format!(r#"{{"intent":"camera-supervision","op":"start_camera","camera_id":"sensor:driveway-cam","approval_digest":"{sup_app}","idempotency_key":"{sup_key}"}}"#)),
    ])?;
    let (is_err, cam_live) = extract_envelope(&p3[0])?;
    assert!(!is_err);
    let cam_p = field(&cam_live, "payload")?;
    assert!(
        bool_field(cam_p, "daemonLive")?
            && text(field(cam_p, "ring")?, "ringPressure")? == "elevated"
    );
    assert_eq!(
        text(
            &field(cam_p, "cameras")?.array().ok_or("cameras")?[0],
            "cameraId"
        )?,
        "sensor:driveway-cam"
    );
    let (is_err, sup_live) = extract_envelope(&p3[1])?;
    // This deliberately process-local owner has no durable key journal. The new request
    // must refuse instead of silently falling back to legacy duplicate-prone admission.
    assert!(is_err);
    assert!(format!("{sup_live:?}").contains("durable"));
    assert!(shared.drain_control_commands().is_empty());
    server.shutdown()?;

    // Phase 4: Fail-closed capability denial on EVERY target/probe/intent + `-32602` escape-hatch rejection
    let p4 = fixture.run_mcp_session(&[], &[
        (60, "query", r#"{"target":"cameras"}"#.to_owned()),
        (61, "query", r#"{"target":"graph"}"#.to_owned()),
        (62, "query", r#"{"target":"fusion","evidence":[{"id":"e1","sensor":"s1","llr_lo":100,"llr_hi":200,"calibration_generation":"c1"}]}"#.to_owned()),
        (63, "query", r#"{"target":"holds"}"#.to_owned()),
        (64, "query", r#"{"target":"privacy-masks"}"#.to_owned()),
        (65, "investigate", format!(r#"{{"transition":"probe-detect","session":"{session_id}","case_id":"c","hypothesis_id":"h","import_id":"{import_hex}"}}"#)),
        (66, "investigate", format!(r#"{{"transition":"probe-corroborate","session":"{session_id}","cameras":[{{"sensor_id":"cam-a","failure_domains":["poe:a"],"zones":["driveway"]}},{{"sensor_id":"cam-b","failure_domains":["poe:b"],"zones":["driveway"]}}],"observations":[{{"sensor_id":"cam-a","zone_id":"driveway","track_id":1,"class_label":"person","score_ppm":900000,"earliest_ns":1000000000,"latest_ns":1050000000}},{{"sensor_id":"cam-b","zone_id":"driveway","track_id":2,"class_label":"person","score_ppm":900000,"earliest_ns":1010000000,"latest_ns":1060000000}}]}}"#)),
        (67, "plan", r#"{"intent":"privacy-mask","sensor":"sensor:driveway-cam","resolution":[96,64],"rectangles":[[0,0,32,24]]}"#.to_owned()),
        (68, "commit", format!(r#"{{"intent":"evidence-hold","action":"place","hold_id":"hold-mcp-2","import_id":"{import_hex}","reason":"cap check","approval_digest":"{hold_app}"}}"#)),
        (69, "plan", r#"{"intent":"retention-policy","sensor":"sensor:driveway-cam","enabled":true,"retain_for_ns":3600000000000,"attested_earliest_ns":1700000010000000000,"attested_latest_ns":1700000010000000000,"reason":"cap check"}"#.to_owned()),
        (70, "plan", r#"{"intent":"camera-supervision","op":"start_camera","camera_id":"sensor:driveway-cam"}"#.to_owned()),
        (71, "query", r#"{"target":"cameras","capability":"CAP-AGENT-QUERY-001"}"#.to_owned()),
        (72, "query", r#"{"target":"graph","root":"/etc"}"#.to_owned()),
        (73, "plan", r#"{"intent":"camera-supervision","op":"start_camera","shell":"rm -rf /"}"#.to_owned()),
    ])?;
    for (idx, item) in p4.iter().enumerate().take(11) {
        let (is_err, env) = extract_envelope(item)?;
        assert!(
            is_err && text(&env, "errorId")? == ERR_CAPABILITY_DENIED,
            "idx {idx}"
        );
    }
    for (idx, item) in p4.iter().enumerate().take(14).skip(11) {
        let code = field(item, "error")?
            .object()
            .and_then(|o| o.get("code"))
            .and_then(|v| match v {
                Value::Number(n) => n.parse::<i32>().ok(),
                _ => None,
            });
        assert_eq!(code, Some(-32602), "escape hatch idx {idx}");
    }
    Ok(())
}
