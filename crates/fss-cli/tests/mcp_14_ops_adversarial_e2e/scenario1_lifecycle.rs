#![forbid(unsafe_code)]
//! Scenario 1 — Full 14-Tool JSON-RPC 2.0 Lifecycle Against Live `fss-daemon` + Real RFC 8446 TLS 1.3.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_cli::query_cmd::hydration::{
    CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3, H2_PAYLOAD_SCHEMA, H3_PAYLOAD_SCHEMA, decode_base64,
};
use fss_cli::query_cmd::ops_targets::{
    CAP_AGENT_INVESTIGATE, CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS, CAP_RETENTION_COMMIT, CAP_RETENTION_PREPARE,
};
use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb_v1};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::json_input::Value;
use fss_core::{ContentDigest, EventId};
use fss_fusion::ScoreCalibration;
use fss_reference::agent_orient::{OrientLimits, read_deployment};

use super::TestResult;
use super::fixtures::{
    LiveDaemonHandle, PRINCIPAL, TempWorkspace, build_site_manifest, import_corroboration_pair,
    import_sentinel_and_watch_event, init_empty_deployment, publish_corroborated_event,
};
use super::harness::{
    CORE_TOOL_NAMES, LatencyStats, McpClient, array, bool_field, field, json_stringify,
    orientation_anchor, quote, text,
};
use super::report::Scenario1Report;
use super::scenario1_effects::{EffectsContext, run_effects_and_closing, scan_all_canary_surfaces};

const OPS_CAPS: &[&str] = &[
    CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS,
    CAP_RETENTION_PREPARE,
    CAP_RETENTION_COMMIT,
    CAP_AGENT_INVESTIGATE,
    CAP_AGENT_PLAN_PREPARE,
    CAP_AGENT_PLAN_COMMIT,
];

const HYDRATION_CAPS: &[&str] = &[
    CAP_AGENT_HYDRATE_H2,
    CAP_AGENT_HYDRATE_H3,
    CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS,
];

fn merge_stats(
    dest_us: &mut BTreeMap<String, Vec<u64>>,
    dest_tok: &mut BTreeMap<String, u64>,
    src_us: BTreeMap<String, Vec<u64>>,
    src_tok: BTreeMap<String, u64>,
) {
    for (k, v) in src_us {
        dest_us.entry(k).or_default().extend(v);
    }
    for (k, v) in src_tok {
        *dest_tok.entry(k).or_insert(0) += v;
    }
}

pub fn run() -> TestResult<Scenario1Report> {
    let ws = TempWorkspace::new("s1")?;
    let deploy_root = init_empty_deployment(&ws)?;

    // Start live multi-camera fss-daemon serving real v2 storage + UDS fss-ipc on deploy_root.
    let manifest = build_site_manifest(&ws.v2_root, &deploy_root, 3, 64 * 1024 * 1024, 65_536)?;
    let daemon = LiveDaemonHandle::start(manifest, Duration::from_millis(50), false)?;

    // Persistent primary MCP client with 7 ops capabilities (<= 8 CLI ceiling).
    let mut ops_mcp = McpClient::spawn(
        "scenario_1",
        "s1-ops-agent",
        &deploy_root,
        PRINCIPAL,
        false,
        OPS_CAPS,
    )?;

    // 1. tools/list -> assert exact 14 CORE_TOOLS, zero escape hatches.
    let (list_reply, _) = ops_mcp.tools_list()?;
    let tools = array(&list_reply, &["result", "tools"])?;
    let mut listed_names: Vec<String> = tools
        .iter()
        .map(|t| text(t, &["name"]).map(ToOwned::to_owned))
        .collect::<TestResult<Vec<_>>>()?;
    listed_names.sort();
    let expected_names: Vec<String> = CORE_TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(listed_names, expected_names, "exact 14 CORE_TOOLS required");
    for tool_val in tools {
        let tname = text(tool_val, &["name"])?;
        let schema = field(tool_val, &["inputSchema"])?;
        if let Some(props) = schema
            .object()
            .and_then(|o| o.get("properties"))
            .and_then(Value::object)
        {
            for forbidden in [
                "root",
                "principal",
                "shell",
                "command",
                "allow_visual_hydration",
            ] {
                assert!(
                    !props.contains_key(forbidden),
                    "tool `{tname}` exposed forbidden escape hatch `{forbidden}`"
                );
            }
        }
    }

    // 2. doctor -> assert healthy and possibly_stale == false.
    let doc = ops_mcp.call("doctor", "{}")?;
    assert!(!doc.is_error, "doctor failed: {}", doc.body_text);
    assert_eq!(text(&doc.envelope, &["schema"])?, "fss.doctor.v1");
    assert_eq!(text(&doc.envelope, &["verdict"])?, "healthy");
    assert!(!bool_field(&doc.envelope, &["possibly_stale"])?);

    // 3. session_open -> verify BOTH pulse and brief views return ok!
    let open_pulse = ops_mcp.call(
        "session_open",
        r#"{"mission":"Pulse view admission check.","objective":"Verify pulse session_open succeeds.","view":"pulse","budget_tokens":40000}"#,
    )?;
    assert!(
        !open_pulse.is_error,
        "session_open(pulse) failed: {}",
        open_pulse.body_text
    );
    assert_eq!(text(&open_pulse.envelope, &["outcome"])?, "ok");

    let open_brief = ops_mcp.call(
        "session_open",
        r#"{"mission":"Brief view admission check.","objective":"Verify brief session_open succeeds.","view":"brief","budget_tokens":40000}"#,
    )?;
    assert!(
        !open_brief.is_error,
        "session_open(brief) failed: {}",
        open_brief.body_text
    );
    assert_eq!(text(&open_brief.envelope, &["outcome"])?, "ok");

    // 4. session_orient across pulse, brief, and epistemic_map + warm latency < 10ms p99!
    let orient_pulse = ops_mcp.call("session_orient", r#"{"view":"pulse","budget_tokens":300}"#)?;
    assert!(
        !orient_pulse.is_error,
        "orient(pulse): {}",
        orient_pulse.body_text
    );
    let orient_brief =
        ops_mcp.call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)?;
    assert!(
        !orient_brief.is_error,
        "orient(brief): {}",
        orient_brief.body_text
    );
    let orient_epistemic = ops_mcp.call(
        "session_orient",
        r#"{"view":"epistemic_map","budget_tokens":3000}"#,
    )?;
    assert!(
        !orient_epistemic.is_error,
        "orient(epistemic_map): {}",
        orient_epistemic.body_text
    );

    // Warmup + measure warm session_orient p99 latency across 20 warm iterations.
    let _ = ops_mcp.call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)?;
    let mut warm_orient_us = Vec::with_capacity(20);
    for _ in 0..20 {
        let r = ops_mcp.call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)?;
        assert!(!r.is_error);
        warm_orient_us.push(r.latency_us);
    }
    let warm_orient_stats = LatencyStats::from_micros(&warm_orient_us);

    // 9a. Populate sentinel watch recording + run full H0 -> H1 -> H2 -> H3 hydration ladder
    //     while single-event Brief context fits the native 1600-token H0/H1 ceiling!
    let (sentinel_import_id, watch_event_id) =
        import_sentinel_and_watch_event(&ws, "sensor:porch-cam", 5)?;
    let sentinel_import_hex = sentinel_import_id.to_text();

    let mut hyd_mcp = McpClient::spawn(
        "scenario_1",
        "s1-hydration-agent",
        &deploy_root,
        PRINCIPAL,
        true,
        HYDRATION_CAPS,
    )?;
    let hyd_open = hyd_mcp.call(
        "session_open",
        r#"{"mission":"Evidence hydration H0 through H3 ladder.","objective":"Inspect watch event from H0 metadata through H3 redacted JPEG.","view":"brief","budget_tokens":100000}"#,
    )?;
    assert!(
        !hyd_open.is_error,
        "hyd session_open: {}",
        hyd_open.body_text
    );
    let hyd_session_id = text(&hyd_open.envelope, &["sessionId"])?.to_owned();

    let snap_hyd = read_deployment(&deploy_root, &OrientLimits::default())?;
    let watch_retained = snap_hyd
        .event(&EventId::parse(&watch_event_id)?)
        .ok_or("watch event missing for hydration")?;
    let watch_rev_digest = watch_retained.revision_digest.to_text();
    let hyd_anchor = fss_reference::agent_follow::snapshot_anchor_token(&snap_hyd);

    let h0 = hyd_mcp.call(
        "query",
        &object(&[
            ("target", string("evidence-hydration")),
            ("level", string("H0")),
            ("session", string(&hyd_session_id)),
            ("generation", string("0")),
            ("event_id", string(&watch_event_id)),
            ("revision_digest", string(&watch_rev_digest)),
            ("anchor", string(&hyd_anchor)),
        ]),
    )?;
    assert!(!h0.is_error, "H0 hydration: {}", h0.body_text);
    let descriptor_digest =
        text(&h0.envelope, &["payload", "descriptor", "descriptorDigest"])?.to_owned();
    let h0_cursor = json_stringify(field(
        &h0.envelope,
        &["payload", "receipt", "continuation"],
    )?);

    let h1 = hyd_mcp.call(
        "query",
        &object(&[
            ("target", string("evidence-hydration")),
            ("level", string("H1")),
            ("session", string(&hyd_session_id)),
            ("generation", string("0")),
            ("event_id", string(&watch_event_id)),
            ("revision_digest", string(&watch_rev_digest)),
            ("descriptor_digest", string(&descriptor_digest)),
            ("anchor", string(&hyd_anchor)),
            ("continuation", string(&h0_cursor)),
        ]),
    )?;
    assert!(!h1.is_error, "H1 hydration: {}", h1.body_text);

    let h2 = hyd_mcp.call(
        "query",
        &object(&[
            ("target", string("evidence-hydration")),
            ("level", string("H2")),
            ("session", string(&hyd_session_id)),
            ("event_id", string(&watch_event_id)),
            ("revision_digest", string(&watch_rev_digest)),
            ("descriptor_digest", string(&descriptor_digest)),
            ("anchor", string(&hyd_anchor)),
        ]),
    )?;
    assert!(!h2.is_error, "H2 hydration: {}", h2.body_text);
    assert_eq!(text(&h2.envelope, &["payloadSchema"])?, H2_PAYLOAD_SCHEMA);
    assert!(!array(&h2.envelope, &["payload", "trackTrajectories"])?.is_empty());

    let h3 = hyd_mcp.call(
        "query",
        &object(&[
            ("target", string("evidence-hydration")),
            ("level", string("H3")),
            ("session", string(&hyd_session_id)),
            ("event_id", string(&watch_event_id)),
            ("revision_digest", string(&watch_rev_digest)),
            ("descriptor_digest", string(&descriptor_digest)),
            ("anchor", string(&hyd_anchor)),
            ("max_h3_frames", "2".to_owned()),
            ("max_dimension", "640".to_owned()),
        ]),
    )?;
    assert!(!h3.is_error, "H3 hydration: {}", h3.body_text);
    assert_eq!(text(&h3.envelope, &["payloadSchema"])?, H3_PAYLOAD_SCHEMA);
    let h3_blocks = h3.content_blocks()?;
    assert!(
        h3_blocks.len() >= 2,
        "H3 must return text + image MCP content blocks"
    );
    assert_eq!(text(&h3_blocks[1], &["type"])?, "image");
    assert_eq!(text(&h3_blocks[1], &["mimeType"])?, "image/jpeg");
    let h3_jpeg = decode_base64(text(&h3_blocks[1], &["data"])?)?;
    let rgb_limits = RgbDecodeLimits::default();
    let mut rgb_budget = DecodeBudget::new(rgb_limits.rgb_work_bound());
    let decoded = decode_rgb_v1(
        &h3_jpeg,
        ContentDigest::sha256(&h3_jpeg).bytes(),
        ComponentInterpretation::YCbCr,
        rgb_limits,
        &mut rgb_budget,
    )?;
    assert_eq!(decoded.dimensions(), [128, 96]);

    // Capture anchor BEFORE live daemon motion + corroborated delta event for AOP-004 session_follow!
    let orient_pre_delta =
        ops_mcp.call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)?;
    assert!(
        !orient_pre_delta.is_error,
        "orient(pre_delta): {}",
        orient_pre_delta.body_text
    );
    let anchor_before_delta = orientation_anchor(&orient_pre_delta.body_text)?;

    // Trigger live daemon motion + add 2-camera corroboration pair & corroborated delta event!
    daemon.inject_corroborated_motion("sensor:cam-01", "sensor:cam-02", 500)?;
    let (east_arg, west_arg) = import_corroboration_pair(&ws)?;
    let corr_event_id =
        publish_corroborated_event(&deploy_root, &east_arg, &west_arg, "door:32,0,40,48")?;
    let open_mission = ops_mcp.call(
        "session_open",
        r#"{"mission":"Full 14-tool MCP mission lifecycle.","objective":"Orient, query, investigate, hydrate, plan, commit, reconcile, and handoff cleanly.","view":"epistemic_map","budget_tokens":200000}"#,
    )?;
    assert!(
        !open_mission.is_error,
        "session_open(epistemic_map) failed: {}",
        open_mission.body_text
    );
    assert_eq!(text(&open_mission.envelope, &["outcome"])?, "ok");
    let session_id = text(&open_mission.envelope, &["sessionId"])?.to_owned();

    // 5. query across ALL operational + evidence targets!
    let q_cameras = ops_mcp.call("query", r#"{"target":"cameras"}"#)?;
    assert!(
        !q_cameras.is_error,
        "query(cameras): {}",
        q_cameras.body_text
    );
    assert!(bool_field(&q_cameras.envelope, &["payload", "daemonLive"])?);
    assert_eq!(
        array(&q_cameras.envelope, &["payload", "cameras"])?.len(),
        3
    );

    let q_events = ops_mcp.call(
        "query",
        &object(&[
            ("target", string("events")),
            ("max_entries", "16".to_owned()),
        ]),
    )?;
    assert!(!q_events.is_error, "query(events): {}", q_events.body_text);

    let q_footage = ops_mcp.call(
        "query",
        r#"{"target":"footage","sensor":"sensor:east","stream":"stream:east","max_entries":4}"#,
    )?;
    assert!(
        !q_footage.is_error,
        "query(footage): {}",
        q_footage.body_text
    );

    let q_sources = ops_mcp.call("query", r#"{"target":"sources","max_entries":8}"#)?;
    assert!(
        !q_sources.is_error,
        "query(sources): {}",
        q_sources.body_text
    );

    let q_graph = ops_mcp.call(
        "query",
        r#"{"target":"graph","projection":"SensorCoverageGraph","algorithm":"ALG-BRIDGE-001"}"#,
    )?;
    assert!(!q_graph.is_error, "query(graph): {}", q_graph.body_text);
    assert_eq!(
        text(&q_graph.envelope, &["payload", "witness", "schema"])?,
        "fss.graph_algorithm_witness.v1"
    );

    let q_fusion = ops_mcp.call(
        "query",
        r#"{"target":"fusion","evidence":[{"id":"e1","sensor":"sensor:east","failure_domains":["poe:a"],"llr_lo":1300,"llr_hi":1500,"calibration_generation":"cal:v1"},{"id":"e2","sensor":"sensor:west","failure_domains":["poe:b"],"llr_lo":1300,"llr_hi":1500,"calibration_generation":"cal:v1"}],"without_sensors":["sensor:west"],"without_domains":["poe:b"]}"#,
    )?;
    assert!(!q_fusion.is_error, "query(fusion): {}", q_fusion.body_text);
    assert_eq!(
        text(
            &q_fusion.envelope,
            &["payload", "baseline", "decision", "kind"]
        )?,
        "alert"
    );
    assert!(bool_field(
        &q_fusion.envelope,
        &["payload", "ablation", "decisionChanged"]
    )?);

    let q_holds = ops_mcp.call("query", r#"{"target":"holds"}"#)?;
    assert!(!q_holds.is_error, "query(holds): {}", q_holds.body_text);

    let q_masks = ops_mcp.call("query", r#"{"target":"privacy-masks"}"#)?;
    assert!(
        !q_masks.is_error,
        "query(privacy-masks): {}",
        q_masks.body_text
    );

    // 6. session_follow -> verify live committed delta arrival after anchor_before_delta!
    let follow_res = ops_mcp.call(
        "session_follow",
        &object(&[
            ("since", string(&anchor_before_delta)),
            ("view", string("brief")),
            ("max_entries", "16".to_owned()),
        ]),
    )?;
    assert!(
        !follow_res.is_error,
        "session_follow: {}",
        follow_res.body_text
    );
    assert!(
        follow_res.body_text.contains(&corr_event_id)
            || !array(&follow_res.envelope, &["payload", "entries"])?.is_empty(),
        "session_follow must observe committed delta after anchor"
    );

    // 7. explain (decision_diff, forensic, AND what_if inline counterfactual)!
    let exp_diff = ops_mcp.call(
        "explain",
        &object(&[
            ("event_id", string(&corr_event_id)),
            ("view", string("decision_diff")),
        ]),
    )?;
    assert!(
        !exp_diff.is_error,
        "explain(decision_diff): {}",
        exp_diff.body_text
    );

    let exp_forensic = ops_mcp.call(
        "explain",
        &object(&[
            ("event_id", string(&corr_event_id)),
            ("view", string("forensic")),
            ("budget_tokens", "8000".to_owned()),
            ("custody", string("yes")),
        ]),
    )?;
    assert!(
        !exp_forensic.is_error,
        "explain(forensic): {}",
        exp_forensic.body_text
    );

    // Build exact what_if counterfactual matching the retained corroborated event's domains.
    let snap = read_deployment(&deploy_root, &OrientLimits::default())?;
    let retained_corr = snap
        .event(&EventId::parse(&corr_event_id)?)
        .ok_or("corroborated event missing from snapshot")?;
    let corr_rev_digest = retained_corr.revision_digest.to_text();
    let mut domain_names: Vec<String> = retained_corr
        .event
        .evidence
        .iter()
        .filter(|ev| {
            matches!(
                ev.relation,
                fss_core::EvidenceEdgeRelation::Supports
                    | fss_core::EvidenceEdgeRelation::Contradicts
            )
        })
        .map(|ev| ev.failure_domain.clone())
        .collect();
    domain_names.sort();
    domain_names.dedup();
    let without_domain = domain_names
        .first()
        .ok_or("no failure domains on event")?
        .clone();
    let domain_scores_entries: Vec<(&str, String)> = domain_names
        .iter()
        .map(|d| (d.as_str(), "900000".to_owned()))
        .collect();
    let cal = ScoreCalibration::from_counts(
        "cal:mcp14-whatif:v1",
        &[0, 500_000],
        &[(10, 990), (990, 10)],
    )?;
    let what_if_scenario = object(&[
        ("schema", string("fss.event_counterfactual_request.v1")),
        ("event_revision_digest", string(&corr_rev_digest)),
        ("without_domains", format!("[{}]", string(&without_domain))),
        ("domain_scores_ppm", object(&domain_scores_entries)),
        (
            "score_calibration",
            object(&[
                ("schema", string("fss.score_calibration.v1")),
                ("generation", string(&cal.generation)),
                ("digest", string(&cal.digest.to_text())),
                (
                    "bins",
                    r#"[{"lo_ppm":0,"true_positives":10,"false_positives":990},{"lo_ppm":500000,"true_positives":990,"false_positives":10}]"#
                        .to_owned(),
                ),
            ]),
        ),
    ]);
    let exp_what_if = ops_mcp.call(
        "explain",
        &object(&[
            ("event_id", string(&corr_event_id)),
            ("question", string("what_if")),
            ("view", string("forensic")),
            ("budget_tokens", "16000".to_owned()),
            ("counterfactual", what_if_scenario),
        ]),
    )?;
    assert!(
        !exp_what_if.is_error,
        "explain(what_if): {}",
        exp_what_if.body_text
    );

    // 8. investigate: open -> expand (hypothesis) -> activate -> cite -> assess -> claim ->
    //    probe-detect -> probe-corroborate -> finding -> conclude!
    let stop_rule = "independent two-camera evidence settles competing hypotheses";
    let case_id = "case:mcp14-door";
    let draft = format!(
        r#"{{"caseId":"{case_id}","question":"Did a corroborated entrant cross the east door?","decisionInformed":"Alert dispatch vs hold","hypotheses":[{{"hypothesisId":"h:entry","description":"Corroborated physical entry","predictions":["matched east and west tracks"]}},{{"hypothesisId":"h:artifact","description":"Transient glare artifact","predictions":["disjoint sensor tracks"]}}],"knowns":[{{"statementId":"k:cams","text":"East and west cameras retained footage","basis":["sensor:east","sensor:west"]}}],"unknowns":[{{"statementId":"u:identity","text":"Person identity remains unknown"}}],"discriminators":[{{"discriminatorId":"d:overlap","description":"Two-camera ground-plane overlap","separates":["h:entry","h:artifact"],"expectedOutcomes":["matched","disjoint"]}}],"probes":["probe:corroborate"],"stopRules":["{stop_rule}"],"decisionWindowNs":3600000000000}}"#
    );
    let inv_open = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"open","draft":{draft}}}"#,
            quote(&session_id)
        ),
    )?;
    assert!(
        !inv_open.is_error,
        "investigate(open): {}",
        inv_open.body_text
    );
    let mut case_rev = text(&inv_open.envelope, &["decisionFingerprint"])?.to_owned();

    let expansion = r#"{"hypothesis":{"hypothesisId":"h:animal","description":"Small animal crossing","predictions":["low bounding box height"]},"discriminator":{"discriminatorId":"d:size","description":"Target height","separates":["h:animal","h:entry"],"expectedOutcomes":["small","human-height"]},"probe":"probe:size-check"}"#;
    let inv_expand = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"expand","case":"{case_id}","expected":{},"expansion":{expansion}}}"#,
            quote(&session_id),
            quote(&case_rev)
        ),
    )?;
    assert!(
        !inv_expand.is_error,
        "investigate(expand): {}",
        inv_expand.body_text
    );
    case_rev = text(&inv_expand.envelope, &["decisionFingerprint"])?.to_owned();

    let inv_act = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"activate","case":"{case_id}","expected":{}}}"#,
            quote(&session_id),
            quote(&case_rev)
        ),
    )?;
    assert!(
        !inv_act.is_error,
        "investigate(activate): {}",
        inv_act.body_text
    );
    case_rev = text(&inv_act.envelope, &["decisionFingerprint"])?.to_owned();

    let ev_support = ContentDigest::sha256(b"mcp14-corroborated-track-match").to_text();
    let ev_contra = ContentDigest::sha256(b"mcp14-no-glare-or-animal-signature").to_text();
    for (hyp, ev, side) in [
        ("h:entry", ev_support.as_str(), "support"),
        ("h:artifact", ev_contra.as_str(), "contradiction"),
        ("h:animal", ev_contra.as_str(), "contradiction"),
    ] {
        let cited = ops_mcp.call(
            "investigate",
            &format!(
                r#"{{"session":{},"transition":"cite","case":"{case_id}","expected":{},"hypothesis":"{hyp}","evidence":{},"side":"{side}"}}"#,
                quote(&session_id),
                quote(&case_rev),
                quote(ev)
            ),
        )?;
        assert!(
            !cited.is_error,
            "investigate(cite {hyp}): {}",
            cited.body_text
        );
        case_rev = text(&cited.envelope, &["decisionFingerprint"])?.to_owned();
    }
    for (hyp, ev, disp) in [
        ("h:entry", ev_support.as_str(), "supported"),
        ("h:artifact", ev_contra.as_str(), "refuted"),
        ("h:animal", ev_contra.as_str(), "refuted"),
    ] {
        let assessed = ops_mcp.call(
            "investigate",
            &format!(
                r#"{{"session":{},"transition":"assess","case":"{case_id}","expected":{},"hypothesis":"{hyp}","disposition":"{disp}","evidence":{}}}"#,
                quote(&session_id),
                quote(&case_rev),
                quote(ev)
            ),
        )?;
        assert!(
            !assessed.is_error,
            "investigate(assess {hyp}): {}",
            assessed.body_text
        );
        case_rev = text(&assessed.envelope, &["decisionFingerprint"])?.to_owned();
    }

    // Work claim -> activate -> complete!
    let claim_acq = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"claim","case":"{case_id}","work":"probe:probe:corroborate","lease_ms":60000}}"#,
            quote(&session_id)
        ),
    )?;
    assert!(
        !claim_acq.is_error,
        "investigate(claim): {}",
        claim_acq.body_text
    );
    let claim_id = text(
        &array(
            &claim_acq.envelope,
            &["payload", "epistemic", "propositions"],
        )?[0],
        &["id"],
    )?
    .to_owned();
    let claim_rev = text(&claim_acq.envelope, &["decisionFingerprint"])?.to_owned();
    let claim_act = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"claim-activate","claim":{},"expected":{}}}"#,
            quote(&session_id),
            quote(&claim_id),
            quote(&claim_rev)
        ),
    )?;
    assert!(
        !claim_act.is_error,
        "claim-activate: {}",
        claim_act.body_text
    );
    let claim_rev2 = text(&claim_act.envelope, &["decisionFingerprint"])?.to_owned();
    let claim_done = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"claim-complete","claim":{},"expected":{},"result":{}}}"#,
            quote(&session_id),
            quote(&claim_id),
            quote(&claim_rev2),
            quote(&ev_support)
        ),
    )?;
    assert!(
        !claim_done.is_error,
        "claim-complete: {}",
        claim_done.body_text
    );

    // Discriminating probes: probe-detect + probe-corroborate!
    let p_detect = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"transition":"probe-detect","session":{},"case_id":"{case_id}","hypothesis_id":"h:entry","import_id":{},"max_frames":3}}"#,
            quote(&session_id),
            quote(&sentinel_import_hex)
        ),
    )?;
    assert!(!p_detect.is_error, "probe-detect: {}", p_detect.body_text);
    assert!(!bool_field(
        &p_detect.envelope,
        &["payload", "effectsAuthorized"]
    )?);

    let p_corr = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"transition":"probe-corroborate","session":{},"case_id":"{case_id}","hypothesis_id":"h:entry","cameras":[{{"sensor_id":"cam-a","failure_domains":["poe:a"],"zones":["driveway"]}},{{"sensor_id":"cam-b","failure_domains":["poe:b"],"zones":["driveway"]}}],"observations":[{{"sensor_id":"cam-a","zone_id":"driveway","track_id":1,"class_label":"person","score_ppm":930000,"earliest_ns":1000000000,"latest_ns":1050000000}},{{"sensor_id":"cam-b","zone_id":"driveway","track_id":2,"class_label":"person","score_ppm":940000,"earliest_ns":1010000000,"latest_ns":1060000000}}]}}"#,
            quote(&session_id)
        ),
    )?;
    assert!(!p_corr.is_error, "probe-corroborate: {}", p_corr.body_text);
    assert_eq!(
        text(
            &array(&p_corr.envelope, &["payload", "decisions"])?[0],
            &["outcome"]
        )?,
        "corroborated"
    );

    // Immutable finding + case conclude!
    let finding = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"finding","case":"{case_id}","hypothesis":"h:entry","claim":"Two independent camera clusters matched entry in door zone.","state":"estimated","supporting":[{}]}}"#,
            quote(&session_id),
            quote(&ev_support)
        ),
    )?;
    assert!(
        !finding.is_error,
        "investigate(finding): {}",
        finding.body_text
    );

    let concluded = ops_mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"conclude","case":"{case_id}","expected":{},"conclusion":"resolved","stop_rule":{},"assessment":{},"residual_unknowns":["u:identity"]}}"#,
            quote(&session_id),
            quote(&case_rev),
            quote(stop_rule),
            quote(&ev_support)
        ),
    )?;
    assert!(
        !concluded.is_error,
        "investigate(conclude): {}",
        concluded.body_text
    );

    // 10–13. Operational intents, alert plan/commit/wait/reconcile, pure-Rust RFC 8446 TLS 1.3
    //        HMAC webhook delivery, Indeterminate reconciliation, feedback/handoff/resume/cancel!
    let effects = run_effects_and_closing(
        &mut ops_mcp,
        &EffectsContext {
            ws: &ws,
            deploy_root: &deploy_root,
            session_id: &session_id,
            corr_event_id: &corr_event_id,
            east_arg: &east_arg,
            west_arg: &west_arg,
            sentinel_import_hex: &sentinel_import_hex,
        },
    )?;

    // Shut down MCP clients + live fss-daemon cleanly and assert zero leaked obligations/tasks!
    let (tx_ops, us_ops, tok_ops) = ops_mcp.finish()?;
    let (tx_hyd, us_hyd, tok_hyd) = hyd_mcp.finish()?;
    let (shutdown, telemetry_lines) = daemon.stop_gracefully()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);

    let mut all_tx = tx_ops;
    all_tx.extend(tx_hyd);
    let mut all_us = BTreeMap::new();
    let mut all_tok = BTreeMap::new();
    merge_stats(&mut all_us, &mut all_tok, us_ops, tok_ops);
    merge_stats(&mut all_us, &mut all_tok, us_hyd, tok_hyd);

    // Verify all 14 CORE_TOOLS were actually invoked!
    let called_tools: BTreeSet<String> = all_tx.iter().filter_map(|e| e.tool.clone()).collect();
    for tool in CORE_TOOL_NAMES {
        assert!(
            called_tools.contains(tool),
            "Scenario 1 missed calling required MCP tool `{tool}`"
        );
    }

    // Canary leak scan across every RPC response, daemon telemetry, and durable journals!
    let (surfaces, bytes_scanned) = scan_all_canary_surfaces(
        &effects.rig,
        &deploy_root,
        &effects.tls_journal_path,
        &effects.tls_audit_jsonl,
        &all_tx,
        &telemetry_lines,
    )?;

    let per_tool_latency: BTreeMap<String, LatencyStats> = all_us
        .iter()
        .map(|(k, v)| (k.clone(), LatencyStats::from_micros(v)))
        .collect();

    assert!(
        warm_orient_stats.p99_ms < 10.0,
        "warm session_orient p99 latency {:.3}ms >= 10.0ms budget",
        warm_orient_stats.p99_ms
    );

    Ok(Scenario1Report {
        tools_verified: listed_names,
        per_tool_latency,
        per_tool_tokens: all_tok,
        warm_orient_latency: warm_orient_stats,
        tls13_signature_verified: true,
        tls13_idempotency_key: effects.tls13_idempotency_key,
        indeterminate_reconciled: true,
        live_daemon_active_tasks: shutdown.active_tasks,
        live_daemon_leaked_obligations: shutdown.leaked_obligations,
        canary_surfaces_scanned: surfaces,
        canary_bytes_scanned: bytes_scanned,
        canary_leaks: 0,
        transcript: all_tx,
    })
}
