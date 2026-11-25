#![forbid(unsafe_code)]
//! Scenario 3 — Concurrent 4-Agent `fss-mcp` Read/Write Stress Against Live 8-Camera `fss-daemon`
//! with Continuous Ingestion, Periodic Pack Compaction, and Graceful Shutdown Verification.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_cli::query_cmd::hydration::{CAP_AGENT_HYDRATE_H3, decode_base64};
use fss_cli::query_cmd::ops_targets::{
    CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_AGENT_QUERY, CAP_OBSERVE_STATUS,
};
use fss_core::ContentDigest;
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_vault::{CanaryLeakScanner, SecretScope};

use super::TestResult;
use super::fixtures::{
    CANARY_CAM_RTSP_PASS, CANARY_UNIFI_API_KEY, CANARY_WEBHOOK_HMAC, LiveDaemonHandle, PRINCIPAL,
    SITE_ID, TempWorkspace, VaultCanaryRig, build_site_manifest, import_sentinel_and_watch_event,
    init_empty_deployment,
};
use super::harness::{
    LatencyStats, McpClient, TranscriptEntry, array, bool_field, orientation_anchor, quote, text,
};
use super::report::Scenario3Report;

const STRESS_CAPS: &[&str] = &[
    CAP_AGENT_QUERY,
    CAP_OBSERVE_STATUS,
    CAP_AGENT_HYDRATE_H3,
    CAP_AGENT_PLAN_PREPARE,
    CAP_AGENT_PLAN_COMMIT,
];

struct WorkerOutcome {
    total_rpcs: usize,
    orient_query_us: Vec<u64>,
    h3_us: Vec<u64>,
    locked_errors: usize,
    protocol_errors: usize,
    transcript: Vec<TranscriptEntry>,
}

pub fn run() -> TestResult<Scenario3Report> {
    let ws = TempWorkspace::new("s3")?;
    let deploy_root = init_empty_deployment(&ws)?;

    // Seed compact 6-frame sentinel MJPEG (motion frames 3..5 for confirmation_hits: 2) + privacy mask.
    let (import_id, _watch_event_id) = import_sentinel_and_watch_event(&ws, "sensor:cam-01", 6)?;
    let import_hex = import_id.to_text();

    let mut setup_mcp = McpClient::spawn(
        "scenario_3",
        "s3-setup",
        &deploy_root,
        PRINCIPAL,
        false,
        STRESS_CAPS,
    )?;
    let pm_plan = setup_mcp.call(
        "plan",
        r#"{"intent":"privacy-mask","sensor":"sensor:cam-01","resolution":[128,96],"rectangles":[[16,16,48,32]]}"#,
    )?;
    assert!(!pm_plan.is_error);
    let pm_app = text(&pm_plan.envelope, &["payload", "approvalDigest"])?.to_owned();
    let pm_commit = setup_mcp.call(
        "commit",
        &format!(
            r#"{{"intent":"privacy-mask","sensor":"sensor:cam-01","resolution":[128,96],"rectangles":[[16,16,48,32]],"approval_digest":{}}}"#,
            quote(&pm_app)
        ),
    )?;
    assert!(!pm_commit.is_error);
    let initial_orient =
        setup_mcp.call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)?;
    assert!(!initial_orient.is_error);
    let base_anchor = orientation_anchor(&initial_orient.body_text)?;
    let _ = setup_mcp.finish()?;

    // Start live 8-camera fss-daemon with 64 KiB pack rotation and seeded expired candidates so
    // retention eviction and pack compaction run continuously while accommodating durable 8-camera
    // corroborated event holds without tripping StorageQuotaPinned during graceful shutdown.
    let manifest = build_site_manifest(&ws.v2_root, &deploy_root, 8, 4 * 1024 * 1024, 65_536)?;
    let daemon = LiveDaemonHandle::start(manifest, Duration::from_millis(12), true)?;

    // Open vault canary rig for leak check.
    let _rig = VaultCanaryRig::open(
        &ws.vault_dir,
        SecretScope::new(
            fss_vault::AdapterFamily::AlertWebhook,
            "webhook-s3",
            "https://hooks.fss.test/stress",
        )?,
    )?;

    let stop_feed = Arc::new(AtomicBool::new(false));
    let agent_count = 4_usize;
    let rounds_per_agent = 6_usize;

    let worker_results: Vec<WorkerOutcome> = std::thread::scope(
        |scope| -> TestResult<Vec<WorkerOutcome>> {
            // Motion feeder driving continuous 8-camera ingestion + corroboration during concurrent MCP reads.
            let feeder_stop = Arc::clone(&stop_feed);
            let controls = daemon.controls.clone();
            let feeder = scope.spawn(move || {
                let mut track_seq = 1_000_u64;
                while !feeder_stop.load(Ordering::Acquire) {
                    if let Ok(rect) = fss_reference::ingest::osd_mask::ImageRect::new(8, 8, 12, 12)
                    {
                        for idx in 1..=8_usize {
                            let key = format!("sensor:cam-{idx:02}");
                            if let Some(ctrl) = controls.get(&key) {
                                ctrl.inject_motion(rect, "person", 930_000, None, track_seq);
                                track_seq += 1;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(15));
                }
            });

            let mut handles = Vec::with_capacity(agent_count);
            for agent_idx in 0..agent_count {
                let root_ref = &deploy_root;
                let anchor_ref = &base_anchor;
                let import_ref = &import_hex;
                handles.push(scope.spawn(move || -> Result<WorkerOutcome, String> {
                let mut client = McpClient::spawn(
                    "scenario_3",
                    &format!("s3-agent-{agent_idx}"),
                    root_ref,
                    PRINCIPAL,
                    true,
                    STRESS_CAPS,
                )
                .map_err(|e| e.to_string())?;

                // Warm up binary & caches with 1 unmeasured orient before steady-state loop.
                let _ = client
                    .call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)
                    .map_err(|e| e.to_string())?;

                let mut total_rpcs = 0_usize;
                let mut orient_query_us = Vec::new();
                let mut h3_us = Vec::new();
                let mut locked_errors = 0_usize;
                let mut protocol_errors = 0_usize;

                let record_reply = |label: &str,
                                    r: &super::harness::ToolReply,
                                    rpcs: &mut usize,
                                    locked: &mut usize,
                                    proto: &mut usize| {
                    *rpcs += 1;
                    if r.raw_wire.contains("DeploymentLocked")
                        || r.body_text.contains("DeploymentLocked")
                    {
                        *locked += 1;
                    }
                    if r.is_error {
                        *proto += 1;
                        eprintln!("s3-agent-{agent_idx} error on {label}: {}", r.body_text);
                    }
                };

                for round in 0..rounds_per_agent {
                    // 1. session_orient (warm read)
                    let r_orient = client
                        .call("session_orient", r#"{"view":"brief","budget_tokens":1600}"#)
                        .map_err(|e| e.to_string())?;
                    record_reply(
                        "session_orient",
                        &r_orient,
                        &mut total_rpcs,
                        &mut locked_errors,
                        &mut protocol_errors,
                    );
                    orient_query_us.push(r_orient.latency_us);

                    // 2. query(cameras) over live UDS fss-ipc against 8-camera daemon!
                    let r_cams = client
                        .call("query", r#"{"target":"cameras"}"#)
                        .map_err(|e| e.to_string())?;
                    record_reply(
                        "query:cameras",
                        &r_cams,
                        &mut total_rpcs,
                        &mut locked_errors,
                        &mut protocol_errors,
                    );
                    orient_query_us.push(r_cams.latency_us);
                    if !bool_field(&r_cams.envelope, &["payload", "daemonLive"]).unwrap_or(false)
                        || array(&r_cams.envelope, &["payload", "cameras"])
                            .map(|c| c.len())
                            .unwrap_or(0)
                            != 8
                    {
                        protocol_errors += 1;
                    }

                    // 3. query(events)
                    let r_events = client
                        .call("query", r#"{"target":"events","max_entries":8}"#)
                        .map_err(|e| e.to_string())?;
                    record_reply(
                        "query:events",
                        &r_events,
                        &mut total_rpcs,
                        &mut locked_errors,
                        &mut protocol_errors,
                    );
                    orient_query_us.push(r_events.latency_us);

                    // 4. session_follow
                    let r_follow = client
                        .call(
                            "session_follow",
                            &object(&[
                                ("since", string(anchor_ref)),
                                ("view", string("brief")),
                                ("max_entries", "8".to_owned()),
                            ]),
                        )
                        .map_err(|e| e.to_string())?;
                    record_reply(
                        "session_follow",
                        &r_follow,
                        &mut total_rpcs,
                        &mut locked_errors,
                        &mut protocol_errors,
                    );
                    orient_query_us.push(r_follow.latency_us);

                    // 5. Periodic concurrent H3 redacted JPEG hydration (every 3rd round)
                    if round % 3 == 0 {
                        let r_h3 = client
                            .call(
                                "query",
                                &format!(
                                    r#"{{"target":"evidence-hydration","level":"H3","import_id":{},"segment_indices":[0],"max_h3_frames":1}}"#,
                                    quote(import_ref)
                                ),
                            )
                            .map_err(|e| e.to_string())?;
                        record_reply(
                            "query:h3",
                            &r_h3,
                            &mut total_rpcs,
                            &mut locked_errors,
                            &mut protocol_errors,
                        );
                        h3_us.push(r_h3.latency_us);
                        let blocks = r_h3.content_blocks().map_err(|e| e.to_string())?;
                        if blocks.len() != 2
                            || text(&blocks[1], &["mimeType"]).ok() != Some("image/jpeg")
                        {
                            protocol_errors += 1;
                        } else {
                            let bytes = decode_base64(
                                text(&blocks[1], &["data"]).map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                            let expected_sha = text(
                                &array(&r_h3.envelope, &["payload", "frames"])
                                    .map_err(|e| e.to_string())?[0],
                                &["receipt", "outputJpegSha256"],
                            )
                            .map_err(|e| e.to_string())?;
                            if ContentDigest::sha256(&bytes).to_text() != expected_sha {
                                protocol_errors += 1;
                            }
                        }
                    }
                }

                let (transcript, _, _) = client.finish().map_err(|e| e.to_string())?;
                Ok(WorkerOutcome {
                    total_rpcs,
                    orient_query_us,
                    h3_us,
                    locked_errors,
                    protocol_errors,
                    transcript,
                })
            }));
            }

            let mut results = Vec::with_capacity(agent_count);
            for h in handles {
                let res = h
                    .join()
                    .map_err(|_| "concurrent MCP worker thread panicked")?
                    .map_err(|e| format!("concurrent MCP worker failed: {e}"))?;
                results.push(res);
            }
            stop_feed.store(true, Ordering::Release);
            let _ = feeder.join();
            Ok(results)
        },
    )?;

    // Clean graceful shutdown of live 8-camera fss-daemon!
    let (shutdown, telemetry_lines) = daemon.stop_gracefully()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    assert!(
        !fss_ipc::default_socket_path(&deploy_root).exists(),
        "daemon.sock must be removed on graceful shutdown"
    );

    // Reopen v2 Merkle epoch ledger strictly rejecting incomplete tails!
    let reopened = MerkleEpochLedger::open(
        ws.v2_root.join("ledger"),
        SITE_ID,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(reopened.commit_sequence(), shutdown.head_commit_sequence);
    let _ = reopened.verify_full_chain()?;

    let mut total_rpcs = 0_usize;
    let mut all_orient_query_us = Vec::new();
    let mut all_h3_us = Vec::new();
    let mut locked_errors = 0_usize;
    let mut protocol_errors = 0_usize;
    let mut all_tx = Vec::new();
    for w in worker_results {
        total_rpcs += w.total_rpcs;
        all_orient_query_us.extend(w.orient_query_us);
        all_h3_us.extend(w.h3_us);
        locked_errors += w.locked_errors;
        protocol_errors += w.protocol_errors;
        all_tx.extend(w.transcript);
    }

    assert_eq!(locked_errors, 0, "expected 0 DeploymentLocked errors");
    assert_eq!(
        protocol_errors, 0,
        "expected 0 corrupt reads or JSON-RPC protocol errors"
    );
    let orient_query_stats = LatencyStats::from_micros(&all_orient_query_us);
    let h3_stats = LatencyStats::from_micros(&all_h3_us);
    assert!(
        orient_query_stats.p99_ms < 15.0,
        "concurrent 4-agent orient/query p99 latency {:.3}ms >= 15.0ms budget",
        orient_query_stats.p99_ms
    );

    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("webhook-hmac-canary", CANARY_WEBHOOK_HMAC)?;
    scanner.register_bytes("camera-rtsp-canary", CANARY_CAM_RTSP_PASS)?;
    scanner.register_bytes("unifi-api-canary", CANARY_UNIFI_API_KEY)?;
    for (idx, e) in all_tx.iter().enumerate() {
        scanner.assert_clean(&format!("s3_resp_{idx}"), e.response_json.as_bytes())?;
    }
    for (idx, line) in telemetry_lines.iter().enumerate() {
        scanner.assert_clean(&format!("s3_telemetry_{idx}"), line.as_bytes())?;
    }

    Ok(Scenario3Report {
        camera_count: 8,
        agent_count,
        total_rpcs,
        orient_query_latency: orient_query_stats,
        h3_hydration_latency: h3_stats,
        deployment_locked_errors: locked_errors,
        corrupt_or_protocol_errors: protocol_errors,
        daemon_active_tasks_after_stop: shutdown.active_tasks,
        daemon_leaked_obligations_after_stop: shutdown.leaked_obligations,
        daemon_verified_batches: shutdown.verified_batches,
        canary_leaks: 0,
        transcript: all_tx,
    })
}
