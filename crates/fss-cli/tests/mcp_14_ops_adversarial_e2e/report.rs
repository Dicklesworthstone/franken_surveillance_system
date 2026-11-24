#![forbid(unsafe_code)]
//! Manual structured JSON report and sanitized JSONL transcript writer for
//! `target/test-logs/mcp-14-ops/mcp_14_ops_e2e_report.json` and `mcp_14_ops_transcript.jsonl`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use fss_cli::agent_json::{array, object, string};
use fss_vault::CanaryLeakScanner;

use super::TestResult;
use super::fixtures::{CANARY_CAM_RTSP_PASS, CANARY_UNIFI_API_KEY, CANARY_WEBHOOK_HMAC};
use super::harness::{LatencyStats, TranscriptEntry};

#[derive(Clone, Debug)]
pub struct Scenario1Report {
    pub tools_verified: Vec<String>,
    pub per_tool_latency: BTreeMap<String, LatencyStats>,
    pub per_tool_tokens: BTreeMap<String, u64>,
    pub warm_orient_latency: LatencyStats,
    pub tls13_signature_verified: bool,
    pub tls13_idempotency_key: String,
    pub indeterminate_reconciled: bool,
    pub live_daemon_active_tasks: usize,
    pub live_daemon_leaked_obligations: usize,
    pub canary_surfaces_scanned: usize,
    pub canary_bytes_scanned: usize,
    pub canary_leaks: usize,
    pub transcript: Vec<TranscriptEntry>,
}

#[derive(Clone, Debug)]
pub struct RedactedPixelProof {
    pub dimensions: [u32; 2],
    pub mask_rect: [u32; 4],
    pub masked_pixels_checked: usize,
    pub masked_max_r: u8,
    pub masked_max_g: u8,
    pub masked_max_b: u8,
    pub masked_max_luma: u8,
    pub masked_sentinel_leaks: usize,
    pub unmasked_pixels_checked: usize,
    pub unmasked_mean_green: u32,
    pub crop_masked_pixels_checked: usize,
    pub crop_max_luma: u8,
}

#[derive(Clone, Debug)]
pub struct Scenario2Report {
    pub checks: BTreeMap<String, bool>,
    pub pixel_proof: RedactedPixelProof,
    pub canary_surfaces_scanned: usize,
    pub canary_bytes_scanned: usize,
    pub canary_leaks: usize,
    pub transcript: Vec<TranscriptEntry>,
}

#[derive(Clone, Debug)]
pub struct Scenario3Report {
    pub camera_count: usize,
    pub agent_count: usize,
    pub total_rpcs: usize,
    pub orient_query_latency: LatencyStats,
    pub h3_hydration_latency: LatencyStats,
    pub deployment_locked_errors: usize,
    pub corrupt_or_protocol_errors: usize,
    pub daemon_active_tasks_after_stop: usize,
    pub daemon_leaked_obligations_after_stop: usize,
    pub daemon_verified_batches: u64,
    pub canary_leaks: usize,
    pub transcript: Vec<TranscriptEntry>,
}

#[derive(Default)]
struct CombinedState {
    s1: Option<Scenario1Report>,
    s2: Option<Scenario2Report>,
    s3: Option<Scenario3Report>,
}

static STATE: Mutex<CombinedState> = Mutex::new(CombinedState {
    s1: None,
    s2: None,
    s3: None,
});

fn report_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/test-logs/mcp-14-ops")
}

fn format_f64(val: f64) -> String {
    format!("{val:.3}")
}

fn latency_json(stats: &LatencyStats) -> String {
    object(&[
        ("count", stats.count.to_string()),
        ("p50Ms", format_f64(stats.p50_ms)),
        ("p95Ms", format_f64(stats.p95_ms)),
        ("p99Ms", format_f64(stats.p99_ms)),
        ("maxMs", format_f64(stats.max_ms)),
    ])
}

fn transcript_line(entry: &TranscriptEntry) -> String {
    // Keep transcript compact and secret-free (truncate huge base64 JPEG echoes only in JSONL preview).
    let resp_preview = if entry.response_json.len() > 2048 {
        format!(
            "{}...[redacted_large_payload_len={}]",
            &entry.response_json[..512],
            entry.response_json.len()
        )
    } else {
        entry.response_json.clone()
    };
    object(&[
        ("scenario", string(&entry.scenario)),
        ("client", string(&entry.client)),
        (
            "rpcId",
            entry
                .rpc_id
                .map_or_else(|| "null".to_owned(), |id| id.to_string()),
        ),
        ("method", string(&entry.method)),
        (
            "tool",
            entry
                .tool
                .as_deref()
                .map_or_else(|| "null".to_owned(), string),
        ),
        ("latencyUs", entry.latency_us.to_string()),
        ("isError", entry.is_error.to_string()),
        ("requestBytes", entry.request_json.len().to_string()),
        ("responseBytes", entry.response_json.len().to_string()),
        ("requestPreview", string(&entry.request_json)),
        ("responsePreview", string(&resp_preview)),
    ])
}

fn flush_artifacts(state: &CombinedState) -> TestResult {
    let dir = report_dir();
    fs::create_dir_all(&dir)?;

    let mut all_transcript = Vec::new();
    let mut total_canary_leaks = 0_usize;

    let s1_json = if let Some(s1) = &state.s1 {
        total_canary_leaks += s1.canary_leaks;
        all_transcript.extend(s1.transcript.iter().cloned());
        let lat_entries: Vec<(String, String)> = s1
            .per_tool_latency
            .iter()
            .map(|(k, v)| (k.clone(), latency_json(v)))
            .collect();
        let lat_refs: Vec<(&str, String)> = lat_entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let tok_entries: Vec<(String, String)> = s1
            .per_tool_tokens
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let tok_refs: Vec<(&str, String)> = tok_entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let tools_arr: Vec<String> = s1.tools_verified.iter().map(|t| string(t)).collect();
        object(&[
            ("status", string("PASS")),
            ("toolsVerifiedCount", s1.tools_verified.len().to_string()),
            ("toolsVerified", array(&tools_arr)),
            ("warmOrientLatency", latency_json(&s1.warm_orient_latency)),
            ("perToolLatency", object(&lat_refs)),
            ("perToolTokenEstimates", object(&tok_refs)),
            (
                "tls13WebhookSignatureVerified",
                s1.tls13_signature_verified.to_string(),
            ),
            ("tls13IdempotencyKey", string(&s1.tls13_idempotency_key)),
            (
                "indeterminateEffectReconciled",
                s1.indeterminate_reconciled.to_string(),
            ),
            (
                "daemonActiveTasksAfterStop",
                s1.live_daemon_active_tasks.to_string(),
            ),
            (
                "daemonLeakedObligationsAfterStop",
                s1.live_daemon_leaked_obligations.to_string(),
            ),
            (
                "canarySurfacesScanned",
                s1.canary_surfaces_scanned.to_string(),
            ),
            ("canaryBytesScanned", s1.canary_bytes_scanned.to_string()),
            ("canaryLeaks", s1.canary_leaks.to_string()),
        ])
    } else {
        "null".to_owned()
    };

    let s2_json = if let Some(s2) = &state.s2 {
        total_canary_leaks += s2.canary_leaks;
        all_transcript.extend(s2.transcript.iter().cloned());
        let check_entries: Vec<(String, String)> = s2
            .checks
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();
        let check_refs: Vec<(&str, String)> = check_entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let p = &s2.pixel_proof;
        let pixel_json = object(&[
            (
                "dimensions",
                format!("[{},{}]", p.dimensions[0], p.dimensions[1]),
            ),
            (
                "maskRect",
                format!(
                    "[{},{},{},{}]",
                    p.mask_rect[0], p.mask_rect[1], p.mask_rect[2], p.mask_rect[3]
                ),
            ),
            ("maskedPixelsChecked", p.masked_pixels_checked.to_string()),
            (
                "maskedMaxRgb",
                format!("[{},{},{}]", p.masked_max_r, p.masked_max_g, p.masked_max_b),
            ),
            ("maskedMaxLuma", p.masked_max_luma.to_string()),
            ("maskedSentinelLeaks", p.masked_sentinel_leaks.to_string()),
            (
                "unmaskedPixelsChecked",
                p.unmasked_pixels_checked.to_string(),
            ),
            ("unmaskedMeanGreen", p.unmasked_mean_green.to_string()),
            (
                "cropMaskedPixelsChecked",
                p.crop_masked_pixels_checked.to_string(),
            ),
            ("cropMaxLuma", p.crop_max_luma.to_string()),
        ]);
        object(&[
            ("status", string("PASS")),
            ("adversarialChecksMatrix", object(&check_refs)),
            ("redactedPixelProof", pixel_json),
            (
                "canarySurfacesScanned",
                s2.canary_surfaces_scanned.to_string(),
            ),
            ("canaryBytesScanned", s2.canary_bytes_scanned.to_string()),
            ("canaryLeaks", s2.canary_leaks.to_string()),
        ])
    } else {
        "null".to_owned()
    };

    let s3_json = if let Some(s3) = &state.s3 {
        total_canary_leaks += s3.canary_leaks;
        all_transcript.extend(s3.transcript.iter().cloned());
        object(&[
            ("status", string("PASS")),
            ("cameraCount", s3.camera_count.to_string()),
            ("concurrentAgents", s3.agent_count.to_string()),
            ("totalRpcs", s3.total_rpcs.to_string()),
            ("orientQueryLatency", latency_json(&s3.orient_query_latency)),
            ("h3HydrationLatency", latency_json(&s3.h3_hydration_latency)),
            (
                "deploymentLockedErrors",
                s3.deployment_locked_errors.to_string(),
            ),
            (
                "corruptOrProtocolErrors",
                s3.corrupt_or_protocol_errors.to_string(),
            ),
            (
                "daemonActiveTasksAfterStop",
                s3.daemon_active_tasks_after_stop.to_string(),
            ),
            (
                "daemonLeakedObligationsAfterStop",
                s3.daemon_leaked_obligations_after_stop.to_string(),
            ),
            (
                "daemonVerifiedBatches",
                s3.daemon_verified_batches.to_string(),
            ),
            ("canaryLeaks", s3.canary_leaks.to_string()),
        ])
    } else {
        "null".to_owned()
    };

    let report_json = object(&[
        ("schema", string("fss.mcp_14_ops_e2e_report.v1")),
        ("bead", string("fss-x4a.31.4.5")),
        ("canaryLeaks", total_canary_leaks.to_string()),
        ("transcriptEntries", all_transcript.len().to_string()),
        ("scenario1Lifecycle", s1_json),
        ("scenario2Adversarial", s2_json),
        ("scenario3Concurrency", s3_json),
        ("verdict", string("PASS")),
    ]);

    let mut transcript_body = String::new();
    for entry in &all_transcript {
        transcript_body.push_str(&transcript_line(entry));
        transcript_body.push('\n');
    }

    // Final canary sweep on the serialized proof artifacts themselves!
    let mut scanner = CanaryLeakScanner::new();
    scanner.register_bytes("webhook-hmac-canary", CANARY_WEBHOOK_HMAC)?;
    scanner.register_bytes("camera-rtsp-canary", CANARY_CAM_RTSP_PASS)?;
    scanner.register_bytes("unifi-api-canary", CANARY_UNIFI_API_KEY)?;
    scanner.assert_clean("mcp_14_ops_e2e_report.json", report_json.as_bytes())?;
    scanner.assert_clean("mcp_14_ops_transcript.jsonl", transcript_body.as_bytes())?;

    let report_path = dir.join("mcp_14_ops_e2e_report.json");
    let report_tmp = dir.join(format!("mcp_14_ops_e2e_report.tmp.{}", std::process::id()));
    fs::write(&report_tmp, format!("{report_json}\n"))?;
    fs::rename(&report_tmp, &report_path)?;

    let tx_path = dir.join("mcp_14_ops_transcript.jsonl");
    let tx_tmp = dir.join(format!("mcp_14_ops_transcript.tmp.{}", std::process::id()));
    fs::write(&tx_tmp, transcript_body)?;
    fs::rename(&tx_tmp, &tx_path)?;
    Ok(())
}

pub fn record_scenario_1(report: Scenario1Report) -> TestResult {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    guard.s1 = Some(report);
    flush_artifacts(&guard)
}

pub fn record_scenario_2(report: Scenario2Report) -> TestResult {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    guard.s2 = Some(report);
    flush_artifacts(&guard)
}

pub fn record_scenario_3(report: Scenario3Report) -> TestResult {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    guard.s3 = Some(report);
    flush_artifacts(&guard)
}
