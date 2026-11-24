#![forbid(unsafe_code)]
//! Contract integration tests for `fss-dashboard --live` (bead `fss-x4a.31.5.5`):
//! 1. Live `SubscribeDeltas` connection to a running multi-camera `fss-daemon` receives live
//!    deltas in `< 500 ms`, renders all 6 cockpit panes accurately, and never mutates the root.
//! 2. Headless `--live --tui` rendering and stopped-daemon MVCC fallback (`daemon_live == false`)
//!    leave deployment bytes 100% unmodified.
//! 3. Live loopback HTTP `/api/live` JSON endpoint and `/api/live/stream` SSE push deliver valid
//!    `fss.dashboard_live_frame.v1` updates within `< 500 ms` of new daemon deltas.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::SensorId;
use fss_daemon::{
    DaemonStartConfig, DaemonSupervisor, PerceptionConfig, SensorDriver, SiteManifest,
    SyntheticCameraControl, SyntheticCameraDriver,
};
use fss_fusion::ScoreCalibration;
use fss_reference::ingest::osd_mask::ImageRect;

type TestResult = Result<(), Box<dyn Error>>;
type DriverMap = BTreeMap<SensorId, Box<dyn SensorDriver>>;
type ControlMap = BTreeMap<String, Arc<SyntheticCameraControl>>;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let short: String = label.chars().take(8).collect();
        // Keep path well below macOS SUN_LEN (104 bytes) for `<root>/run/daemon.sock`.
        let dir = PathBuf::from("/tmp").join(format!("fssd-{short}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                result.insert(path.strip_prefix(root)?.to_owned(), Vec::new());
                visit(root, &path, result)?;
            } else {
                result.insert(path.strip_prefix(root)?.to_owned(), fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

fn make_calibrated_person_table() -> Result<ScoreCalibration, Box<dyn Error>> {
    Ok(ScoreCalibration::from_counts(
        "cal:live-dashboard:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?)
}

fn three_camera_manifest_json(root: &Path, site_id: &str) -> String {
    let root_str = root.to_string_lossy().replace('\\', "\\\\");
    format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "{site_id}",
  "deployment_root": "{root_str}",
  "ring_cap_bytes": 67108864,
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [
    {{
      "sensor_id": "sensor:wyze-39",
      "adapter": "synthetic",
      "endpoint": "synthetic://wyze-39",
      "secret_id": "secret:wyze:39",
      "priority_tier": "standard",
      "zone_id": "driveway",
      "dimensions": [32, 32],
      "osd_ignore_rects": ["0,0,8,4"],
      "failure_domains": ["wifi:home-2g", "power:circuit-a"],
      "reconnect_min_ms": 200,
      "reconnect_max_ms": 2000,
      "stall_timeout_ms": 5000,
      "ring_max_frames": 64,
      "ring_max_bytes": 32768,
      "gop_frames": 4
    }},
    {{
      "sensor_id": "sensor:wyze-51",
      "adapter": "synthetic",
      "endpoint": "synthetic://wyze-51",
      "secret_id": "secret:wyze:51",
      "priority_tier": "high_consequence_zone",
      "zone_id": "driveway",
      "dimensions": [32, 32],
      "osd_ignore_rects": ["0,0,8,4"],
      "failure_domains": ["wifi:home-2g", "power:circuit-b"],
      "reconnect_min_ms": 200,
      "reconnect_max_ms": 2000,
      "stall_timeout_ms": 5000,
      "ring_max_frames": 64,
      "ring_max_bytes": 32768,
      "gop_frames": 4
    }},
    {{
      "sensor_id": "sensor:unifi-g4-177",
      "adapter": "synthetic",
      "endpoint": "synthetic://unifi-g4-177",
      "secret_id": "secret:unifi:177",
      "priority_tier": "active_investigation",
      "zone_id": "driveway",
      "dimensions": [32, 32],
      "osd_ignore_rects": ["0,0,8,4"],
      "failure_domains": ["poe:switch-1", "power:ups-rack"],
      "reconnect_min_ms": 200,
      "reconnect_max_ms": 2000,
      "stall_timeout_ms": 5000,
      "ring_max_frames": 64,
      "ring_max_bytes": 32768,
      "gop_frames": 4
    }}
  ],
  "topology": {{
    "shared_zones": [
      {{
        "zone_id": "driveway",
        "cameras": ["sensor:wyze-39", "sensor:wyze-51", "sensor:unifi-g4-177"],
        "max_separation_ns": 5000000000
      }}
    ]
  }}
}}"#
    )
}

fn wire_synthetic_drivers(manifest: &SiteManifest) -> (DriverMap, ControlMap) {
    let mut drivers = BTreeMap::new();
    let mut controls = BTreeMap::new();
    for cam in &manifest.cameras {
        let ctrl = SyntheticCameraControl::new(cam.sensor_id.clone());
        let drv: Box<dyn SensorDriver> =
            Box::new(SyntheticCameraDriver::new(cam, Arc::clone(&ctrl)));
        drivers.insert(cam.sensor_id.clone(), drv);
        controls.insert(cam.sensor_id.as_str().to_owned(), ctrl);
    }
    (drivers, controls)
}

fn start_test_daemon(
    root: &Path,
    site_id: &str,
    t_base: i128,
) -> Result<(DaemonSupervisor, ControlMap), Box<dyn Error>> {
    let manifest = SiteManifest::parse_json(&three_camera_manifest_json(root, site_id))?;
    let (drivers, controls) = wire_synthetic_drivers(&manifest);
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.perception_config = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };
    cfg.started_at_ns = t_base;
    cfg.enable_ipc = true;
    let mut sup = DaemonSupervisor::start(cfg)?;
    let _ = sup.step_tick(t_base + 100_000_000)?;
    let _ = sup.step_tick(t_base + 200_000_000)?;
    Ok((sup, controls))
}

fn obj_field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    v.object()
        .and_then(|m| m.get(key))
        .ok_or_else(|| format!("missing JSON field `{key}`").into())
}

#[test]
fn live_cockpit_subscribes_to_daemon_sub_500ms_and_renders_all_six_panes() -> TestResult {
    let dir = TempDirGuard::new("live-ipc")?;
    let site = "site-live-ipc";
    let t_base: i128 = 1_700_000_000_000_000_000;
    let (mut sup, controls) = start_test_daemon(dir.path(), site, t_base)?;

    let ctrl_39 = controls.get("sensor:wyze-39").ok_or("missing wyze-39")?;
    let ctrl_51 = controls.get("sensor:wyze-51").ok_or("missing wyze-51")?;
    let ctrl_177 = controls
        .get("sensor:unifi-g4-177")
        .ok_or("missing unifi-g4-177")?;
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;

    let child = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--live", "--root"])
        .arg(dir.path())
        .args([
            "--site",
            site,
            "--allow-local-metadata",
            "yes",
            "--once-events",
            "2",
            "--json",
            "--serve-seconds",
            "10",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait deterministically for fss-dashboard to complete UDS handshake and attach SubscribeDeltas.
    let probe_principal = fss_core::PrincipalId::parse("principal:local-operator")?;
    let ready_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < ready_deadline {
        if let Ok((_, st)) =
            fss_daemon::query_live_daemon_status(dir.path(), Some(site), probe_principal.clone())
            && st.active_connections >= 2
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(25));

    // Delta 1: Shared-WiFi pair -> SharedFailureDomainHeld.
    ctrl_39.inject_motion(motion_rect, "person", 920_000, None, 101);
    ctrl_51.inject_motion(motion_rect, "person", 920_000, None, 102);
    let _ = sup.step_tick(t_base + 400_000_000)?;

    // Advance past sliding window and emit Delta 2: Independent clusters -> Corroborated.
    let t_indep = t_base + 12_000_000_000;
    let _ = sup.step_tick(t_indep)?;
    let emit_started = Instant::now();
    ctrl_51.inject_motion(motion_rect, "person", 930_000, None, 201);
    ctrl_177.inject_motion(motion_rect, "person", 940_000, None, 202);
    let _ = sup.step_tick(t_indep + 100_000_000)?;

    let output = child.wait_with_output()?;
    let wall_after_emit_ms = emit_started.elapsed().as_millis();
    assert!(
        output.status.success(),
        "fss-dashboard --live failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wall_after_emit_ms < 500,
        "live delta delivery + frame render took {wall_after_emit_ms} ms (>= 500 ms)"
    );
    println!("[METRICS] live_uds_delta_wall_ms={wall_after_emit_ms}");

    let body = String::from_utf8(output.stdout)?;
    let frame = parse(&body)?;
    assert_eq!(
        obj_field(&frame, "schema")?.text(),
        Some("fss.dashboard_live_frame.v1")
    );
    assert_eq!(obj_field(&frame, "site")?.text(), Some(site));
    assert_eq!(as_bool(obj_field(&frame, "read_only")?), Some(true));
    assert_eq!(as_bool(obj_field(&frame, "daemon_live")?), Some(true));
    assert_eq!(
        obj_field(&frame, "connection_mode")?.text(),
        Some("live_daemon_ipc")
    );

    let deltas_rx = obj_field(&frame, "deltas_received")?
        .integer()
        .ok_or("deltas_received")?;
    assert!(deltas_rx >= 2, "expected >= 2 live deltas, got {deltas_rx}");
    let max_lat = obj_field(&frame, "max_delta_latency_ms")?
        .integer()
        .ok_or("max_delta_latency_ms")?;
    assert!(max_lat < 500, "max_delta_latency_ms={max_lat} >= 500 ms");

    // Pane 1: Camera Mesh Health
    let cameras = obj_field(&frame, "cameras")?
        .array()
        .ok_or("cameras array")?;
    assert_eq!(cameras.len(), 3);
    for cam in cameras {
        assert_eq!(as_bool(obj_field(cam, "running")?), Some(true));
        assert_eq!(obj_field(cam, "coverage_status")?.text(), Some("covered"));
    }

    // Pane 2: Active Situation & Attention Frontier
    let sit = obj_field(&frame, "situation")?;
    assert!(
        obj_field(sit, "anchor_commit_sequence")?
            .integer()
            .unwrap_or(0)
            > 0
    );
    let affordances = obj_field(sit, "affordances")?
        .array()
        .ok_or("affordances")?;
    assert!(
        affordances
            .iter()
            .any(|a| obj_field(a, "affordance_id").ok().and_then(Value::text)
                == Some("affordance:orient:plan")),
        "expected affordance:orient:plan in dynamic frontier: {body}"
    );

    // Pane 3: Corroborated Events & Milliban Fusion Scores
    let events = obj_field(&frame, "events")?.array().ok_or("events")?;
    assert!(!events.is_empty(), "expected live events in frame");
    let has_corr = events.iter().any(|e| {
        obj_field(e, "epistemic_classification")
            .ok()
            .and_then(Value::text)
            == Some("Corroborated")
            && obj_field(e, "failure_domain_clusters")
                .ok()
                .and_then(Value::integer)
                .unwrap_or(0)
                >= 2
    });
    assert!(
        has_corr,
        "expected Corroborated multi-cluster event in Pane 3: {body}"
    );
    for ev in events {
        let handle = obj_field(ev, "privacy_masked_handle")?;
        assert_eq!(
            as_bool(obj_field(handle, "raw_media_exposed")?),
            Some(false)
        );
    }

    // Pane 4: Obligations, Effects & Holds
    let ob = obj_field(&frame, "obligations_and_holds")?;
    assert!(obj_field(ob, "open_obligations")?.integer().is_some());
    assert!(obj_field(ob, "active_holds")?.integer().is_some());

    // Pane 5: Storage Ring & Compaction Telemetry
    let ring = obj_field(&frame, "storage_ring")?;
    assert!(obj_field(ring, "pack_count")?.integer().unwrap_or(0) >= 1);
    assert!(obj_field(ring, "ring_cap_bytes")?.integer().unwrap_or(0) > 0);
    assert_eq!(
        obj_field(ring, "resource_pressure")?.text(),
        Some("Nominal")
    );

    // Pane 6: Agent Activity Log & Preview->Approve Workflows
    let log = obj_field(&frame, "agent_log")?;
    assert_eq!(as_bool(obj_field(log, "read_only")?), Some(true));
    assert!(
        obj_field(log, "recent_deltas")?
            .array()
            .map_or(0, <[Value]>::len)
            >= 2
    );
    let workflows = obj_field(log, "operator_workflows")?
        .array()
        .ok_or("workflows")?;
    assert_eq!(workflows.len(), 3);
    for wf in workflows {
        assert_eq!(
            as_bool(obj_field(wf, "requires_approval_digest")?),
            Some(true)
        );
    }

    let shutdown = sup.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    Ok(())
}

#[test]
fn live_cockpit_headless_tui_and_stopped_daemon_mvcc_fallback_are_readonly() -> TestResult {
    let dir = TempDirGuard::new("live-off")?;
    let site = "site-live-offline";
    let t_base: i128 = 1_700_000_000_000_000_000;
    let (mut sup, controls) = start_test_daemon(dir.path(), site, t_base)?;

    let ctrl_51 = controls.get("sensor:wyze-51").ok_or("missing wyze-51")?;
    let ctrl_177 = controls
        .get("sensor:unifi-g4-177")
        .ok_or("missing unifi-g4-177")?;
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    ctrl_51.inject_motion(motion_rect, "person", 930_000, None, 301);
    ctrl_177.inject_motion(motion_rect, "person", 940_000, None, 302);
    let _ = sup.step_tick(t_base + 400_000_000)?;
    let report = sup.shutdown_graceful()?;
    assert_eq!(report.active_tasks, 0);

    let before = inventory(dir.path())?;

    // 1. Offline MVCC JSON fallback (`daemon_live == false`).
    let json_out = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--live", "--root"])
        .arg(dir.path())
        .args([
            "--site",
            site,
            "--allow-local-metadata",
            "yes",
            "--once-events",
            "2",
            "--json",
        ])
        .output()?;
    assert!(
        json_out.status.success(),
        "offline fallback json failed: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let parsed = parse(&String::from_utf8(json_out.stdout)?)?;
    assert_eq!(
        obj_field(&parsed, "schema")?.text(),
        Some("fss.dashboard_live_frame.v1")
    );
    assert_eq!(as_bool(obj_field(&parsed, "daemon_live")?), Some(false));
    assert_eq!(
        obj_field(&parsed, "connection_mode")?.text(),
        Some("offline_mvcc_readonly")
    );
    assert_eq!(as_bool(obj_field(&parsed, "read_only")?), Some(true));
    assert!(
        obj_field(&parsed, "events")?
            .array()
            .map_or(0, <[Value]>::len)
            >= 1
    );

    // 2. Headless `--live --tui` 6-pane terminal cockpit snapshot.
    let tui_out = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--live", "--root"])
        .arg(dir.path())
        .args(["--site", site, "--allow-local-metadata", "yes", "--tui"])
        .output()?;
    assert!(
        tui_out.status.success(),
        "tui snapshot failed: {}",
        String::from_utf8_lossy(&tui_out.stderr)
    );
    let tui_text = String::from_utf8(tui_out.stdout)?;
    for needle in [
        "OFFLINE MVCC FALLBACK",
        "daemon_live=false",
        "[1] CAMERA MESH HEALTH",
        "[2] ACTIVE SITUATION & ATTENTION FRONTIER",
        "[3] CORROBORATED EVENTS & MILLIBAN FUSION",
        "[4] ACTIVE OBLIGATIONS, EFFECTS & LEGAL HOLDS",
        "[5] STORAGE RING CAPACITY & COMPACTION TELEMETRY",
        "[6] AGENT ACTIVITY LOG",
        "preview -> approval_digest -> approve",
    ] {
        assert!(
            tui_text.contains(needle),
            "missing `{needle}` in TUI:\n{tui_text}"
        );
    }

    // 3. Deployment root MUST remain 100% byte-for-byte unmodified (strictly read-only).
    assert_eq!(
        inventory(dir.path())?,
        before,
        "fss-dashboard --live mutated deployment bytes!"
    );
    Ok(())
}

#[test]
fn live_cockpit_http_api_live_and_sse_stream_push_updates() -> TestResult {
    let dir = TempDirGuard::new("live-http")?;
    let site = "site-live-http";
    let t_base: i128 = 1_700_000_000_000_000_000;
    let (mut sup, controls) = start_test_daemon(dir.path(), site, t_base)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--live", "--root"])
        .arg(dir.path())
        .args([
            "--site",
            site,
            "--allow-local-metadata",
            "yes",
            "--port",
            "0",
            "--serve-seconds",
            "6",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr = child.stderr.take().ok_or("missing stderr")?;
    let mut reader = BufReader::new(stderr);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;
    let host = first_line
        .trim()
        .strip_prefix("FSS Observatory Live Cockpit: http://")
        .ok_or_else(|| format!("unexpected startup line: {first_line}"))?
        .to_owned();

    // 1. Verify GET /api/live returns valid fss.dashboard_live_frame.v1 JSON.
    let mut stream = TcpStream::connect(&host)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    write!(stream, "GET /api/live HTTP/1.1\r\nHost: {host}\r\n\r\n")?;
    stream.flush()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    assert!(
        head.starts_with("HTTP/1.1 200 OK"),
        "unexpected head: {head}"
    );
    assert!(
        head.contains("application/json"),
        "missing json mime: {head}"
    );
    let parsed = parse(body)?;
    assert_eq!(
        obj_field(&parsed, "schema")?.text(),
        Some("fss.dashboard_live_frame.v1")
    );
    assert_eq!(as_bool(obj_field(&parsed, "daemon_live")?), Some(true));
    assert_eq!(as_bool(obj_field(&parsed, "read_only")?), Some(true));

    // 2. Verify POST /api/live is refused (read-only HTTP boundary).
    let mut post_stream = TcpStream::connect(&host)?;
    post_stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        post_stream,
        "POST /api/live HTTP/1.1\r\nHost: {host}\r\n\r\n"
    )?;
    let mut post_resp = String::new();
    post_stream.read_to_string(&mut post_resp)?;
    assert!(
        post_resp.starts_with("HTTP/1.1 405"),
        "expected 405: {post_resp}"
    );

    // 3. Verify GET /api/live/stream (SSE) pushes initial frame and live delta update < 500 ms.
    let mut sse = TcpStream::connect(&host)?;
    sse.set_read_timeout(Some(Duration::from_secs(3)))?;
    write!(sse, "GET /api/live/stream HTTP/1.1\r\nHost: {host}\r\n\r\n")?;
    sse.flush()?;
    let mut sse_reader = BufReader::new(sse);
    let mut status_line = String::new();
    sse_reader.read_line(&mut status_line)?;
    assert!(
        status_line.starts_with("HTTP/1.1 200 OK"),
        "sse status: {status_line}"
    );
    let mut sse_headers = String::new();
    loop {
        let mut line = String::new();
        sse_reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        sse_headers.push_str(&line);
    }
    assert!(
        sse_headers.contains("text/event-stream"),
        "missing SSE mime: {sse_headers}"
    );

    let read_sse_event = |r: &mut BufReader<TcpStream>| -> Result<String, Box<dyn Error>> {
        let mut data_line = None;
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line)?;
            if n == 0 {
                return Err("SSE stream closed early".into());
            }
            if let Some(d) = line.strip_prefix("data: ") {
                data_line = Some(d.trim().to_owned());
            } else if (line == "\n" || line == "\r\n")
                && let Some(payload) = data_line.take()
            {
                return Ok(payload);
            }
        }
    };

    let first_sse = read_sse_event(&mut sse_reader)?;
    let first_val = parse(&first_sse)?;
    assert_eq!(
        obj_field(&first_val, "schema")?.text(),
        Some("fss.dashboard_live_frame.v1")
    );

    // Trigger a live corroborated event and measure SSE push latency (< 500 ms).
    let ctrl_51 = controls.get("sensor:wyze-51").ok_or("missing wyze-51")?;
    let ctrl_177 = controls
        .get("sensor:unifi-g4-177")
        .ok_or("missing unifi-g4-177")?;
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    let push_started = Instant::now();
    ctrl_51.inject_motion(motion_rect, "person", 935_000, None, 401);
    ctrl_177.inject_motion(motion_rect, "person", 945_000, None, 402);
    let _ = sup.step_tick(t_base + 500_000_000)?;

    let second_sse = read_sse_event(&mut sse_reader)?;
    let sse_push_ms = push_started.elapsed().as_millis();
    assert!(
        sse_push_ms < 500,
        "SSE push latency after delta commit was {sse_push_ms} ms (>= 500 ms)"
    );
    println!("[METRICS] live_http_sse_push_ms={sse_push_ms}");
    let second_val = parse(&second_sse)?;
    assert!(
        obj_field(&second_val, "deltas_received")?
            .integer()
            .unwrap_or(0)
            >= 1,
        "expected updated deltas_received in SSE push: {second_sse}"
    );

    drop(sse_reader);
    let _ = child.kill();
    let _ = child.wait();
    let report = sup.shutdown_graceful()?;
    assert_eq!(report.active_tasks, 0);
    Ok(())
}

#[test]
fn offline_mvcc_readonly_loader_replays_post_checkpoint_wal_batches() -> TestResult {
    let dir = TempDirGuard::new("wal-rply")?;
    let site = "site-wal-replay";
    let t_base: i128 = 1_700_000_000_000_000_000;

    // 1. First supervisor run: commit initial batches and gracefully shut down so `mvcc.snap`
    //    is checkpointed at `snap_seq > 0`.
    let (mut sup1, controls1) = start_test_daemon(dir.path(), site, t_base)?;
    let ctrl_51 = controls1.get("sensor:wyze-51").ok_or("missing wyze-51")?;
    let ctrl_177 = controls1
        .get("sensor:unifi-g4-177")
        .ok_or("missing unifi-g4-177")?;
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    ctrl_51.inject_motion(motion_rect, "person", 930_000, None, 501);
    ctrl_177.inject_motion(motion_rect, "person", 940_000, None, 502);
    let _ = sup1.step_tick(t_base + 400_000_000)?;
    let shutdown1 = sup1.shutdown_graceful()?;
    let snap_seq = shutdown1.head_commit_sequence;
    assert!(snap_seq > 0, "expected non-zero checkpoint commit_sequence");
    assert!(
        dir.path()
            .join("projections")
            .join("mvcc")
            .join("mvcc.snap")
            .is_file(),
        "expected mvcc.snap after shutdown"
    );

    // 2. Second supervisor run with IPC disabled: append additional batches into `mvcc.wal`
    //    WITHOUT checkpointing `mvcc.snap`, so `mvcc.snap` stays at `snap_seq` while `mvcc.wal`
    //    advances strictly ahead to `head_after > snap_seq`.
    let manifest = SiteManifest::parse_json(&three_camera_manifest_json(dir.path(), site))?;
    let (drivers, _controls2) = wire_synthetic_drivers(&manifest);
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.perception_config = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };
    cfg.started_at_ns = t_base + 20_000_000_000;
    cfg.enable_ipc = false;

    let mut sup2 = DaemonSupervisor::start(cfg)?;
    let _ = sup2.step_tick(t_base + 20_100_000_000)?;
    let _ = sup2.step_tick(t_base + 20_200_000_000)?;
    let _ = sup2.step_tick(t_base + 20_300_000_000)?;
    let _ = sup2.step_tick(t_base + 20_400_000_000)?;
    let head_after = sup2.storage().head_snapshot()?.commit_sequence;
    assert!(
        head_after > snap_seq,
        "expected post-checkpoint WAL batches ({head_after} > {snap_seq})"
    );

    // 3. Run `fss-dashboard --live --json` offline (no daemon.sock -> MVCC read-only fallback)
    //    and verify it observes ALL post-checkpoint WAL commits (`head_after`), not stale `snap_seq`!
    let before = inventory(dir.path())?;
    let json_out = Command::new(env!("CARGO_BIN_EXE_fss-dashboard"))
        .args(["--live", "--root"])
        .arg(dir.path())
        .args([
            "--site",
            site,
            "--allow-local-metadata",
            "yes",
            "--once-events",
            "2",
            "--json",
        ])
        .output()?;
    assert!(
        json_out.status.success(),
        "fss-dashboard failed: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let parsed = parse(&String::from_utf8(json_out.stdout)?)?;
    assert_eq!(
        obj_field(&parsed, "connection_mode")?.text(),
        Some("offline_mvcc_readonly")
    );
    let sit = obj_field(&parsed, "situation")?;
    let observed_seq = obj_field(sit, "anchor_commit_sequence")?
        .integer()
        .ok_or("anchor_commit_sequence")?;
    assert_eq!(
        observed_seq,
        i128::from(head_after),
        "offline read-only loader MUST replay post-checkpoint WAL batches onto mvcc.snap"
    );
    assert_eq!(
        inventory(dir.path())?,
        before,
        "read-only replay must never mutate deployment root"
    );

    let shutdown2 = sup2.shutdown_graceful()?;
    assert_eq!(shutdown2.active_tasks, 0);
    assert_eq!(shutdown2.leaked_obligations, 0);
    Ok(())
}
