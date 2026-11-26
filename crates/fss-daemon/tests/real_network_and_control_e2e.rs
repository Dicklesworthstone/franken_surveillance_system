#![forbid(unsafe_code)]
//! Real-network, IPC control-op, and v2 doctor/orient interoperability E2E tests for `fss-daemon`.
//!
//! Verifies:
//! 1. `NetworkAdapterDriver(OnvifHttp)` against a real loopback HTTP/1.1 multipart MJPEG server
//!    serving pure-Rust encoded JPEG frames: single persistent connection, real decoded RGB pixels
//!    (never gray placeholders), exact SHA-256 `source_digest`, HTTP 401 -> `AuthFailure`, and
//!    honest fail-closed refusal on unsupported direct network adapters (`Tutk`, `UniFiProtect`).
//! 2. Real IPC bounded control commands (`SnapshotCamera`, `ReloadManifest`, `ProbeDetect`) over
//!    Unix domain socket `fss-ipc`, verifying real disk manifest reload + delta publication.
//! 3. Native v2 daemon root interoperability with `fss_reference::doctor::inspect_deployment`
//!    (`format_version == 2`, `Healthy`) and `fss_reference::agent_orient::{read_deployment,
//!    orient_deployment}` BOTH while the daemon is live-locked AND after graceful shutdown.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_core::{AgentView, CanonicalDecode, ContentDigest, PrincipalId, SensorId};
use fss_daemon::{
    CameraAdapterKind, CameraManifestEntry, DaemonRuntimeDescriptor, DaemonStartConfig,
    DaemonSupervisor, NetworkAdapterDriver, PerceptionConfig, PerceptionEngine,
    SensorDisconnectReason, SensorDriver, SensorDriverEvent, SiteManifest, SyntheticCameraControl,
    SyntheticCameraDriver, control_op_approval_digest,
};
use fss_fusion::ScoreCalibration;
use fss_ipc::{
    BoundedControlOp, DeltaEventSummary, DeltaSubscriptionItem, IpcClient, IpcClientConfig,
    IpcResponse,
};
use fss_pack::PACK_FOOTER_END_MAGIC;
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use fss_reference::doctor::{DoctorVerdict, inspect_deployment};
use fss_reference::ingest::model_pool::{CameraPriorityTier, FramePixelInput};
use fss_reference::ingest::osd_mask::ImageRect;
use fss_vault::SecretBytes;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let short: String = label.chars().take(8).collect();
        let dir = PathBuf::from("/tmp").join(format!("fssr-{short}-{}-{n}", std::process::id()));
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

fn encode_test_jpeg_rgb(
    width: u32,
    height: u32,
    r_base: u8,
    g_base: u8,
    b_base: u8,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    for y in 0..height {
        for x in 0..width {
            let r = r_base.wrapping_add(((x * 7) % 64) as u8);
            let g = g_base.wrapping_add(((y * 5) % 64) as u8);
            let b = b_base.wrapping_add((((x + y) * 3) % 64) as u8);
            rgb.push(r);
            rgb.push(g);
            rgb.push(b);
        }
    }
    let sha = ContentDigest::sha256(&rgb).bytes();
    let cfg = EncodeConfig {
        quality: 85,
        format: PixelFormat::Rgb,
    };
    let limits = EncodeLimits::default();
    let mut budget = EncodeBudget::new(10_000_000);
    let encoded = encode_jpeg(width, height, &rgb, sha, cfg, &limits, &mut budget)?;
    Ok(encoded.into_bytes())
}

fn make_calibrated_person_table() -> Result<ScoreCalibration, Box<dyn std::error::Error>> {
    Ok(ScoreCalibration::from_counts(
        "cal:live-person:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?)
}

fn two_cam_manifest_json(root: &Path, osd_rect: &str) -> String {
    let root_str = root.to_string_lossy().replace('\\', "\\\\");
    format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-v2-interop",
  "deployment_root": "{root_str}",
  "ring_cap_bytes": 67108864,
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [
    {{
      "sensor_id": "sensor:cam-a",
      "adapter": "synthetic",
      "endpoint": "synthetic://cam-a",
      "priority_tier": "high_consequence_zone",
      "zone_id": "entry",
      "dimensions": [32, 32],
      "osd_ignore_rects": ["{osd_rect}"],
      "failure_domains": ["poe:switch-a", "power:ups-a"],
      "reconnect_min_ms": 200,
      "reconnect_max_ms": 2000,
      "stall_timeout_ms": 5000,
      "ring_max_frames": 64,
      "ring_max_bytes": 32768,
      "gop_frames": 4
    }},
    {{
      "sensor_id": "sensor:cam-b",
      "adapter": "synthetic",
      "endpoint": "synthetic://cam-b",
      "priority_tier": "active_investigation",
      "zone_id": "entry",
      "dimensions": [32, 32],
      "osd_ignore_rects": ["{osd_rect}"],
      "failure_domains": ["wifi:ap-b", "power:ups-b"],
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
        "zone_id": "entry",
        "cameras": ["sensor:cam-a", "sensor:cam-b"],
        "max_separation_ns": 5000000000
      }}
    ]
  }}
}}"#
    )
}

#[test]
fn real_http_mjpeg_driver_decodes_real_pixels_and_refuses_401() -> TestResult {
    let jpeg1 = encode_test_jpeg_rgb(32, 32, 20, 40, 60)?;
    let jpeg2 = encode_test_jpeg_rgb(32, 32, 180, 120, 50)?;
    let digest1 = ContentDigest::sha256(&jpeg1);
    let digest2 = ContentDigest::sha256(&jpeg2);
    assert_ne!(digest1, digest2);

    // 1. Real loopback HTTP/1.1 multipart MJPEG server.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let conn_count = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let conn_bg = Arc::clone(&conn_count);
    let stop_bg = Arc::clone(&stop);
    let j1_bg = jpeg1.clone();
    let j2_bg = jpeg2.clone();
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            conn_bg.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut req_buf = [0_u8; 1024];
            let _ = stream.read(&mut req_buf);
            let header = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n";
            let _ = stream.write_all(header);
            for jpg in [&j1_bg, &j2_bg] {
                let part = format!(
                    "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                    jpg.len()
                );
                let _ = stream.write_all(part.as_bytes());
                let _ = stream.write_all(jpg);
                let _ = stream.write_all(b"\r\n");
                let _ = stream.flush();
                thread::sleep(Duration::from_millis(20));
            }
            while !stop_bg.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(10));
            }
        }
    });

    let mut cam = CameraManifestEntry {
        sensor_id: SensorId::parse("sensor:mjpeg-real-1")?,
        adapter: CameraAdapterKind::OnvifHttp,
        endpoint: format!("http://{addr}/mjpeg"),
        secret_id: None,
        priority_tier: CameraPriorityTier::Standard,
        primary_zone: "porch".to_owned(),
        zones: BTreeSet::from(["porch".to_owned()]),
        dimensions: [32, 32],
        osd_ignore_rects: Vec::new(),
        failure_domains: BTreeSet::from(["lan:eth0".to_owned()]),
        reconnect_min_ms: 200,
        reconnect_max_ms: 2000,
        stall_timeout_ms: 5000,
        ring_max_frames: 16,
        ring_max_bytes: 128 * 1024,
        retain_hot_ns: None,
        max_sensor_bytes: None,
        gop_frames: 4,
        auth_realm: None,
        allow_inband_sps_pps: false,
        setup_companion_tracks: false,
    };

    let mut drv = NetworkAdapterDriver::new(&cam);
    drv.connect(1)
        .map_err(|r| format!("connect failed: {r:?}"))?;
    assert_eq!(drv.active_session_count(), 1);
    assert_eq!(drv.total_connections(), 1);

    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut ts = 1_700_000_000_000_000_000_i128;
    while received.len() < 2 && Instant::now() < deadline {
        ts += 33_000_000;
        match drv.poll_frame(ts) {
            SensorDriverEvent::Frame(frame) => received.push(frame),
            SensorDriverEvent::Idle => thread::sleep(Duration::from_millis(10)),
            SensorDriverEvent::Disconnected(reason) => {
                return Err(format!("unexpected disconnect: {reason:?}").into());
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    drv.disconnect();
    let _ = server.join();

    assert_eq!(received.len(), 2, "expected 2 real decoded MJPEG frames");
    assert_eq!(
        conn_count.load(Ordering::SeqCst),
        1,
        "must hold 1 persistent TCP session"
    );
    assert_eq!(received[0].source_digest, digest1);
    assert_eq!(received[1].source_digest, digest2);
    assert_eq!(received[0].dimensions, [32, 32]);
    assert_eq!(received[1].dimensions, [32, 32]);
    // Verify real decoded RGB pixel variance (never constant gray placeholder).
    match (&received[0].pixels, &received[1].pixels) {
        (FramePixelInput::Rgb { pixels: p1 }, FramePixelInput::Rgb { pixels: p2 }) => {
            assert_eq!(p1.len(), 32 * 32 * 3);
            assert_eq!(p2.len(), 32 * 32 * 3);
            assert_ne!(p1, p2, "distinct JPEGs must decode to distinct RGB buffers");
            assert!(
                p1.iter().any(|&b| b != p1[0]),
                "decoded frame must not be a flat gray placeholder"
            );
        }
        other => return Err(format!("expected FramePixelInput::Rgb, got {other:?}").into()),
    }

    // 2. Real HTTP 401 Unauthorized must fail closed with SensorDisconnectReason::AuthFailure.
    let auth_listener = TcpListener::bind("127.0.0.1:0")?;
    let auth_addr = auth_listener.local_addr()?;
    let auth_srv = thread::spawn(move || {
        if let Ok((mut s, _)) = auth_listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0_u8; 512];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"cam\"\r\nContent-Length: 0\r\n\r\n",
            );
            let _ = s.flush();
        }
    });
    cam.endpoint = format!("http://{auth_addr}/mjpeg");
    let mut auth_drv = NetworkAdapterDriver::new(&cam);
    auth_drv
        .connect(1)
        .map_err(|r| format!("auth connect failed: {r:?}"))?;
    let mut auth_reason = None;
    let auth_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < auth_deadline {
        match auth_drv.poll_frame(1_700_000_001_000_000_000) {
            SensorDriverEvent::Disconnected(reason) => {
                auth_reason = Some(reason);
                break;
            }
            SensorDriverEvent::Idle => thread::sleep(Duration::from_millis(10)),
            SensorDriverEvent::Frame(_) => {
                return Err("HTTP 401 endpoint must never emit a frame".into());
            }
        }
    }
    let _ = auth_srv.join();
    assert!(
        matches!(auth_reason, Some(SensorDisconnectReason::AuthFailure)),
        "expected AuthFailure on HTTP 401, got {auth_reason:?}"
    );

    // 3. Direct Tutk / UniFiProtect adapters must fail closed honestly (never fabricate blank frames).
    for adapter in [CameraAdapterKind::Tutk, CameraAdapterKind::UniFiProtect] {
        let mut entry = cam.clone();
        entry.adapter = adapter;
        entry.endpoint = "tutk://127.0.0.1:32100".to_owned();
        let mut d = NetworkAdapterDriver::new(&entry);
        let res = d.connect(1);
        assert!(
            matches!(res, Err(SensorDisconnectReason::DriverError(_))),
            "adapter {adapter:?} must fail closed honestly instead of synthesizing blank frames, got {res:?}"
        );
    }

    Ok(())
}

#[test]
fn ipc_snapshot_reload_manifest_and_probe_detect_execute_real_operations() -> TestResult {
    let dir = TempDirGuard::new("ipc-ctrl")?;
    let manifest_path = dir.path().join("site.json");
    let initial_json = two_cam_manifest_json(dir.path(), "0,0,8,4");
    fs::write(&manifest_path, &initial_json)?;
    let manifest = SiteManifest::parse_json(&initial_json)?;

    let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
    let mut controls = BTreeMap::new();
    for cam in &manifest.cameras {
        let ctrl = SyntheticCameraControl::new(cam.sensor_id.clone());
        let drv: Box<dyn SensorDriver> =
            Box::new(SyntheticCameraDriver::new(cam, Arc::clone(&ctrl)));
        drivers.insert(cam.sensor_id.clone(), drv);
        controls.insert(cam.sensor_id.as_str().to_owned(), ctrl);
    }

    let t0: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.manifest_path = Some(manifest_path.clone());
    cfg.custom_drivers = drivers;
    cfg.perception_config = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };
    cfg.started_at_ns = t0;
    cfg.enable_ipc = true;

    let mut sup = DaemonSupervisor::start(cfg)?;
    let _ = sup.step_tick(t0 + 100_000_000)?;
    let _ = sup.step_tick(t0 + 200_000_000)?;

    let head_before = sup.storage().head_snapshot()?.commit_sequence;
    let desc = DaemonRuntimeDescriptor::read_from_root(dir.path())?;
    let root_bg = dir.path().to_path_buf();
    let desc_bg = desc.clone();

    // Update site.json on disk with an expanded OSD ignore rectangle BEFORE ReloadManifest.
    let updated_json = two_cam_manifest_json(dir.path(), "0,0,16,8");
    fs::write(&manifest_path, &updated_json)?;

    let sub_handle = thread::spawn(move || -> Result<Vec<String>, String> {
        let mut client = IpcClient::connect(IpcClientConfig {
            deployment_root: root_bg,
            deployment_id: desc_bg.site_id,
            contract_basis_digest: desc_bg.contract_basis_digest,
            principal: PrincipalId::parse("principal:local-operator").map_err(|e| e.to_string())?,
            capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
            io_timeout: Duration::from_secs(3),
        })
        .map_err(|e| e.to_string())?;
        let req = client.next_request_id();
        let sub = client
            .subscribe_deltas(req, head_before, 8)
            .map_err(|e| e.to_string())?;
        let mut notes = Vec::new();
        for item in sub {
            if let DeltaSubscriptionItem::Event {
                summary_canonical, ..
            } = item.map_err(|e| e.to_string())?
                && let Ok(summary) = DeltaEventSummary::from_canonical_bytes(&summary_canonical)
            {
                notes.push(summary.summary);
                if notes.iter().any(|n| n.starts_with("camera_snapshot"))
                    && notes.iter().any(|n| n.starts_with("manifest_reloaded"))
                    && notes
                        .iter()
                        .any(|n| n.starts_with("probe_detect_completed"))
                {
                    break;
                }
            }
        }
        Ok(notes)
    });

    thread::sleep(Duration::from_millis(40));

    let mut ctrl_client = IpcClient::connect(IpcClientConfig {
        deployment_root: dir.path().to_path_buf(),
        deployment_id: desc.site_id.clone(),
        contract_basis_digest: desc.contract_basis_digest,
        principal: PrincipalId::parse("principal:local-operator")?,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?;

    // 1. Submit SnapshotCamera
    let snap_approval = control_op_approval_digest(
        &desc.site_id,
        BoundedControlOp::SnapshotCamera,
        Some("sensor:cam-a"),
    );
    let r1 = ctrl_client.next_request_id();
    assert!(matches!(
        ctrl_client.submit_bounded_control(
            r1,
            BoundedControlOp::SnapshotCamera,
            Some("sensor:cam-a".to_owned()),
            snap_approval,
        )?,
        IpcResponse::ControlAccepted { .. }
    ));

    // 2. Submit ReloadManifest
    let reload_approval =
        control_op_approval_digest(&desc.site_id, BoundedControlOp::ReloadManifest, None);
    let r2 = ctrl_client.next_request_id();
    assert!(matches!(
        ctrl_client.submit_bounded_control(
            r2,
            BoundedControlOp::ReloadManifest,
            None,
            reload_approval,
        )?,
        IpcResponse::ControlAccepted { .. }
    ));

    // 3. Submit ProbeDetect
    let probe_approval = control_op_approval_digest(
        &desc.site_id,
        BoundedControlOp::ProbeDetect,
        Some("sensor:cam-a"),
    );
    let r3 = ctrl_client.next_request_id();
    assert!(matches!(
        ctrl_client.submit_bounded_control(
            r3,
            BoundedControlOp::ProbeDetect,
            Some("sensor:cam-a".to_owned()),
            probe_approval,
        )?,
        IpcResponse::ControlAccepted { .. }
    ));
    drop(ctrl_client);

    // Step supervisor tick to process all 3 control ops!
    let _ = sup.step_tick(t0 + 300_000_000)?;

    let notes = sub_handle.join().map_err(|_| "sub thread panicked")??;
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("camera_snapshot sensor=sensor:cam-a")),
        "missing real camera_snapshot delta: {notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("manifest_reloaded site=site-v2-interop")),
        "missing real manifest_reloaded delta: {notes:?}"
    );
    assert!(
        notes.iter().any(
            |n| n.starts_with("probe_detect_completed target=sensor:cam-a")
                && n.contains("ran_ml=1")
        ),
        "ProbeDetect must force Stage-2 ML inference (ran_ml=1) even on static frames: {notes:?}"
    );
    assert_eq!(
        sup.perception().pool_metrics().loads,
        1,
        "ProbeDetect must reuse the pinned ResidentModelPool with zero extra weight loads"
    );

    let shutdown = sup.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    Ok(())
}

#[test]
fn daemon_v2_root_passes_fss_doctor_and_fss_orient_live_and_stopped() -> TestResult {
    let dir = TempDirGuard::new("v2-docor")?;
    let manifest = SiteManifest::parse_json(&two_cam_manifest_json(dir.path(), "0,0,8,4"))?;

    let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
    let mut controls = BTreeMap::new();
    for cam in &manifest.cameras {
        let ctrl = SyntheticCameraControl::new(cam.sensor_id.clone());
        let drv: Box<dyn SensorDriver> =
            Box::new(SyntheticCameraDriver::new(cam, Arc::clone(&ctrl)));
        drivers.insert(cam.sensor_id.clone(), drv);
        controls.insert(cam.sensor_id.as_str().to_owned(), ctrl);
    }

    let t0: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.perception_config = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };
    cfg.started_at_ns = t0;
    cfg.enable_ipc = false;

    let mut sup = DaemonSupervisor::start(cfg)?;
    let _ = sup.step_tick(t0 + 100_000_000)?;
    let _ = sup.step_tick(t0 + 200_000_000)?;

    // Trigger a corroborated multi-camera event across independent failure domains.
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    controls
        .get("sensor:cam-a")
        .ok_or("missing cam-a")?
        .inject_motion(motion_rect, "person", 930_000, None, 101);
    controls
        .get("sensor:cam-b")
        .ok_or("missing cam-b")?
        .inject_motion(motion_rect, "person", 940_000, None, 102);
    let tick = sup.step_tick(t0 + 300_000_000)?;
    assert!(tick.corroborated_events >= 1, "expected corroborated event");

    // 1. LIVE-LOCKED verification: daemon still holds <root>/LOCK!
    assert!(dir.path().join("LAYOUT").is_file(), "v2 LAYOUT missing");
    assert!(
        dir.path().join("projections").join("mvcc").is_dir(),
        "canonical projections/mvcc dir missing"
    );
    let live_doc = inspect_deployment(dir.path());
    assert_eq!(
        live_doc.verdict,
        DoctorVerdict::Healthy,
        "live v2 doctor must be Healthy (lock-free): {}",
        live_doc.to_json()
    );
    assert!(
        live_doc.to_json().contains("\"format_version\":2"),
        "doctor JSON must report v2 layout: {}",
        live_doc.to_json()
    );
    let live_doc_json = live_doc.to_json();
    assert!(
        live_doc_json.contains("\"wal_present\":true")
            && live_doc_json.contains("\"wal_batch_frames\":")
            && live_doc_json.contains("\"projected_commit_sequence\":"),
        "live v2 doctor must inspect mvcc.wal and report projected_commit_sequence: {live_doc_json}"
    );

    let live_snap = read_deployment(dir.path(), &OrientLimits::default())?;
    assert!(live_snap.anchor.commit_sequence > 0);
    assert!(
        !live_snap.events.is_empty(),
        "v2 orient snapshot must decode daemon FSPP EventRevision records"
    );
    let live_orient = orient_deployment(
        &live_snap,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse("principal:test-agent")?,
            budget_tokens: None,
        },
        &OrientLimits::default(),
    )?;
    live_orient.capsule().validate()?;
    assert_eq!(live_orient.capsule().anchor, live_snap.anchor);

    // 2. STOPPED verification after graceful shutdown.
    let shutdown = sup.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);

    let stopped_doc = inspect_deployment(dir.path());
    assert_eq!(
        stopped_doc.verdict,
        DoctorVerdict::Healthy,
        "stopped v2 doctor must be Healthy: {}",
        stopped_doc.to_json()
    );
    let stopped_snap = read_deployment(dir.path(), &OrientLimits::default())?;
    assert_eq!(
        stopped_snap.anchor.commit_sequence,
        shutdown.head_commit_sequence
    );
    assert!(!stopped_snap.events.is_empty());
    let stopped_orient = orient_deployment(
        &stopped_snap,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse("principal:test-agent")?,
            budget_tokens: None,
        },
        &OrientLimits::default(),
    )?;
    stopped_orient.capsule().validate()?;

    // 3. Symlinked `.fssp` entry inside objects/packs must trigger AttentionRequired + symlink_pack_entry.
    #[cfg(unix)]
    {
        let bogus_target = dir.path().join("outside-pack-target.bin");
        fs::write(&bogus_target, b"not-a-real-pack")?;
        let sym_pack = dir
            .path()
            .join("objects")
            .join("packs")
            .join("pack-00000000-000000000099.fssp");
        std::os::unix::fs::symlink(&bogus_target, &sym_pack)?;
        let sym_doc = inspect_deployment(dir.path());
        assert_eq!(
            sym_doc.verdict,
            DoctorVerdict::AttentionRequired,
            "symlinked pack entry must trigger AttentionRequired: {}",
            sym_doc.to_json()
        );
        assert!(
            sym_doc.to_json().contains("symlink_pack_entry"),
            "doctor JSON must report symlink_pack_entry: {}",
            sym_doc.to_json()
        );
        let _ = fs::remove_file(&sym_pack);
        let _ = fs::remove_file(&bogus_target);

        // 4. Symlinked mvcc.snap inside projections/mvcc must trigger AttentionRequired + projection_symlink_entry.
        let proj_dir = dir.path().join("projections").join("mvcc");
        let snap_path = proj_dir.join("mvcc.snap");
        let snap_backup = proj_dir.join("mvcc.snap.bak");
        let had_snap = snap_path.exists();
        if had_snap {
            fs::rename(&snap_path, &snap_backup)?;
        }
        let dummy_snap_target = dir.path().join("outside-snap.bin");
        fs::write(&dummy_snap_target, b"dummy")?;
        std::os::unix::fs::symlink(&dummy_snap_target, &snap_path)?;
        let sym_proj_doc = inspect_deployment(dir.path());
        assert_eq!(
            sym_proj_doc.verdict,
            DoctorVerdict::AttentionRequired,
            "symlinked mvcc.snap must trigger AttentionRequired: {}",
            sym_proj_doc.to_json()
        );
        assert!(
            sym_proj_doc.to_json().contains("projection_symlink_entry"),
            "doctor JSON must report projection_symlink_entry: {}",
            sym_proj_doc.to_json()
        );
        let _ = fs::remove_file(&snap_path);
        let _ = fs::remove_file(&dummy_snap_target);
        if had_snap {
            fs::rename(&snap_backup, &snap_path)?;
        }
    }

    // 5. Sealed `.fssp` pack with unrecognized filename stem must trigger AttentionRequired.
    let bad_name_pack = dir
        .path()
        .join("objects")
        .join("packs")
        .join("bogus-unparseable.fssp");
    let mut bad_pack_bytes = vec![0_u8; 16];
    bad_pack_bytes.extend_from_slice(&PACK_FOOTER_END_MAGIC);
    fs::write(&bad_name_pack, &bad_pack_bytes)?;
    let bad_name_doc = inspect_deployment(dir.path());
    assert_eq!(
        bad_name_doc.verdict,
        DoctorVerdict::AttentionRequired,
        "unrecognized sealed pack filename must trigger AttentionRequired: {}",
        bad_name_doc.to_json()
    );
    assert!(
        bad_name_doc
            .to_json()
            .contains("unrecognized_pack_filename"),
        "doctor JSON must report unrecognized_pack_filename: {}",
        bad_name_doc.to_json()
    );
    let _ = fs::remove_file(&bad_name_pack);

    Ok(())
}

#[test]
fn site_manifest_parses_rtsp_realm_and_rejects_invalid_realm_or_symlink_file() -> TestResult {
    let dir = TempDirGuard::new("man-rlm")?;
    let root_str = dir.path().to_string_lossy().replace('\\', "\\\\");
    let valid_json = format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-rtsp-realm",
  "deployment_root": "{root_str}",
  "cameras": [
    {{
      "sensor_id": "sensor:wyze-39",
      "adapter": "rtsp",
      "endpoint": "rtsp://127.0.0.1:8554/stream1",
      "auth_realm": "smolrtsp",
      "allow_inband_sps_pps": true,
      "setup_companion_tracks": true,
      "zone_id": "front"
    }}
  ]
}}"#
    );
    let m = SiteManifest::parse_json(&valid_json)?;
    assert_eq!(m.cameras[0].auth_realm.as_deref(), Some("smolrtsp"));
    assert!(m.cameras[0].allow_inband_sps_pps);
    assert!(m.cameras[0].setup_companion_tracks);

    let default_json = format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-rtsp-realm",
  "deployment_root": "{root_str}",
  "cameras": [
    {{
      "sensor_id": "sensor:wyze-39",
      "adapter": "rtsp",
      "endpoint": "rtsp://127.0.0.1:8554/stream1",
      "zone_id": "front"
    }}
  ]
}}"#
    );
    let m_default = SiteManifest::parse_json(&default_json)?;
    assert_ne!(
        m.digest(),
        m_default.digest(),
        "manifest digest must commit to auth_realm / inband / companion track options"
    );

    let bad_realm = valid_json.replace("\"smolrtsp\"", "\"bad\\\"realm\"");
    assert!(
        SiteManifest::parse_json(&bad_realm).is_err(),
        "auth_realm containing quotes must be rejected"
    );

    #[cfg(unix)]
    {
        let real_file = dir.path().join("real-site.json");
        let link_file = dir.path().join("link-site.json");
        fs::write(&real_file, &valid_json)?;
        std::os::unix::fs::symlink(&real_file, &link_file)?;
        assert!(
            SiteManifest::from_file(&link_file).is_err(),
            "SiteManifest::from_file must reject symlink manifest paths"
        );
    }

    // Orphan detector_package_digest override without detector_package_path must fail closed.
    let bad_cfg = PerceptionConfig {
        detector_package_digest: Some(ContentDigest::sha256(b"orphan-digest")),
        ..PerceptionConfig::default()
    };
    assert!(
        PerceptionEngine::new(&m, bad_cfg).is_err(),
        "orphan detector_package_digest without detector_package_path must be rejected"
    );

    // Non-UTF-8 vault password must fail closed with AuthFailure (never send unauthenticated HTTP).
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let mut cam = m.cameras[0].clone();
    cam.adapter = CameraAdapterKind::OnvifHttp;
    cam.endpoint = format!("http://{addr}/mjpeg");
    let mut bad_drv = NetworkAdapterDriver::new(&cam)
        .with_vault_credentials("admin", SecretBytes::new(vec![0xFF, 0xFE, 0xFD])?);
    assert_eq!(
        bad_drv.connect(1),
        Err(SensorDisconnectReason::AuthFailure),
        "non-UTF-8 vault password must fail closed with AuthFailure"
    );

    // Hot-reloading transport fields updates endpoint and disconnects active sessions cleanly.
    let mut ok_drv = NetworkAdapterDriver::new(&cam);
    ok_drv.connect(1).map_err(|e| format!("{e:?}"))?;
    assert_eq!(ok_drv.active_session_count(), 1);
    let mut updated_cam = cam;
    updated_cam.endpoint = format!("http://{addr}/mjpeg-v2");
    ok_drv.update_manifest_entry(&updated_cam);
    assert_eq!(ok_drv.endpoint(), updated_cam.endpoint);
    assert_eq!(
        ok_drv.active_session_count(),
        0,
        "changing endpoint on hot-reload must disconnect stale active session"
    );
    drop(listener);
    Ok(())
}
