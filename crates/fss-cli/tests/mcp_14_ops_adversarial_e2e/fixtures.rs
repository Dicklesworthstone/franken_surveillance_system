#![forbid(unsafe_code)]
//! Real deployment fixtures, live multi-camera `DaemonSupervisor` wrapper, synthetic MJPEG scenes
//! (including bright magenta privacy-mask sentinels), and `fss-vault` canary secret rig.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, PrincipalId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_daemon::{
    DaemonShutdownReport, DaemonStartConfig, DaemonSupervisor, PerceptionConfig, SensorDriver,
    SiteManifest, SyntheticCameraControl, SyntheticCameraDriver, query_live_daemon_status,
    request_live_daemon_stop,
};
use fss_fusion::ScoreCalibration;
use fss_pack::RetentionCandidate;
use fss_reference::ingest::file_adapter::{CaptureHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::osd_mask::ImageRect;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::media_fixture::jpeg::{
    JpegConfig, Subsampling, encode_jpeg as encode_gray_jpeg,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};
use fss_vault::{
    CAP_SECRET_READ_001, CAP_SECRET_WRITE_001, CanaryLeakScanner, KdfParams, LabEntropy,
    LocalEncryptedVault, SecretAccessCx, SecretBytes, SecretId, SecretScope, SecretStore,
};

use super::TestResult;

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

pub const SITE_ID: &str = "site:mcp14-e2e";
pub const PRINCIPAL: &str = "principal:mcp14-owner";
pub const MIRROR_HOMOGRAPHY: &str = "-1,0,96,0,1,0,0,0,1";

pub const CANARY_WEBHOOK_HMAC: &[u8] = b"CANARY-FSS-HMAC-9f8e7d6c5b4a3210-DO-NOT-LEAK!";
pub const CANARY_CAM_RTSP_PASS: &[u8] = b"CANARY-CAM-RTSP-7a6b5c4d3e2f1098-DO-NOT-LEAK!";
pub const CANARY_UNIFI_API_KEY: &[u8] = b"CANARY-UNIFI-KEY-0192837465abcdef-DO-NOT-LEAK!";

/// Short `/tmp/fss-m14-*` directory keeping `<root>/run/daemon.sock` well under macOS `SUN_LEN`.
pub struct TempWorkspace {
    pub base: PathBuf,
    pub deploy_root: PathBuf,
    pub v2_root: PathBuf,
    pub vault_dir: PathBuf,
}

impl TempWorkspace {
    pub fn new(tag: &str) -> TestResult<Self> {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let short: String = tag.chars().take(6).collect();
        let base =
            PathBuf::from("/tmp").join(format!("fss14-{short}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base)?;
        let deploy_root = base.join("dep");
        let v2_root = base.join("v2");
        let vault_dir = base.join("vault");
        fs::create_dir_all(&v2_root)?;
        fs::create_dir_all(&vault_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            base,
            deploy_root,
            v2_root,
            vault_dir,
        })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

pub fn wall_now_ns() -> TestResult<i128> {
    Ok(i128::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

pub fn make_write_cx(root: &Path, site_id: &str) -> TestResult<(ContextAuthority, ReplayCx)> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:mcp14-fixture".to_owned(),
        operation_id: OperationId::parse("operation:mcp14-fixture")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(100_000)
            .build()?,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:current-deletion-restrictions".to_owned(),
        anchor_universe: ContentDigest::sha256(site_id.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?);
    Ok((authority, cx))
}

pub fn init_empty_deployment(ws: &TempWorkspace) -> TestResult<PathBuf> {
    let (_, cx) = make_write_cx(&ws.deploy_root, SITE_ID)?;
    drop(ReferenceDeployment::open(&ws.deploy_root, SITE_ID, &cx)?);
    cx.drain_and_finalize();
    Ok(ws.deploy_root.canonicalize()?)
}

fn assert_bin_ok(output: &Output, label: &str) -> TestResult {
    if !output.status.success() {
        return Err(format!(
            "{label} failed ({:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing `{key}` in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Encodes a 96x48 grayscale MJPEG stream with a moving target for 2-camera corroboration.
fn encode_corroboration_mjpeg(rightward: bool) -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let cfg = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..8_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let offset = 16 + (index - 3) * 8;
            let left = if rightward { offset } else { 80 - offset };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_gray_jpeg(width, height, &pixels, &cfg)?);
    }
    Ok(stream)
}

/// Encodes an RGB 128x96 frame with bright magenta `(255, 0, 255)` sentinel inside
/// `[16, 16, 48, 32]` (MCU-aligned!) and green scene `(60, 210, 70)` + moving white target
/// `(245, 240, 235)` outside the mask rectangle.
pub fn encode_sentinel_rgb_frame(frame_idx: u32) -> TestResult<Vec<u8>> {
    let (w, h) = (128_u32, 96_u32);
    let mut rgb = vec![0_u8; (w as usize) * (h as usize) * 3];
    for y in 0..h {
        for x in 0..w {
            let idx = ((y as usize) * (w as usize) + (x as usize)) * 3;
            let px = if (16..64).contains(&x) && (16..48).contains(&y) {
                [255_u8, 0, 255]
            } else if frame_idx >= 3 {
                let bx = 76 + (frame_idx - 3) * 2;
                if x >= bx && x < bx + 24 && (56..80).contains(&y) {
                    [245, 240, 235]
                } else {
                    [60, 210, 70]
                }
            } else {
                [60, 210, 70]
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
            quality: 75,
            format: PixelFormat::Rgb,
        },
        &limits,
        &mut budget,
    )?
    .into_bytes())
}

pub fn import_corroboration_pair(ws: &TempWorkspace) -> TestResult<(String, String)> {
    let now = u128::try_from(wall_now_ns()?)?;
    let capture_start = now.saturating_sub(10_000_000_000);
    let mut ids = Vec::new();
    for (label, sensor, rightward) in [
        ("east", "sensor:east", true),
        ("west", "sensor:west", false),
    ] {
        let input = ws.base.join(format!("{label}.mjpeg"));
        fs::write(&input, encode_corroboration_mjpeg(rightward)?)?;
        let out = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(&ws.deploy_root)
            .args(["--site", SITE_ID, "--input"])
            .arg(&input)
            .args(["--sensor", sensor, "--stream", &format!("stream:{label}")])
            .args([
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                &now.to_string(),
                "--capture-start-ns",
                &capture_start.to_string(),
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                "10",
            ])
            .output()?;
        assert_bin_ok(&out, "fss-file import")?;
        let import_id = String::from_utf8(out.stdout)?
            .lines()
            .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
            .ok_or("missing import_identity from fss-file")?;
        ids.push(format!("{label}:{import_id}"));
    }
    Ok((ids[0].clone(), ids[1].clone()))
}

pub fn publish_corroborated_event(
    root: &Path,
    east_arg: &str,
    west_arg: &str,
    zone_spec: &str,
) -> TestResult<String> {
    let west_ground = format!("west:{MIRROR_HOMOGRAPHY}");
    let run = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "corroborate",
            "--root",
            root.to_str().ok_or("utf8 root")?,
            "--site",
            SITE_ID,
            "--camera",
            east_arg,
            "--camera",
            west_arg,
            "--ground",
            "east:1,0,0,0,1,0,0,0,1",
            "--ground",
            &west_ground,
            "--zone",
            zone_spec,
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        args.extend_from_slice(extra);
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(args)
            .output()?)
    };
    let prepared = run(&[])?;
    assert_bin_ok(&prepared, "fss-event corroborate preview")?;
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = run(&["--approve", &proposal])?;
    assert_bin_ok(&published, "fss-event corroborate publish")?;
    report_field(&published, "event_id")
}

/// Imports an RGB 128x96 sentinel MJPEG recording and publishes a real single-camera watch event
/// with track provenance (for H2/H3 hydration and uncorroborated alert refusal tests).
pub fn import_sentinel_and_watch_event(
    ws: &TempWorkspace,
    sensor_name: &str,
    frame_count: u32,
) -> TestResult<(ContentDigest, String)> {
    let mut mjpeg = Vec::new();
    for i in 0..frame_count {
        mjpeg.extend_from_slice(&encode_sentinel_rgb_frame(i)?);
    }
    let mjpeg_path = ws
        .base
        .join(format!("{}.mjpeg", sensor_name.replace(':', "-")));
    fs::write(&mjpeg_path, &mjpeg)?;
    let (_, cx) = make_write_cx(&ws.deploy_root, SITE_ID)?;
    let mut dep = ReferenceDeployment::open(&ws.deploy_root, SITE_ID, &cx)?;
    let sensor = SensorId::parse(sensor_name)?;
    let stream = StreamId::parse("stream:main")?;
    let now_ns = wall_now_ns()?;
    let req = FileIngestRequest::new(&mjpeg_path, sensor, stream)
        .with_receive_time(TimestampNs(now_ns))
        .with_capture_hint(CaptureHint::new(
            TimestampNs(now_ns - 2_000_000_000),
            1_000_000,
            10.0,
        )?);
    let receipt = FileIngestAdapter::ingest(req, &cx, &mut dep)?;
    let plan = WatchPlan {
        import_identity: receipt.import_identity,
        interpretation: ComponentInterpretation::YCbCr,
        first_segment: 0,
        segment_count: frame_count as usize,
        zones: vec![WatchZone {
            zone_id: "entry_zone".to_owned(),
            x: 70,
            y: 50,
            width: 52,
            height: 42,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig {
            confirmation_hits: 2,
            maximum_missed_frames: 2,
            minimum_iou_ppm: 100_000,
        },
    };
    let mut report = WatchReport::analyze(&dep, &plan, &WatchLimits::default(), &cx)?;
    let approvals: BTreeSet<ContentDigest> = report
        .candidates()
        .iter()
        .map(|c| c.proposal_digest())
        .collect();
    if approvals.is_empty() {
        return Err("sentinel watch fixture produced no track candidate".into());
    }
    let published = report.publish(&mut dep, &approvals, &cx)?;
    if published == 0 {
        return Err("sentinel watch fixture published 0 events".into());
    }
    let cov_approval = report.coverage_approval();
    let _ = report.retain_coverage(&mut dep, cov_approval, &cx)?;
    cx.drain_and_finalize();
    let event_id = report
        .candidates()
        .first()
        .map(|c| c.event().event_id.as_str().to_owned())
        .ok_or("missing watch candidate event id")?;
    Ok((receipt.import_identity, event_id))
}

pub fn make_calibrated_table() -> TestResult<ScoreCalibration> {
    Ok(ScoreCalibration::from_counts(
        "cal:mcp14-live:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?)
}

/// Builds a `SiteManifest` with `camera_count` cameras across distinct failure domains,
/// storing v2 packs/epochs/MVCC under `v2_root` while serving UDS `fss-ipc` at `ipc_root`.
pub fn build_site_manifest(
    v2_root: &Path,
    ipc_root: &Path,
    camera_count: usize,
    ring_cap_bytes: u64,
    pack_target_bytes: u64,
) -> TestResult<SiteManifest> {
    let mut cameras_json = Vec::with_capacity(camera_count);
    let mut cam_ids = Vec::with_capacity(camera_count);
    for idx in 1..=camera_count {
        let sensor_id = format!("sensor:cam-{idx:02}");
        let domain = format!("poe:switch-{}", ((idx - 1) % 4) + 1);
        let circuit = format!("power:circuit-{idx}");
        let tier = match idx % 3 {
            0 => "active_investigation",
            1 => "high_consequence_zone",
            _ => "standard",
        };
        cameras_json.push(format!(
            r#"{{
              "sensor_id": "{sensor_id}",
              "adapter": "synthetic",
              "endpoint": "synthetic://cam-{idx:02}",
              "secret_id": "secret:cam:{idx:02}",
              "priority_tier": "{tier}",
              "zone_id": "driveway",
              "dimensions": [32, 32],
              "osd_ignore_rects": ["0,0,8,4"],
              "failure_domains": ["{domain}", "{circuit}"],
              "reconnect_min_ms": 200,
              "reconnect_max_ms": 2000,
              "stall_timeout_ms": 5000,
              "ring_max_frames": 32,
              "ring_max_bytes": 65536,
              "gop_frames": 2
            }}"#
        ));
        cam_ids.push(format!("\"{sensor_id}\""));
    }
    let root_str = v2_root.to_string_lossy().replace('\\', "\\\\");
    let raw = format!(
        r#"{{
          "schema": "fss.site_manifest.v1",
          "site_id": "{SITE_ID}",
          "deployment_root": "{root_str}",
          "ring_cap_bytes": {ring_cap_bytes},
          "soft_watermark_pct": 60,
          "hard_watermark_pct": 85,
          "pack_target_bytes": {pack_target_bytes},
          "scrub_budget_bytes_per_tick": 1048576,
          "cameras": [{}],
          "topology": {{
            "shared_zones": [{{
              "zone_id": "driveway",
              "cameras": [{}],
              "max_separation_ns": 5000000000
            }}]
          }}
        }}"#,
        cameras_json.join(","),
        cam_ids.join(","),
    );
    let mut manifest = SiteManifest::parse_json(&raw)?;
    manifest.ipc_socket_override = Some(ipc_root.to_path_buf());
    Ok(manifest)
}

type DaemonRunnerResult = Result<(DaemonShutdownReport, Vec<String>), String>;

/// Live background `DaemonSupervisor` running real camera ingestion, pack compaction,
/// MVCC projection commits, and UDS `fss-ipc` server until gracefully stopped via IPC.
pub struct LiveDaemonHandle {
    pub ipc_root: PathBuf,
    pub controls: BTreeMap<String, Arc<SyntheticCameraControl>>,
    runner: Option<JoinHandle<DaemonRunnerResult>>,
}

impl LiveDaemonHandle {
    pub fn start(
        manifest: SiteManifest,
        tick_interval: Duration,
        seed_compaction_candidates: bool,
    ) -> TestResult<Self> {
        let ipc_root = manifest
            .ipc_socket_override
            .clone()
            .unwrap_or_else(|| manifest.deployment_root.clone());
        let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
        let mut controls = BTreeMap::new();
        for cam in &manifest.cameras {
            let ctrl = SyntheticCameraControl::new(cam.sensor_id.clone());
            let drv: Box<dyn SensorDriver> =
                Box::new(SyntheticCameraDriver::new(cam, Arc::clone(&ctrl)));
            drivers.insert(cam.sensor_id.clone(), drv);
            controls.insert(cam.sensor_id.as_str().to_owned(), ctrl);
        }
        let now_ns = wall_now_ns()?;
        let mut cfg = DaemonStartConfig::new(manifest);
        cfg.custom_drivers = drivers;
        cfg.perception_config = PerceptionConfig {
            default_calibration: Some(make_calibrated_table()?),
            ..PerceptionConfig::default()
        };
        cfg.started_at_ns = now_ns;
        cfg.enable_ipc = true;

        let mut supervisor = DaemonSupervisor::start(cfg)?;
        if seed_compaction_candidates {
            for idx in 0..6_u64 {
                let _ = supervisor
                    .storage_mut()
                    .register_retention_candidate(RetentionCandidate {
                        import_id: format!("gop:stress-evict-{idx:03}"),
                        sensor_id: "sensor:cam-01".to_owned(),
                        capture_end_ns: TimestampNs(now_ns - 90_000_000_000_000 - i128::from(idx)),
                        byte_size: 32_768,
                        object_digests: vec![ContentDigest::sha256(
                            format!("evict-candidate-{idx}").as_bytes(),
                        )],
                        is_derived_proxy: false,
                        held_by: Vec::new(),
                        active_obligation_ids: Vec::new(),
                        active_event_ids: Vec::new(),
                    });
            }
        }
        // Run two warmup ticks synchronously so Stage-1 background models + IPC status are warm.
        let _ = supervisor.step_tick(now_ns + 50_000_000)?;
        let _ = supervisor.step_tick(now_ns + 100_000_000)?;

        let runner = thread::spawn(move || {
            let mut telemetry_tail = Vec::new();
            let mut sup = supervisor;
            loop {
                if sup.is_shutdown_requested() {
                    break;
                }
                let tick_ns = wall_now_ns().unwrap_or(now_ns + 200_000_000);
                if let Err(err) = sup.step_tick(tick_ns) {
                    return Err(format!("daemon step_tick failed: {err}"));
                }
                telemetry_tail = sup.telemetry_jsonl().iter().cloned().collect();
                if sup.is_shutdown_requested() {
                    break;
                }
                thread::sleep(tick_interval);
            }
            let report = sup
                .shutdown_graceful()
                .map_err(|e| format!("daemon shutdown_graceful failed: {e}"))?;
            Ok((report, telemetry_tail))
        });

        // Confirm UDS IPC responds cleanly before returning.
        let op = PrincipalId::parse(PRINCIPAL)?;
        let (_desc, _status) = query_live_daemon_status(&ipc_root, Some(SITE_ID), op)?;
        Ok(Self {
            ipc_root,
            controls,
            runner: Some(runner),
        })
    }

    pub fn inject_corroborated_motion(
        &self,
        cam_a: &str,
        cam_b: &str,
        track_base: u64,
    ) -> TestResult {
        let rect = ImageRect::new(10, 10, 12, 12)?;
        if let Some(a) = self.controls.get(cam_a) {
            a.inject_motion(rect, "person", 930_000, None, track_base);
        }
        if let Some(b) = self.controls.get(cam_b) {
            b.inject_motion(rect, "person", 940_000, None, track_base + 1);
        }
        Ok(())
    }

    pub fn stop_gracefully(mut self) -> TestResult<(DaemonShutdownReport, Vec<String>)> {
        let op = PrincipalId::parse(PRINCIPAL)?;
        let _ = request_live_daemon_stop(&self.ipc_root, Some(SITE_ID), op)?;
        let handle = self.runner.take().ok_or("daemon runner already joined")?;
        let joined = handle
            .join()
            .map_err(|_| "live daemon thread panicked")?
            .map_err(|e| format!("live daemon error: {e}"))?;
        Ok(joined)
    }
}

impl Drop for LiveDaemonHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.runner.take() {
            if let Ok(op) = PrincipalId::parse(PRINCIPAL) {
                let _ = request_live_daemon_stop(&self.ipc_root, Some(SITE_ID), op);
            }
            let _ = handle.join();
        }
    }
}

/// Real encrypted `fss-vault` loaded with canary secrets + paired `CanaryLeakScanner`.
pub struct VaultCanaryRig {
    pub vault: LocalEncryptedVault<LabEntropy>,
    pub scanner: CanaryLeakScanner,
    pub now: TimestampNs,
}

impl VaultCanaryRig {
    pub fn open(vault_dir: &Path, webhook_scope: SecretScope) -> TestResult<Self> {
        let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
        let pass = SecretBytes::from_slice(b"mcp14-test-vault-master-passphrase")?;
        let mut vault = LocalEncryptedVault::open_with_entropy(
            vault_dir,
            KdfParams::for_testing(1)?,
            LabEntropy::from_seed([0xA5; 32]),
        );
        vault.initialize(&pass)?;

        let hmac_secret_id = SecretId::parse("secret:webhook:primary-hmac")?;
        let hmac_cx = make_secret_cx(webhook_scope, now)?;
        vault.store(
            &hmac_cx,
            &hmac_secret_id,
            SecretBytes::from_slice(CANARY_WEBHOOK_HMAC)?,
        )?;

        let rtsp_sid = SecretId::parse("secret:camera:wyze-39-rtsp")?;
        let rtsp_cx = make_secret_cx(
            SecretScope::new(
                fss_vault::AdapterFamily::Rtsp,
                "sensor:cam-01",
                "rtsp://127.0.0.1:554/live",
            )?,
            now,
        )?;
        vault.store(
            &rtsp_cx,
            &rtsp_sid,
            SecretBytes::from_slice(CANARY_CAM_RTSP_PASS)?,
        )?;

        let unifi_sid = SecretId::parse("secret:camera:unifi-177-key")?;
        let unifi_cx = make_secret_cx(
            SecretScope::new(
                fss_vault::AdapterFamily::UniFiProtect,
                "sensor:cam-02",
                "https://127.0.0.1:7443/proxy",
            )?,
            now,
        )?;
        vault.store(
            &unifi_cx,
            &unifi_sid,
            SecretBytes::from_slice(CANARY_UNIFI_API_KEY)?,
        )?;

        let mut scanner = CanaryLeakScanner::new();
        scanner.register_bytes("webhook-hmac-canary", CANARY_WEBHOOK_HMAC)?;
        scanner.register_bytes("camera-rtsp-canary", CANARY_CAM_RTSP_PASS)?;
        scanner.register_bytes("unifi-api-canary", CANARY_UNIFI_API_KEY)?;

        Ok(Self {
            vault,
            scanner,
            now,
        })
    }

    pub fn secret_cx(&self, scope: SecretScope) -> TestResult<SecretAccessCx> {
        make_secret_cx(scope, self.now)
    }
}

pub fn make_secret_cx(scope: SecretScope, now: TimestampNs) -> TestResult<SecretAccessCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:mcp14-vault".to_owned(),
        operation_id: OperationId::parse("op:vault:mcp14")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            CAP_SECRET_READ_001.to_owned(),
            CAP_SECRET_WRITE_001.to_owned(),
        ],
        deadline: None,
        priority: 100,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner".to_owned(),
        retention_scope: "retention:standard".to_owned(),
        anchor_universe: ContentDigest::sha256(b"mcp14-vault-universe"),
        generation: 1,
    })?;
    Ok(SecretAccessCx::new(authority, scope, now)?)
}
