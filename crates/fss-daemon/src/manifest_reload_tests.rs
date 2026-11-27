#![forbid(unsafe_code)]
//! Live reload regressions: refusals are atomic, bounded, correlated, and nonfatal.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use fss_core::{CanonicalDecode, ContentDigest, OperationId, PrincipalId, SensorId};
use fss_ipc::{
    BoundedControlOp, DeltaEventSummary, DeltaSubscriptionItem, IpcClient, IpcClientConfig,
    IpcResponse,
};

use crate::{
    CameraAdapterKind, CameraManifestEntry, DaemonRuntimeDescriptor, DaemonStartConfig,
    DaemonSupervisor, SensorDisconnectReason, SensorDriver, SensorDriverEvent, SensorState,
    SiteManifest, SyntheticCameraControl, SyntheticCameraDriver,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const START_NS: i128 = 1_700_000_000_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            PathBuf::from("/tmp").join(format!("fss-reload-{}-{sequence}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn manifest_path(&self) -> PathBuf {
        self.0.join("site.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RecordingDriver {
    inner: SyntheticCameraDriver,
    updates: Arc<AtomicUsize>,
    replacement_on_update: Option<(PathBuf, String)>,
}

impl SensorDriver for RecordingDriver {
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason> {
        self.inner.connect(generation)
    }

    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent {
        self.inner.poll_frame(now_ns)
    }

    fn disconnect(&mut self) {
        self.inner.disconnect();
    }

    fn active_session_count(&self) -> u32 {
        self.inner.active_session_count()
    }

    fn total_connections(&self) -> u64 {
        self.inner.total_connections()
    }

    fn adapter_kind(&self) -> CameraAdapterKind {
        self.inner.adapter_kind()
    }

    fn update_manifest_entry(&mut self, entry: &CameraManifestEntry) {
        self.updates.fetch_add(1, Ordering::Relaxed);
        if let Some((path, text)) = self.replacement_on_update.take() {
            let _ = fs::write(path, text);
        }
        self.inner.update_manifest_entry(entry);
    }
}

fn camera_json(name: &str) -> String {
    format!(
        r#"{{
            "sensor_id":"sensor:{name}",
            "adapter":"synthetic",
            "endpoint":"synthetic://{name}",
            "priority_tier":"high_consequence_zone",
            "zone_id":"entry",
            "zones":["entry"],
            "dimensions":[32,32],
            "osd_ignore_rects":["0,0,4,4"],
            "failure_domains":["power:{name}"],
            "reconnect_min_ms":200,
            "reconnect_max_ms":2000,
            "stall_timeout_ms":5000,
            "ring_max_frames":64,
            "ring_max_bytes":32768,
            "gop_frames":4
        }}"#
    )
}

fn manifest_json(root: &Path, cameras: &[String]) -> String {
    let root = crate::telemetry::escape_json(&root.to_string_lossy());
    format!(
        r#"{{
            "schema":"fss.site_manifest.v1",
            "site_id":"site-reload-test",
            "deployment_root":"{root}",
            "ring_cap_bytes":67108864,
            "soft_watermark_pct":75,
            "hard_watermark_pct":95,
            "pack_target_bytes":65536,
            "scrub_budget_bytes_per_tick":1048576,
            "retain_hot_ns":86400000000000,
            "cameras":[{}]
        }}"#,
        cameras.join(",")
    )
}

fn start_supervisor(
    dir: &TempDir,
    enable_ipc: bool,
) -> Result<(DaemonSupervisor, Arc<AtomicUsize>, String), Box<dyn std::error::Error>> {
    start_supervisor_with_replacement(dir, enable_ipc, None)
}

fn start_supervisor_with_replacement(
    dir: &TempDir,
    enable_ipc: bool,
    replacement: Option<&str>,
) -> Result<(DaemonSupervisor, Arc<AtomicUsize>, String), Box<dyn std::error::Error>> {
    let text = manifest_json(&dir.0, &[camera_json("cam-a"), camera_json("cam-b")]);
    fs::write(dir.manifest_path(), &text)?;
    let manifest = SiteManifest::parse_json(&text)?;
    let updates = Arc::new(AtomicUsize::new(0));
    let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
    for entry in &manifest.cameras {
        let control = SyntheticCameraControl::new(entry.sensor_id.clone());
        drivers.insert(
            entry.sensor_id.clone(),
            Box::new(RecordingDriver {
                inner: SyntheticCameraDriver::new(entry, control),
                updates: Arc::clone(&updates),
                replacement_on_update: replacement
                    .map(|text| (dir.manifest_path(), text.to_owned())),
            }),
        );
    }
    let mut config = DaemonStartConfig::new(manifest);
    config.manifest_path = Some(dir.manifest_path());
    config.custom_drivers = drivers;
    config.started_at_ns = START_NS;
    config.enable_ipc = enable_ipc;
    let mut supervisor = DaemonSupervisor::start(config)?;
    let first_tick = supervisor.step_tick(START_NS + 100_000_000)?;
    assert!(first_tick.frames_received >= 2);
    Ok((supervisor, updates, text))
}

fn reload_current_candidate(
    supervisor: &mut DaemonSupervisor,
    operation: &OperationId,
) -> TestResult {
    let path = supervisor
        .manifest_path
        .as_ref()
        .ok_or("reload source missing")?;
    let candidate = SiteManifest::from_file(path)?;
    let shared = supervisor
        .control_shared
        .as_ref()
        .ok_or("control owner missing")?;
    let approval =
        shared.expected_manifest_reload_approval(supervisor.manifest.digest(), candidate.digest());
    supervisor.handle_reload_manifest(operation, approval)?;
    Ok(())
}

fn reload_client(dir: &TempDir) -> Result<IpcClient, Box<dyn std::error::Error>> {
    reload_client_as(dir, "principal:local-operator")
}

fn reload_client_as(
    dir: &TempDir,
    principal: &str,
) -> Result<IpcClient, Box<dyn std::error::Error>> {
    let descriptor = DaemonRuntimeDescriptor::read_from_root(&dir.0)?;
    Ok(IpcClient::connect(IpcClientConfig {
        deployment_root: dir.0.clone(),
        deployment_id: descriptor.site_id,
        contract_basis_digest: descriptor.contract_basis_digest,
        principal: PrincipalId::parse(principal)?,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?)
}

fn preview_reload(
    client: &mut IpcClient,
) -> Result<(ContentDigest, ContentDigest, ContentDigest), Box<dyn std::error::Error>> {
    let request = client.next_request_id();
    match client.preview_manifest_reload(request)? {
        IpcResponse::ManifestReloadPreview {
            request_id,
            active_manifest_digest,
            candidate_manifest_digest,
            approval_digest,
        } => {
            assert_eq!(request_id, request);
            Ok((
                active_manifest_digest,
                candidate_manifest_digest,
                approval_digest,
            ))
        }
        response => Err(format!("reload preview refused: {response:?}").into()),
    }
}

fn reload_operation_summaries(dir: &TempDir) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut observer = reload_client(dir)?;
    let request = observer.next_request_id();
    let mut summaries = Vec::new();
    for item in observer.subscribe_deltas(request, 0, 64)? {
        if let DeltaSubscriptionItem::Event {
            summary_canonical, ..
        } = item?
        {
            let summary = DeltaEventSummary::from_canonical_bytes(&summary_canonical)?;
            if summary.summary.starts_with("manifest_reload") {
                summaries.push(summary.summary);
            }
        }
    }
    Ok(summaries)
}

fn finish(supervisor: DaemonSupervisor) -> TestResult {
    let shutdown = supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    Ok(())
}

#[test]
fn reload_refuses_startup_owned_changes_before_mutating_any_live_owner() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, false)?;
    let before = supervisor.manifest.clone();
    let clock = supervisor
        .perception
        .corroborator()
        .clock_receipt("sensor:cam-a")?;
    let metrics = supervisor.perception.pool_metrics();
    let operation = OperationId::parse("op:reload:atomic")?;

    let cases = [
        (
            "site identity",
            r#""site_id":"site-reload-test""#,
            r#""site_id":"other-site""#,
        ),
        (
            "storage capacity",
            r#""ring_cap_bytes":67108864"#,
            r#""ring_cap_bytes":134217728"#,
        ),
        (
            "soft watermark",
            r#""soft_watermark_pct":75"#,
            r#""soft_watermark_pct":70"#,
        ),
        (
            "hard watermark",
            r#""hard_watermark_pct":95"#,
            r#""hard_watermark_pct":90"#,
        ),
        (
            "pack target",
            r#""pack_target_bytes":65536"#,
            r#""pack_target_bytes":131072"#,
        ),
        (
            "scrub budget",
            r#""scrub_budget_bytes_per_tick":1048576"#,
            r#""scrub_budget_bytes_per_tick":2097152"#,
        ),
        (
            "retention",
            r#""retain_hot_ns":86400000000000"#,
            r#""retain_hot_ns":43200000000000"#,
        ),
        (
            "detector threshold",
            r#""retain_hot_ns":86400000000000"#,
            r#""retain_hot_ns":86400000000000,"detector_min_score_ppm":500000"#,
        ),
        ("adapter", r#""adapter":"synthetic""#, r#""adapter":"rtsp""#),
        (
            "endpoint",
            r#""endpoint":"synthetic://cam-a""#,
            r#""endpoint":"synthetic://other-camera""#,
        ),
        (
            "secret binding",
            r#""endpoint":"synthetic://cam-a""#,
            r#""endpoint":"synthetic://cam-a","secret_id":"secret:rtsp:cam-a""#,
        ),
        (
            "dimensions",
            r#""dimensions":[32,32]"#,
            r#""dimensions":[64,32]"#,
        ),
        (
            "primary zone",
            r#""zone_id":"entry""#,
            r#""zone_id":"porch""#,
        ),
        (
            "ring frame budget",
            r#""ring_max_frames":64"#,
            r#""ring_max_frames":128"#,
        ),
        (
            "ring byte budget",
            r#""ring_max_bytes":32768"#,
            r#""ring_max_bytes":65536"#,
        ),
        (
            "camera retention time",
            r#""ring_max_bytes":32768"#,
            r#""ring_max_bytes":32768,"retain_hot_ns":1000"#,
        ),
        (
            "camera storage quota",
            r#""ring_max_bytes":32768"#,
            r#""ring_max_bytes":32768,"max_sensor_bytes":65536"#,
        ),
        (
            "auth realm",
            r#""endpoint":"synthetic://cam-a""#,
            r#""endpoint":"synthetic://cam-a","auth_realm":"other-realm""#,
        ),
        (
            "in-band parameters",
            r#""endpoint":"synthetic://cam-a""#,
            r#""endpoint":"synthetic://cam-a","allow_inband_sps_pps":true"#,
        ),
        (
            "companion tracks",
            r#""endpoint":"synthetic://cam-a""#,
            r#""endpoint":"synthetic://cam-a","setup_companion_tracks":true"#,
        ),
    ];
    for (label, old, new) in cases {
        // Mix a supported update with the unsupported one: refusal must not partially apply it.
        let candidate = text.replacen(old, new, 1).replace("0,0,4,4", "0,0,8,4");
        let _ = SiteManifest::parse_json(&candidate)?;
        fs::write(dir.manifest_path(), candidate)?;
        reload_current_candidate(&mut supervisor, &operation)?;
        assert_eq!(supervisor.manifest, before, "{label}");
        for slot in supervisor.sensors.values() {
            let original = before
                .cameras
                .iter()
                .find(|camera| camera.sensor_id == slot.entry.sensor_id)
                .ok_or("original camera missing")?;
            assert_eq!(&slot.entry, original, "{label}");
            assert_eq!(slot.driver.active_session_count(), 1, "{label}");
        }
        assert_eq!(updates.load(Ordering::Relaxed), 0, "{label}");
        assert_eq!(supervisor.perception.pool_metrics(), metrics, "{label}");
        assert_eq!(
            supervisor
                .perception
                .corroborator()
                .clock_receipt("sensor:cam-a")?,
            clock,
            "{label}"
        );
    }

    for (field, value) in [
        (
            "deployment_root",
            crate::telemetry::escape_json(&dir.0.join("other").to_string_lossy()),
        ),
        (
            "ipc_socket_override",
            crate::telemetry::escape_json(&dir.0.join("other-ipc").to_string_lossy()),
        ),
    ] {
        let candidate = if field == "deployment_root" {
            text.replace(
                &format!(
                    r#""deployment_root":"{}""#,
                    crate::telemetry::escape_json(&dir.0.to_string_lossy())
                ),
                &format!(r#""deployment_root":"{value}""#),
            )
        } else {
            text.replacen(
                r#""cameras":["#,
                &format!(r#""ipc_socket_override":"{value}","cameras":["#),
                1,
            )
        };
        let _ = SiteManifest::parse_json(&candidate)?;
        fs::write(dir.manifest_path(), candidate)?;
        reload_current_candidate(&mut supervisor, &operation)?;
        assert_eq!(supervisor.manifest, before, "{field}");
        assert_eq!(updates.load(Ordering::Relaxed), 0, "{field}");
        assert_eq!(supervisor.perception.pool_metrics(), metrics, "{field}");
    }
    finish(supervisor)
}

#[test]
fn reload_cannot_add_remove_or_replace_live_camera_inventory() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, _) = start_supervisor(&dir, false)?;
    let before = supervisor.manifest.clone();
    let operation = OperationId::parse("op:reload:inventory")?;
    for cameras in [
        vec![camera_json("cam-a")],
        vec![
            camera_json("cam-a"),
            camera_json("cam-b"),
            camera_json("cam-c"),
        ],
        vec![camera_json("cam-a"), camera_json("cam-c")],
    ] {
        let candidate = manifest_json(&dir.0, &cameras).replace("0,0,4,4", "0,0,8,4");
        let _ = SiteManifest::parse_json(&candidate)?;
        fs::write(dir.manifest_path(), candidate)?;
        reload_current_candidate(&mut supervisor, &operation)?;
        assert_eq!(supervisor.manifest, before);
        assert_eq!(supervisor.sensors.len(), 2);
        assert!(
            supervisor
                .sensors
                .contains_key(&SensorId::parse("sensor:cam-b")?)
        );
        assert!(
            !supervisor
                .sensors
                .contains_key(&SensorId::parse("sensor:cam-c")?)
        );
        assert_eq!(updates.load(Ordering::Relaxed), 0);
    }
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    finish(supervisor)
}

#[test]
fn reload_noop_and_timing_changes_preserve_accumulated_clock_evidence() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, false)?;
    let operation = OperationId::parse("op:reload:timing")?;
    let clock = supervisor
        .perception
        .corroborator()
        .clock_receipt("sensor:cam-a")?;
    let metrics = supervisor.perception.pool_metrics();

    // A re-read of the same validated manifest must not reset the cascade or clock estimator.
    reload_current_candidate(&mut supervisor, &operation)?;
    assert_eq!(updates.load(Ordering::Relaxed), 0);
    assert_eq!(supervisor.perception.pool_metrics(), metrics);
    assert_eq!(
        supervisor
            .perception
            .corroborator()
            .clock_receipt("sensor:cam-a")?,
        clock
    );

    let sid = SensorId::parse("sensor:cam-a")?;
    {
        let slot = supervisor.sensors.get_mut(&sid).ok_or("missing camera")?;
        slot.driver.disconnect();
        slot.state = SensorState::GapBackoff;
        slot.next_reconnect_ns = START_NS + 60_000_000_000;
    }
    let candidate = text
        .replacen(r#""reconnect_min_ms":200"#, r#""reconnect_min_ms":300"#, 1)
        .replacen(r#""reconnect_max_ms":2000"#, r#""reconnect_max_ms":600"#, 1)
        .replacen(
            r#""stall_timeout_ms":5000"#,
            r#""stall_timeout_ms":6000"#,
            1,
        )
        .replacen(r#""gop_frames":4"#, r#""gop_frames":8"#, 1);
    let expected = SiteManifest::parse_json(&candidate)?;
    fs::write(dir.manifest_path(), candidate)?;
    reload_current_candidate(&mut supervisor, &operation)?;
    assert_eq!(supervisor.manifest, expected);
    assert_eq!(updates.load(Ordering::Relaxed), 1);
    assert_eq!(supervisor.perception.pool_metrics(), metrics);
    assert_eq!(
        supervisor
            .perception
            .corroborator()
            .clock_receipt("sensor:cam-a")?,
        clock
    );
    let slot = supervisor.sensors.get(&sid).ok_or("missing camera")?;
    let delay_ns = slot.next_reconnect_ns - supervisor.last_now_ns;
    assert!((300_000_000..=600_000_000).contains(&delay_ns));
    assert_eq!(slot.entry.gop_frames, 8);
    finish(supervisor)
}

#[test]
fn reload_applies_supported_perception_fields_without_rebinding_resources() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, false)?;
    let sid = SensorId::parse("sensor:cam-a")?;
    let prior_backoff = {
        let slot = supervisor.sensors.get_mut(&sid).ok_or("missing camera")?;
        let _ = slot.backoff.next_delay_ms();
        let _ = slot.backoff.next_delay_ms();
        slot.backoff.clone()
    };
    let candidate = text
        .replace("0,0,4,4", "0,0,8,4")
        .replace("high_consequence_zone", "active_investigation")
        .replace(r#""zones":["entry"]"#, r#""zones":["entry","porch"]"#)
        .replace("power:cam-a", "power:replacement");
    let expected = SiteManifest::parse_json(&candidate)?;
    fs::write(dir.manifest_path(), candidate)?;
    reload_current_candidate(
        &mut supervisor,
        &OperationId::parse("op:reload:perception")?,
    )?;
    assert_eq!(supervisor.manifest, expected);
    assert_eq!(
        supervisor.perception.corroborator().topology_digest(),
        expected.to_site_topology()?.digest()
    );
    for camera in &expected.cameras {
        let slot = supervisor
            .sensors
            .get(&camera.sensor_id)
            .ok_or("missing camera")?;
        assert_eq!(&slot.entry, camera);
        assert_eq!(slot.driver.active_session_count(), 1);
        assert_eq!(slot.stream_generation, 1);
    }
    assert_eq!(updates.load(Ordering::Relaxed), 2);
    assert_eq!(
        supervisor
            .sensors
            .get(&sid)
            .ok_or("missing camera")?
            .backoff,
        prior_backoff
    );
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    finish(supervisor)
}

#[test]
fn reload_unavailable_or_corrupt_model_keeps_the_active_generation() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, false)?;
    let before = supervisor.manifest.clone();
    let clock = supervisor
        .perception
        .corroborator()
        .clock_receipt("sensor:cam-a")?;
    let metrics = supervisor.perception.pool_metrics();
    let operation = OperationId::parse("op:reload:model-failure")?;
    let corrupt_bytes: &[u8] = b"not a canonical detector package";
    for (name, bytes) in [
        ("missing.fmpk", None),
        ("corrupt.fmpk", Some(corrupt_bytes)),
    ] {
        let package_path = dir.0.join(name);
        if let Some(bytes) = bytes {
            fs::write(&package_path, bytes)?;
        }
        // Match the corrupt file's actual digest so this also reaches package validation.
        let digest = ContentDigest::sha256(bytes.unwrap_or(b"missing package")).to_text();
        let package_path = crate::telemetry::escape_json(&package_path.to_string_lossy());
        let candidate = text
            .replacen(
                r#""cameras":["#,
                &format!(
                    r#""detector_package_path":"{package_path}","detector_package_digest":"{digest}","cameras":["#
                ),
                1,
            )
            .replace("0,0,4,4", "0,0,8,4");
        let _ = SiteManifest::parse_json(&candidate)?;
        fs::write(dir.manifest_path(), candidate)?;
        reload_current_candidate(&mut supervisor, &operation)?;
        assert_eq!(supervisor.manifest, before, "{name}");
        assert_eq!(updates.load(Ordering::Relaxed), 0, "{name}");
        assert_eq!(supervisor.perception.pool_metrics(), metrics, "{name}");
        assert!(!supervisor.perception.is_rgb_detector_active());
        assert_eq!(
            supervisor
                .perception
                .corroborator()
                .clock_receipt("sensor:cam-a")?,
            clock,
            "{name}"
        );
        for slot in supervisor.sensors.values() {
            assert_eq!(slot.driver.active_session_count(), 1, "{name}");
        }
    }
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    finish(supervisor)
}

#[test]
fn queued_reload_refusals_are_correlated_and_do_not_stop_camera_ticks() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, true)?;
    let original = supervisor.manifest.clone();
    let descriptor = DaemonRuntimeDescriptor::read_from_root(&dir.0)?;
    let mut client = IpcClient::connect(IpcClientConfig {
        deployment_root: dir.0.clone(),
        deployment_id: descriptor.site_id.clone(),
        contract_basis_digest: descriptor.contract_basis_digest,
        principal: PrincipalId::parse("principal:local-operator")?,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?;
    let unsupported = text.replacen(r#""dimensions":[32,32]"#, r#""dimensions":[64,32]"#, 1);
    let _ = SiteManifest::parse_json(&unsupported)?;
    for (index, candidate) in [unsupported.as_str(), "{malformed"].iter().enumerate() {
        // A valid preview/admission must precede the malformed-on-disk execution case.
        fs::write(dir.manifest_path(), &unsupported)?;
        let (_, _, approval) = preview_reload(&mut client)?;
        let request = client.next_request_id();
        let response = client.submit_idempotent_control(
            request,
            ContentDigest::sha256(format!("reload-refusal-{index}").as_bytes()),
            BoundedControlOp::ReloadManifest,
            None,
            approval,
        )?;
        fs::write(dir.manifest_path(), candidate)?;
        let IpcResponse::ControlAccepted { operation_id, .. } = response else {
            return Err("reload was not queued".into());
        };
        let now = START_NS + (index as i128 + 2) * 100_000_000;
        assert!(supervisor.step_tick(now)?.frames_received >= 2);
        assert_eq!(supervisor.manifest, original);
        assert_eq!(updates.load(Ordering::Relaxed), 0);

        // Read the bounded retained bus after execution, avoiding a subscriber-start race.
        let mut observer = IpcClient::connect(IpcClientConfig {
            deployment_root: dir.0.clone(),
            deployment_id: descriptor.site_id.clone(),
            contract_basis_digest: descriptor.contract_basis_digest,
            principal: PrincipalId::parse("principal:local-operator")?,
            capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
            io_timeout: Duration::from_secs(3),
        })?;
        let request = observer.next_request_id();
        let subscription = observer.subscribe_deltas(request, 0, 64)?;
        let operation_marker = format!("operation_id={}", operation_id.as_str());
        let mut found = false;
        for item in subscription {
            if let DeltaSubscriptionItem::Event {
                summary_canonical, ..
            } = item?
            {
                let summary = DeltaEventSummary::from_canonical_bytes(&summary_canonical)?;
                if summary.summary.starts_with("manifest_reload_refused")
                    && summary.summary.contains(&operation_marker)
                {
                    assert!(
                        summary
                            .summary
                            .contains(crate::ERR_DAEMON_MANIFEST_INVALID_001)
                    );
                    if index == 0 {
                        assert!(summary.summary.contains("reason=restart_required"));
                        assert!(summary.summary.contains("field=camera_dimensions"));
                    }
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "missing correlated reload refusal");
    }
    drop(client);
    assert!(
        supervisor
            .step_tick(START_NS + 400_000_000)?
            .frames_received
            >= 2
    );
    finish(supervisor)
}

#[test]
fn live_reload_preview_binds_exact_generations_and_refuses_stale_or_legacy_approval() -> TestResult
{
    let dir = TempDir::new()?;
    let (supervisor, updates, text) = start_supervisor(&dir, true)?;
    let active = supervisor.manifest.digest();
    let candidate_a = text.replacen(r#""gop_frames":4"#, r#""gop_frames":8"#, 1);
    let expected_a = SiteManifest::parse_json(&candidate_a)?.digest();
    fs::write(dir.manifest_path(), &candidate_a)?;
    let mut client = reload_client(&dir)?;
    let (preview_active, preview_candidate, approval) = preview_reload(&mut client)?;
    assert_eq!(preview_active, active);
    assert_eq!(preview_candidate, expected_a);
    assert_ne!(active, expected_a);
    assert_eq!(updates.load(Ordering::Relaxed), 0);
    assert_eq!(supervisor.manifest.digest(), active);
    let shared = supervisor
        .control_shared
        .as_ref()
        .ok_or("control owner missing")?;
    assert_eq!(shared.queued_control_command_count()?, 0);

    let legacy = crate::control::control_op_approval_digest(
        &supervisor.manifest.site_id,
        BoundedControlOp::ReloadManifest,
        None,
    );
    for keyed in [false, true] {
        let request = client.next_request_id();
        let response = if keyed {
            client.submit_idempotent_control(
                request,
                ContentDigest::sha256(b"legacy-reload-approval"),
                BoundedControlOp::ReloadManifest,
                None,
                legacy,
            )?
        } else {
            client.submit_bounded_control(
                request,
                BoundedControlOp::ReloadManifest,
                None,
                approval,
            )?
        };
        assert!(matches!(response, IpcResponse::Refused { ref error_id, .. }
            if error_id.as_str() == crate::ERR_DAEMON_CONTROL_APPROVAL_001));
    }

    let candidate_b = text.replacen(r#""gop_frames":4"#, r#""gop_frames":16"#, 1);
    fs::write(dir.manifest_path(), candidate_b)?;
    let request = client.next_request_id();
    let response = client.submit_idempotent_control(
        request,
        ContentDigest::sha256(b"stale-reload-candidate"),
        BoundedControlOp::ReloadManifest,
        None,
        approval,
    )?;
    assert!(matches!(response, IpcResponse::Refused { ref error_id, .. }
        if error_id.as_str() == crate::ERR_DAEMON_CONTROL_APPROVAL_001));
    let (same_active, different_candidate, different_approval) = preview_reload(&mut client)?;
    assert_eq!(same_active, active);
    assert_ne!(different_candidate, expected_a);
    assert_ne!(different_approval, approval);
    assert_eq!(shared.queued_control_command_count()?, 0);
    assert_eq!(supervisor.manifest.digest(), active);
    assert_eq!(updates.load(Ordering::Relaxed), 0);
    drop(client);
    finish(supervisor)
}

#[test]
fn queued_reload_refuses_candidate_drift_and_exact_retry_survives_missing_source_and_restart()
-> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, true)?;
    let original = supervisor.manifest.clone();
    let original_clock = supervisor
        .perception
        .corroborator()
        .clock_receipt("sensor:cam-a")?;
    let candidate_a = text.replace("0,0,4,4", "0,0,8,4");
    fs::write(dir.manifest_path(), candidate_a)?;
    let mut client = reload_client(&dir)?;
    let (_, _, approval) = preview_reload(&mut client)?;
    let key = ContentDigest::sha256(b"reload-candidate-drift-retained-key");
    let request = client.next_request_id();
    let IpcResponse::ControlAccepted { operation_id, .. } = client.submit_idempotent_control(
        request,
        key,
        BoundedControlOp::ReloadManifest,
        None,
        approval,
    )?
    else {
        return Err("approved reload was not admitted".into());
    };

    // The already queued approval must never authorize later replacement content.
    fs::write(dir.manifest_path(), text.replace("0,0,4,4", "0,0,16,4"))?;
    supervisor.process_control_commands_step(
        START_NS + 200_000_000,
        fss_core::TimestampNs(START_NS + 200_000_000),
    )?;
    assert_eq!(supervisor.manifest, original);
    assert_eq!(updates.load(Ordering::Relaxed), 0);
    assert_eq!(
        supervisor
            .perception
            .corroborator()
            .clock_receipt("sensor:cam-a")?,
        original_clock,
    );
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    let summaries = reload_operation_summaries(&dir)?;
    assert!(summaries.iter().any(
        |summary| summary.contains("reason=approval_generation_mismatch")
            && summary.contains(&format!("operation_id={}", operation_id.as_str()))
    ));

    fs::remove_file(dir.manifest_path())?;
    let request = client.next_request_id();
    assert!(matches!(
        client.submit_idempotent_control(request, key, BoundedControlOp::ReloadManifest, None, approval)?,
        IpcResponse::ControlReplayed {
            operation_id: ref replayed,
            progress: fss_ipc::RetainedControlProgress::SubsystemReturned,
            recovered: false, ..
        } if replayed == &operation_id
    ));
    let request = client.next_request_id();
    assert!(matches!(
        client.submit_idempotent_control(
            request, key, BoundedControlOp::ReloadManifest, None,
            ContentDigest::sha256(b"changed retained approval"),
        )?,
        IpcResponse::Refused { ref error_id, .. }
            if error_id.as_str() == "ERR-IDEMPOTENCY-CONFLICT-001"
    ));
    let mut changed_principal = reload_client_as(&dir, "principal:other-operator")?;
    let request = changed_principal.next_request_id();
    assert!(matches!(
        changed_principal.submit_idempotent_control(
            request, key, BoundedControlOp::ReloadManifest, None, approval,
        )?,
        IpcResponse::Refused { ref error_id, .. }
            if error_id.as_str() == "ERR-IDEMPOTENCY-CONFLICT-001"
    ));
    drop(changed_principal);
    assert_eq!(updates.load(Ordering::Relaxed), 0);
    drop(client);
    finish(supervisor)?;

    // Recover from the validated startup object; the reload source deliberately stays absent.
    let mut config = DaemonStartConfig::new(original);
    config.manifest_path = Some(dir.manifest_path());
    config.started_at_ns = START_NS + 1_000_000_000;
    config.enable_ipc = true;
    let restarted = DaemonSupervisor::start(config)?;
    let mut client = reload_client(&dir)?;
    let request = client.next_request_id();
    assert!(matches!(
        client.submit_idempotent_control(request, key, BoundedControlOp::ReloadManifest, None, approval)?,
        IpcResponse::ControlReplayed {
            operation_id: ref replayed,
            progress: fss_ipc::RetainedControlProgress::SubsystemReturned,
            recovered: true, ..
        } if replayed == &operation_id
    ));
    assert_eq!(
        restarted
            .control_shared
            .as_ref()
            .ok_or("control owner missing")?
            .queued_control_command_count()?,
        0,
    );
    let request = client.next_request_id();
    assert!(matches!(
        client.preview_manifest_reload(request)?,
        IpcResponse::Refused { .. }
    ));
    drop(client);
    finish(restarted)
}

#[test]
fn queued_reload_revalidates_active_generation_and_publishes_the_applied_candidate() -> TestResult {
    let dir = TempDir::new()?;
    let (mut supervisor, updates, text) = start_supervisor(&dir, true)?;
    let candidate = text.replacen(r#""gop_frames":4"#, r#""gop_frames":8"#, 1);
    let expected = SiteManifest::parse_json(&candidate)?;
    fs::write(dir.manifest_path(), candidate)?;
    let mut client = reload_client(&dir)?;
    let (old_active, candidate_digest, approval) = preview_reload(&mut client)?;
    assert_ne!(old_active, candidate_digest);
    let mut operations = Vec::new();
    for index in 0..2 {
        let request = client.next_request_id();
        let response = client.submit_idempotent_control(
            request,
            ContentDigest::sha256(format!("reload-generation-fence-{index}").as_bytes()),
            BoundedControlOp::ReloadManifest,
            None,
            approval,
        )?;
        let IpcResponse::ControlAccepted { operation_id, .. } = response else {
            return Err(format!("reload was not queued: {response:?}").into());
        };
        operations.push(operation_id);
    }
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    assert_eq!(supervisor.manifest, expected);
    assert_eq!(updates.load(Ordering::Relaxed), 1);
    let summaries = reload_operation_summaries(&dir)?;
    assert!(
        summaries
            .iter()
            .any(|summary| summary.starts_with("manifest_reloaded")
                && summary.contains(&format!("operation_id={}", operations[0].as_str())))
    );
    assert!(summaries.iter().any(
        |summary| summary.contains("reason=approval_generation_mismatch")
            && summary.contains(&format!("operation_id={}", operations[1].as_str()))
    ));
    let (new_active, same_candidate, new_approval) = preview_reload(&mut client)?;
    assert_eq!(new_active, candidate_digest);
    assert_eq!(same_candidate, candidate_digest);
    assert_ne!(approval, new_approval);

    let request = client.next_request_id();
    assert!(matches!(
        client.submit_idempotent_control(
            request, ContentDigest::sha256(b"stale-active-generation"),
            BoundedControlOp::ReloadManifest, None, approval,
        )?,
        IpcResponse::Refused { ref error_id, .. }
            if error_id.as_str() == crate::ERR_DAEMON_CONTROL_APPROVAL_001
    ));
    drop(client);
    finish(supervisor)
}

#[test]
fn reload_applies_one_owned_snapshot_even_if_source_changes_during_driver_update() -> TestResult {
    let dir = TempDir::new()?;
    let replacement = manifest_json(&dir.0, &[camera_json("cam-a"), camera_json("cam-b")])
        .replacen(r#""gop_frames":4"#, r#""gop_frames":16"#, 1);
    let replacement_digest = SiteManifest::parse_json(&replacement)?.digest();
    let (mut supervisor, updates, text) =
        start_supervisor_with_replacement(&dir, true, Some(&replacement))?;
    let candidate = text.replacen(r#""gop_frames":4"#, r#""gop_frames":8"#, 1);
    let approved = SiteManifest::parse_json(&candidate)?;
    fs::write(dir.manifest_path(), candidate)?;
    let mut client = reload_client(&dir)?;
    let (_, candidate_digest, approval) = preview_reload(&mut client)?;
    assert_eq!(candidate_digest, approved.digest());
    let request = client.next_request_id();
    assert!(matches!(
        client.submit_idempotent_control(
            request,
            ContentDigest::sha256(b"reload-owned-snapshot"),
            BoundedControlOp::ReloadManifest,
            None,
            approval,
        )?,
        IpcResponse::ControlAccepted { .. }
    ));
    assert!(
        supervisor
            .step_tick(START_NS + 200_000_000)?
            .frames_received
            >= 2
    );
    assert_eq!(updates.load(Ordering::Relaxed), 1);
    assert_eq!(fs::read_to_string(dir.manifest_path())?, replacement);
    assert_eq!(supervisor.manifest, approved);
    for camera in &approved.cameras {
        assert_eq!(
            &supervisor
                .sensors
                .get(&camera.sensor_id)
                .ok_or("missing camera")?
                .entry,
            camera,
        );
    }
    let (active, pending, _) = preview_reload(&mut client)?;
    assert_eq!(active, approved.digest());
    assert_eq!(pending, replacement_digest);
    assert_ne!(active, pending);
    drop(client);
    finish(supervisor)
}
