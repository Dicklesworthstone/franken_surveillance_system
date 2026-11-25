#![forbid(unsafe_code)]
//! Contract integration tests for `fss-daemon`:
//! 1. Multi-camera (`wyze-39`, `wyze-51`, `unifi-g4-177`) supervision, single upstream session,
//!    OSD masking, independent cluster corroboration + `< 500 ms` `fss-ipc` `SubscribeDeltas`,
//!    and shared-failure-domain honest withholding (`SharedFailureDomainHeld`).
//! 2. Camera disconnect -> immediate `NotObservable` `CoverageGap` + deterministic backoff recovery
//!    into stream generation `2` without bridging the gap.
//! 3. Slow-consumer backpressure shedding with strictly bounded ring RAM.
//! 4. Critical 100%-pinned quota pressure (`ERR-STORAGE-QUOTA-PINNED-001`) pausing ingest cleanly
//!    without evicting held closures.
//! 5. Graceful IPC `Stop` (`request -> drain -> finalize`) with `active_tasks == 0`,
//!    `leaked_obligations == 0`, full Merkle ledger verification, and socket cleanup.
//! 6. Plaintext credential refusal in `site.json` (`ERR-DAEMON-SECRET-IN-MANIFEST-001`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    CanonicalDecode, ContentDigest, DeltaPriority, EventState, MeaningfulDeltaClass, PrincipalId,
    ResourcePressure, SensorId, TimestampNs,
};
use fss_daemon::{
    DaemonError, DaemonRuntimeDescriptor, DaemonStartConfig, DaemonSupervisor,
    ERR_DAEMON_CONTROL_APPROVAL_001, ERR_DAEMON_SECRET_IN_MANIFEST_001, PerceptionConfig,
    SensorDisconnectReason, SensorDriver, SensorState, SiteManifest, SyntheticCameraControl,
    SyntheticCameraDriver, SyntheticFrameSpec, query_live_daemon_status, request_live_daemon_stop,
};
use fss_fusion::ScoreCalibration;
use fss_ipc::{
    BoundedControlOp, DeltaEventSummary, DeltaSubscriptionItem, IpcClient, IpcClientConfig,
    IpcResponse, default_socket_path,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{CapacityPressure, ERR_STORAGE_QUOTA_PINNED_001, RetentionCandidate};
use fss_projection_store::{CoverageStatus, ProjectionStore};
use fss_reference::ReferencePolicyAction;
use fss_reference::ingest::live_corroborate::CorroborationOutcome;
use fss_reference::ingest::osd_mask::ImageRect;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let short_label: String = label.chars().take(8).collect();
        // Keep path well below macOS SUN_LEN (104 bytes) for `<root>/run/daemon.sock`.
        let dir =
            PathBuf::from("/tmp").join(format!("fssd-{short_label}-{}-{n}", std::process::id()));
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

fn make_calibrated_person_table() -> Result<ScoreCalibration, Box<dyn std::error::Error>> {
    // High-confidence bin (800_000..=1_000_000): 95 TP vs 1 FP -> strong positive milliban LLR.
    let cal = ScoreCalibration::from_counts(
        "cal:live-person:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?;
    Ok(cal)
}

fn three_camera_manifest_json(root: &Path, ring_cap_bytes: u64, ring_max_frames: usize) -> String {
    let root_str = root.to_string_lossy().replace('\\', "\\\\");
    format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-home-east",
  "deployment_root": "{root_str}",
  "ring_cap_bytes": {ring_cap_bytes},
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
      "ring_max_frames": {ring_max_frames},
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
      "ring_max_frames": {ring_max_frames},
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
      "ring_max_frames": {ring_max_frames},
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

type DriverMap = BTreeMap<SensorId, Box<dyn SensorDriver>>;
type ControlMap = BTreeMap<String, Arc<SyntheticCameraControl>>;

fn wire_synthetic_drivers(manifest: &SiteManifest) -> (DriverMap, ControlMap) {
    let mut drivers: BTreeMap<SensorId, Box<dyn SensorDriver>> = BTreeMap::new();
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

#[test]
fn multi_camera_supervision_corroboration_shared_domain_and_sub_500ms_ipc() -> TestResult {
    let dir = TempDirGuard::new("multi-cam")?;
    let manifest = SiteManifest::parse_json(&three_camera_manifest_json(
        dir.path(),
        64 * 1024 * 1024,
        64,
    ))?;
    let (drivers, controls) = wire_synthetic_drivers(&manifest);

    let perception_cfg = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };

    let t_base: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest.clone());
    cfg.custom_drivers = drivers;
    cfg.perception_config = perception_cfg;
    cfg.started_at_ns = t_base;
    cfg.enable_ipc = true;

    let mut supervisor = DaemonSupervisor::start(cfg)?;

    // Verify exactly 1 upstream session per camera.
    let views = supervisor.camera_views();
    assert_eq!(views.len(), 3);
    for view in views.values() {
        assert_eq!(view.state, SensorState::Connecting);
        assert_eq!(view.active_sessions, 1);
        assert_eq!(view.peak_concurrent_sessions, 1);
        assert_eq!(view.total_connections, 1);
    }
    assert_eq!(supervisor.active_tasks(), 6);
    assert_eq!(supervisor.leaked_obligations(), 6);

    let ctrl_39 = controls.get("sensor:wyze-39").ok_or("missing wyze-39")?;
    let ctrl_51 = controls.get("sensor:wyze-51").ok_or("missing wyze-51")?;
    let ctrl_177 = controls
        .get("sensor:unifi-g4-177")
        .ok_or("missing unifi-g4-177")?;

    // Warm up Stage-1 background model with 2 quiescent ticks.
    let _ = supervisor.step_tick(t_base + 100_000_000)?;
    let _ = supervisor.step_tick(t_base + 200_000_000)?;

    // OSD-only changes inside ignore rect (0,0,8,4) must produce ZERO corroborations.
    let osd_rect = ImageRect::new(0, 0, 8, 4)?;
    for ctrl in [ctrl_39, ctrl_51, ctrl_177] {
        ctrl.push_spec(SyntheticFrameSpec::OsdOnlyTick {
            osd_rect,
            luma_value: 240,
            is_keyframe: false,
        });
    }
    let osd_tick = supervisor.step_tick(t_base + 300_000_000)?;
    assert_eq!(osd_tick.corroborated_events, 0);
    assert_eq!(osd_tick.shared_domain_held_events, 0);

    // Shared-WiFi pair (wyze-39 + wyze-51) MUST honestly withhold corroboration (SharedFailureDomainHeld).
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    ctrl_39.inject_motion(motion_rect, "person", 920_000, None, 101);
    ctrl_51.inject_motion(motion_rect, "person", 920_000, None, 102);
    let shared_tick = supervisor.step_tick(t_base + 400_000_000)?;
    assert_eq!(shared_tick.corroborated_events, 0);
    assert!(
        shared_tick.shared_domain_held_events >= 1,
        "expected SharedFailureDomainHeld for shared WiFi pair"
    );
    let shared_decision = shared_tick
        .decisions
        .iter()
        .find(|d| {
            matches!(
                d.outcome,
                CorroborationOutcome::SharedFailureDomainHeld { .. }
            )
        })
        .ok_or("missing SharedFailureDomainHeld decision")?;
    if let CorroborationOutcome::SharedFailureDomainHeld {
        shared_domains,
        event,
        policy_action,
        ..
    } = &shared_decision.outcome
    {
        assert!(shared_domains.contains("wifi:home-2g"));
        assert_eq!(event.state, EventState::Indeterminate);
        assert_eq!(*policy_action, ReferencePolicyAction::Hold);
    }

    // Advance past sliding window so next test isolates independent cluster corroboration.
    // Because the 11.6s jump exceeds stall_timeout_ms, take two contiguous ticks to re-establish
    // observed two-sample continuity before attaching the live IPC corroboration subscriber.
    let t_indep = t_base + 12_000_000_000;
    let _ = supervisor.step_tick(t_indep)?;
    let _ = supervisor.step_tick(t_indep + 100_000_000)?;
    for view in supervisor.camera_views().values() {
        assert_eq!(view.state, SensorState::Streaming);
    }

    // Start live fss-ipc SubscribeDeltas client BEFORE triggering independent multi-camera motion.
    let head_before = supervisor.storage().head_snapshot()?.commit_sequence;
    let descriptor = DaemonRuntimeDescriptor::read_from_root(dir.path())?;
    let ipc_root = dir.path().to_path_buf();
    let sub_thread = thread::spawn(
        move || -> Result<(Duration, Vec<(u64, DeltaEventSummary)>), String> {
            let mut client = IpcClient::connect(IpcClientConfig {
                deployment_root: ipc_root,
                deployment_id: descriptor.site_id,
                contract_basis_digest: descriptor.contract_basis_digest,
                principal: PrincipalId::parse("principal:local-agent")
                    .map_err(|e| e.to_string())?,
                capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
                io_timeout: Duration::from_secs(3),
            })
            .map_err(|e| e.to_string())?;
            let req_id = client.next_request_id();
            let started = Instant::now();
            let mut received = Vec::new();
            let sub = client
                .subscribe_deltas(req_id, head_before, 4)
                .map_err(|e| e.to_string())?;
            for item in sub {
                match item.map_err(|e| e.to_string())? {
                    DeltaSubscriptionItem::Event {
                        commit_sequence,
                        summary_canonical,
                        ..
                    } => {
                        if let Ok(summary) =
                            DeltaEventSummary::from_canonical_bytes(&summary_canonical)
                        {
                            let is_corr = summary.delta_class == MeaningfulDeltaClass::Hypothesis
                                && summary.summary.contains("corroborated");
                            received.push((commit_sequence, summary));
                            if is_corr {
                                break;
                            }
                        }
                    }
                    DeltaSubscriptionItem::End { .. } => break,
                }
            }
            let elapsed = started.elapsed();
            Ok((elapsed, received))
        },
    );

    // Brief yield so subscriber attaches cleanly before event commit.
    thread::sleep(Duration::from_millis(25));

    // Independent clusters: wyze-51 (wifi:home-2g) + unifi-g4-177 (poe:switch-1 + power:ups-rack).
    let emit_instant = Instant::now();
    ctrl_51.inject_motion(motion_rect, "person", 930_000, None, 201);
    ctrl_177.inject_motion(motion_rect, "person", 940_000, None, 202);
    let corr_tick = supervisor.step_tick(t_indep + 200_000_000)?;
    assert!(
        corr_tick.corroborated_events >= 1,
        "independent clusters wyze-51 + unifi-g4-177 must corroborate"
    );
    let corr_decision = corr_tick
        .decisions
        .iter()
        .find(|d| matches!(d.outcome, CorroborationOutcome::Corroborated { .. }))
        .ok_or("missing Corroborated decision")?;
    if let CorroborationOutcome::Corroborated {
        supporting_clusters,
        event,
        policy_action,
        alert_eligible,
        ..
    } = &corr_decision.outcome
    {
        assert!(*supporting_clusters >= 2);
        assert_eq!(event.state, EventState::Corroborated);
        assert_eq!(*policy_action, ReferencePolicyAction::PrepareAlert);
        assert!(*alert_eligible);
    }

    let (sub_elapsed, received) = sub_thread
        .join()
        .map_err(|_| "subscriber thread panicked")?
        .map_err(|e| format!("subscriber failed: {e}"))?;
    let notification_ms = emit_instant.elapsed().as_millis();
    assert!(
        notification_ms < 500,
        "IPC corroboration notification took {notification_ms} ms (>= 500 ms budget)"
    );
    assert!(
        sub_elapsed < Duration::from_millis(600),
        "subscribe_deltas round-trip exceeded budget: {sub_elapsed:?}"
    );
    assert!(
        received.iter().any(|(_, s)| {
            s.delta_class == MeaningfulDeltaClass::Hypothesis
                && s.priority == DeltaPriority::High
                && s.summary.contains("corroborated")
        }),
        "expected High-priority Hypothesis corroboration delta over IPC, got: {received:?}"
    );

    // Model pool loaded weights strictly ONCE (zero reloads across 3 cameras).
    assert_eq!(supervisor.perception().pool_metrics().loads, 1);

    // Structured JSONL telemetry contains required fields and zero secrets.
    let telemetry_lines = supervisor.telemetry_jsonl();
    assert!(!telemetry_lines.is_empty());
    let sensor_line = telemetry_lines
        .iter()
        .find(|line| line.contains("\"schema\":\"fss.daemon_telemetry.v1\""))
        .ok_or("missing sensor JSONL telemetry line")?;
    for required_field in [
        "\"sensor_id\":",
        "\"state\":",
        "\"fps_in\":",
        "\"fps_decode\":",
        "\"ingest_lag_ms\":",
        "\"queue_depth\":",
        "\"dropped_frames\":",
        "\"reconnects\":",
        "\"pack_mb\":",
        "\"pressure\":",
        "\"corroborated_events\":",
        "\"active_tasks\":",
    ] {
        assert!(
            sensor_line.contains(required_field),
            "telemetry line missing {required_field}: {sensor_line}"
        );
    }

    // Verify single upstream session invariant held throughout.
    for view in supervisor.camera_views().values() {
        assert_eq!(view.peak_concurrent_sessions, 1);
    }

    let shutdown = supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    eprintln!(
        "METRIC multi_camera: ipc_corroboration_ms={notification_ms} sub_roundtrip_ms={} drain_ms={} active_tasks={} leaked_obligations={} head_seq={}",
        sub_elapsed.as_millis(),
        shutdown.drain_duration_ms,
        shutdown.active_tasks,
        shutdown.leaked_obligations,
        shutdown.head_commit_sequence,
    );
    Ok(())
}

#[test]
fn camera_disconnect_emits_explicit_gap_and_backoff_recovers_new_generation() -> TestResult {
    let dir = TempDirGuard::new("disconnect")?;
    let manifest = SiteManifest::parse_json(&three_camera_manifest_json(
        dir.path(),
        64 * 1024 * 1024,
        64,
    ))?;
    let (drivers, controls) = wire_synthetic_drivers(&manifest);

    let t0: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.started_at_ns = t0;
    cfg.enable_ipc = false;

    let mut supervisor = DaemonSupervisor::start(cfg)?;
    let _ = supervisor.step_tick(t0 + 100_000_000)?;
    let _ = supervisor.step_tick(t0 + 200_000_000)?;

    let wyze_39_id = SensorId::parse("sensor:wyze-39")?;
    let wyze_51_id = SensorId::parse("sensor:wyze-51")?;
    let unifi_177_id = SensorId::parse("sensor:unifi-g4-177")?;
    let ctrl_39 = controls.get("sensor:wyze-39").ok_or("missing wyze-39")?;

    // Kill wyze-39 mid-stream.
    ctrl_39.kill_camera(SensorDisconnectReason::NetworkDrop);
    let drop_tick = supervisor.step_tick(t0 + 300_000_000)?;
    assert!(drop_tick.coverage_gaps_emitted >= 1);

    let views_after_drop = supervisor.camera_views();
    let v39 = views_after_drop.get(&wyze_39_id).ok_or("missing v39")?;
    let v51 = views_after_drop.get(&wyze_51_id).ok_or("missing v51")?;
    let v177 = views_after_drop.get(&unifi_177_id).ok_or("missing v177")?;
    assert_eq!(v39.state, SensorState::GapBackoff);
    assert_eq!(v39.active_sessions, 0);
    assert_eq!(v51.state, SensorState::Streaming);
    assert_eq!(v177.state, SensorState::Streaming);

    // Explicit CoverageGap (`NotObservable`) immediately materialized in MVCC projection.
    let snap = supervisor.storage().projection().snapshot_latest();
    let cov39 = supervisor
        .storage()
        .projection()
        .query_coverage(&snap, Some(&wyze_39_id), None);
    assert_eq!(cov39.len(), 1);
    assert_eq!(cov39[0].status, CoverageStatus::NotObservable);
    assert!(cov39[0].active_gaps >= 1);

    // Before backoff window expires, no zero-delay reconnect storm occurs; other 2 cameras continue.
    let before_ingested_51 = v51.frames_ingested;
    let before_ingested_177 = v177.frames_ingested;
    let _ = supervisor.step_tick(t0 + 350_000_000)?;
    let mid_views = supervisor.camera_views();
    assert_eq!(
        mid_views.get(&wyze_39_id).ok_or("missing v39")?.state,
        SensorState::GapBackoff
    );
    assert!(
        mid_views
            .get(&wyze_51_id)
            .ok_or("missing v51")?
            .frames_ingested
            > before_ingested_51
    );
    assert!(
        mid_views
            .get(&unifi_177_id)
            .ok_or("missing v177")?
            .frames_ingested
            > before_ingested_177
    );

    // Restore camera and advance past bounded backoff window -> fresh generation 2 opens cleanly.
    ctrl_39.restore_camera();
    let rec_tick = supervisor.step_tick(t0 + 1_500_000_000)?;
    assert_eq!(rec_tick.reconnects_completed, 1);

    let recovered_views = supervisor.camera_views();
    let v39_rec = recovered_views.get(&wyze_39_id).ok_or("missing v39")?;
    assert_eq!(v39_rec.state, SensorState::Connecting);
    assert_eq!(v39_rec.stream_generation, 2);
    assert_eq!(v39_rec.active_sessions, 1);
    assert_eq!(v39_rec.peak_concurrent_sessions, 1);
    assert_eq!(v39_rec.total_connections, 2);

    let snap2 = supervisor.storage().projection().snapshot_latest();
    let cov39_rec =
        supervisor
            .storage()
            .projection()
            .query_coverage(&snap2, Some(&wyze_39_id), None);
    assert_eq!(cov39_rec[0].status, CoverageStatus::NotObservable);
    assert!(cov39_rec[0].active_gaps >= 1);

    // A second contiguous frame, rather than successful connect, proves readiness.
    let _ = supervisor.step_tick(t0 + 1_600_000_000)?;
    let ready_views = supervisor.camera_views();
    assert_eq!(
        ready_views.get(&wyze_39_id).ok_or("missing v39")?.state,
        SensorState::Streaming
    );
    let ready_snap = supervisor.storage().projection().snapshot_latest();
    let ready_cov = supervisor
        .storage()
        .projection()
        .query_coverage(&ready_snap, Some(&wyze_39_id), None);
    assert_eq!(ready_cov[0].status, CoverageStatus::Covered);
    assert_eq!(ready_cov[0].active_gaps, 0);

    let shutdown = supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    Ok(())
}

#[test]
fn slow_consumer_backpressure_sheds_deterministically_with_bounded_ring_ram() -> TestResult {
    let dir = TempDirGuard::new("backpressure")?;
    let ring_max_frames = 6_usize;
    let manifest = SiteManifest::parse_json(&three_camera_manifest_json(
        dir.path(),
        64 * 1024 * 1024,
        ring_max_frames,
    ))?;
    let (drivers, controls) = wire_synthetic_drivers(&manifest);

    let t0: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.started_at_ns = t0;
    cfg.enable_ipc = false;

    let mut supervisor = DaemonSupervisor::start(cfg)?;
    let wyze_39_id = SensorId::parse("sensor:wyze-39")?;
    assert!(supervisor.set_ingest_consumer_paused(&wyze_39_id, true));

    let ctrl_39 = controls.get("sensor:wyze-39").ok_or("missing wyze-39")?;
    for _ in 0..24 {
        ctrl_39.push_spec(SyntheticFrameSpec::Quiescent { is_keyframe: false });
    }
    let burst_tick = supervisor.step_tick(t0 + 100_000_000)?;
    assert!(burst_tick.frames_shed >= 18);
    assert!(burst_tick.coverage_gaps_emitted >= 1);

    let views = supervisor.camera_views();
    let v39 = views.get(&wyze_39_id).ok_or("missing v39")?;
    assert!(v39.ring.dropped_frames >= 18);
    assert!(v39.ring.peak_frames <= ring_max_frames);
    assert!(v39.ring.peak_bytes <= 32_768);
    assert!(v39.ring.pressure >= ResourcePressure::Elevated);

    let shutdown = supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    Ok(())
}

#[test]
fn disk_critical_pinned_quota_pauses_ingest_without_evicting_holds() -> TestResult {
    let dir = TempDirGuard::new("quota-pinned")?;
    let cap_bytes = 8_192_u64;
    let manifest =
        SiteManifest::parse_json(&three_camera_manifest_json(dir.path(), cap_bytes, 64))?;
    let (drivers, controls) = wire_synthetic_drivers(&manifest);

    let t0: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.started_at_ns = t0;
    cfg.enable_ipc = false;

    let mut supervisor = DaemonSupervisor::start(cfg)?;
    let held_import_id = "gop:held-insurance-001".to_owned();
    supervisor
        .storage_mut()
        .register_retention_candidate(RetentionCandidate {
            import_id: held_import_id.clone(),
            sensor_id: "sensor:wyze-39".to_owned(),
            capture_end_ns: TimestampNs(t0),
            byte_size: cap_bytes,
            object_digests: vec![ContentDigest::sha256(b"held-closure-payload")],
            is_derived_proxy: false,
            held_by: vec!["hold:insurance-claim-001".to_owned()],
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        })?;

    // Tick 1 detects 100%-pinned Critical capacity and transitions honestly to paused ingest.
    let tick1 = supervisor.step_tick(t0 + 100_000_000)?;
    assert!(tick1.quota_pinned);
    assert_eq!(tick1.pressure, CapacityPressure::Critical);
    assert_eq!(
        supervisor.storage().ingest_paused_reason(),
        Some(ERR_STORAGE_QUOTA_PINNED_001)
    );
    assert!(
        supervisor
            .storage()
            .retention_candidates()
            .contains_key(&held_import_id),
        "held closure must NEVER be evicted under quota pressure"
    );

    // Tick 2 pauses new non-critical frame ingest cleanly while keeping held closure intact.
    let tick2 = supervisor.step_tick(t0 + 200_000_000)?;
    assert!(tick2.quota_pinned);
    assert_eq!(tick2.frames_committed, 0);
    assert!(
        supervisor
            .storage()
            .retention_candidates()
            .contains_key(&held_import_id)
    );

    // Tick 1 admitted source frames before capacity became pinned. A shutdown cannot
    // certify success while those frames remain buffered and cannot be published.
    let shutdown = supervisor.shutdown_graceful();
    assert!(
        matches!(shutdown, Err(DaemonError::StorageQuotaPinned { .. })),
        "unpublished source custody must prevent a clean shutdown receipt: {shutdown:?}"
    );
    for control in controls.values() {
        assert_eq!(
            control.active_session_count(),
            0,
            "a storage shutdown refusal must still disconnect every source"
        );
    }
    Ok(())
}

#[test]
fn graceful_ipc_stop_executes_request_drain_finalize_and_verifies_ledger() -> TestResult {
    let dir = TempDirGuard::new("ipc-stop")?;
    let root = dir.path().to_path_buf();
    let manifest =
        SiteManifest::parse_json(&three_camera_manifest_json(&root, 64 * 1024 * 1024, 64))?;
    let (drivers, _controls) = wire_synthetic_drivers(&manifest);

    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.enable_ipc = true;

    let supervisor = DaemonSupervisor::start(cfg)?;
    let runner = thread::spawn(move || {
        supervisor
            .run_until_stopped(None, Duration::from_millis(15))
            .map_err(|e| e.to_string())
    });

    // Wait briefly for first tick & UDS readiness.
    thread::sleep(Duration::from_millis(60));

    let op_principal = PrincipalId::parse("principal:local-operator")?;
    let (desc, status) = query_live_daemon_status(&root, None, op_principal.clone())?;
    assert_eq!(desc.site_id, "site-home-east");
    assert_eq!(status.cameras.len(), 3);
    assert!(status.head_commit_sequence >= 3);

    // Wrong shutdown approval digest MUST be refused fail-closed.
    let mut bad_client = IpcClient::connect(IpcClientConfig {
        deployment_root: root.clone(),
        deployment_id: desc.site_id.clone(),
        contract_basis_digest: desc.contract_basis_digest,
        principal: op_principal.clone(),
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(3),
    })?;
    let bad_req = bad_client.next_request_id();
    let bad_resp = bad_client.submit_bounded_control(
        bad_req,
        BoundedControlOp::StopCamera,
        Some(fss_daemon::DAEMON_STOP_TARGET.to_owned()),
        ContentDigest::sha256(b"wrong-approval"),
    )?;
    match bad_resp {
        IpcResponse::Refused { error_id, .. } => {
            assert_eq!(error_id.as_str(), ERR_DAEMON_CONTROL_APPROVAL_001);
        }
        other => return Err(format!("expected refusal for wrong approval, got {other:?}").into()),
    }
    drop(bad_client);

    // Issue authorized graceful stop over fss-ipc UDS.
    let (_stop_desc, op_id, _state) = request_live_daemon_stop(&root, None, op_principal)?;
    assert!(!op_id.as_str().is_empty());

    let shutdown = runner.join().map_err(|_| "daemon thread panicked")??;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    assert!(shutdown.closed_regions >= 8);
    assert!(shutdown.verified_batches >= 3);
    assert!(shutdown.storage_summary.projection_snapshot_bytes > 0);
    assert!(
        !default_socket_path(&root).exists(),
        "daemon.sock must be removed on graceful shutdown"
    );

    // Re-open ledger strictly rejecting incomplete tails to prove zero incomplete tails on disk.
    let reopened = MerkleEpochLedger::open(
        root.join("ledger"),
        "site-home-east",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(reopened.commit_sequence(), shutdown.head_commit_sequence);
    let _ = reopened.verify_full_chain()?;
    Ok(())
}

#[test]
fn plaintext_secret_in_site_manifest_refused_fail_closed() -> TestResult {
    let secret = "SuperSecretPass99";
    let cases = [
        // 1. Inline RTSP URL userinfo credentials.
        format!(
            r#"{{"schema":"fss.site_manifest.v1","site_id":"site-1","cameras":[{{"sensor_id":"sensor:wyze-51","adapter":"rtsp","endpoint":"rtsp://admin:{secret}@192.168.1.51/stream1"}}]}}"#
        ),
        // 2. Credential-bearing query parameter.
        format!(
            r#"{{"schema":"fss.site_manifest.v1","site_id":"site-1","cameras":[{{"sensor_id":"sensor:onvif-1","adapter":"onvif_http","endpoint":"http://192.168.1.51/mjpg?password={secret}"}}]}}"#
        ),
        // 3. Forbidden plaintext password key.
        format!(
            r#"{{"schema":"fss.site_manifest.v1","site_id":"site-1","cameras":[{{"sensor_id":"sensor:wyze-51","adapter":"rtsp","endpoint":"rtsp://192.168.1.51/stream1","password":"{secret}"}}]}}"#
        ),
    ];

    for (idx, raw) in cases.iter().enumerate() {
        let err = match SiteManifest::parse_json(raw) {
            Ok(_) => return Err(format!("case {idx} should have rejected plaintext secret").into()),
            Err(e) => e,
        };
        assert_eq!(err.error_id(), ERR_DAEMON_SECRET_IN_MANIFEST_001);
        assert!(matches!(err, DaemonError::SecretInManifest { .. }));
        assert!(
            !err.to_string().contains(secret),
            "error message leaked plaintext secret in case {idx}: {err}"
        );
    }
    Ok(())
}
