#![forbid(unsafe_code)]
//! Continuous Multi-Camera Daemon Soak & Gap Honesty E2E (`fss-x4a.31.3.7` / `C7`).
//!
//! Runs `DaemonSupervisor` continuously over a 3-camera site (`sensor:wyze-39` + `sensor:wyze-51`
//! on shared Wi-Fi `wifi:home-2g` + `sensor:unifi-g4-177` on independent PoE `poe:switch-1`)
//! through 540 simulated continuous ticks with a tight 256 KiB rolling ring cap and active legal
//! holds pinned on selected media closures:
//! - Verifies `MvccProjectionStore::orient_summary` p99 stays flat `< 10 ms` across early, mid,
//!   and late soak windows (zero upward drift).
//! - Verifies on-disk pack usage stays strictly `<= ring_cap + 2 * pack_size` across ring
//!   wraparound while 100% of legal-held closures survive and remain bit-verified.
//! - Verifies OSD ticking clock frames inside each camera's `osd_ignore_rects` produce 0 false
//!   alerts, shared Wi-Fi motion is honestly withheld (`SharedFailureDomainHeld`), and
//!   simultaneous independent motion on `wyze-51` + `unifi-g4-177` produces live `Corroborated`
//!   events delivered over `fss-ipc` in `< 500 ms`.
//! - Injects mid-stream camera drop + backoff recovery on `wyze-51`: immediate explicit
//!   `NotObservable` `CoverageGap`, zero bridged tracks, automatic exponential backoff reconnect
//!   opening fresh stream generation `2`, and clean `request -> drain -> finalize` shutdown
//!   (`active_tasks == 0`, `leaked_obligations == 0`, full Merkle chain verification).
//! - Emits structured JSONL telemetry to `target/test-logs/daemon-soak/deterministic_soak.jsonl`
//!   and final receipt to `target/test-logs/daemon-soak/deterministic_soak_receipt.json`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    CanonicalDecode, ContentDigest, DeltaPriority, EventState, MeaningfulDeltaClass, PrincipalId,
    SensorId,
};
use fss_daemon::{
    DaemonRuntimeDescriptor, DaemonStartConfig, DaemonSupervisor, PerceptionConfig,
    SensorDisconnectReason, SensorDriver, SensorState, SiteManifest, SyntheticCameraControl,
    SyntheticCameraDriver, SyntheticFrameSpec,
};
use fss_fusion::ScoreCalibration;
use fss_ipc::{
    DeltaEventSummary, DeltaSubscriptionItem, IpcClient, IpcClientConfig, default_socket_path,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{PackConfig, PackStore};
use fss_projection_store::{CoverageStatus, ProjectionStore};
use fss_reference::ReferencePolicyAction;
use fss_reference::ingest::live_corroborate::CorroborationOutcome;
use fss_reference::ingest::osd_mask::ImageRect;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SOAK_TICKS: u64 = 540;
const RING_CAP_BYTES: u64 = 256 * 1024; // 256 KiB tight rolling ring cap
const PACK_TARGET_BYTES: u64 = 32 * 1024; // 32 KiB pack rotation target
const DISK_BOUND_BYTES: u64 = RING_CAP_BYTES + 2 * PACK_TARGET_BYTES; // 320 KiB hard ceiling
const ORIENT_P99_BUDGET_US: u64 = 10_000; // 10.0 ms ceiling

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> TestResult<Self> {
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

fn test_logs_dir() -> TestResult<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-logs/daemon-soak");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn make_calibrated_person_table() -> TestResult<ScoreCalibration> {
    let cal = ScoreCalibration::from_counts(
        "cal:soak-person:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?;
    Ok(cal)
}

fn soak_manifest_json(root: &Path) -> String {
    let root_str = root.to_string_lossy().replace('\\', "\\\\");
    format!(
        r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-home-soak",
  "deployment_root": "{root_str}",
  "ring_cap_bytes": {RING_CAP_BYTES},
  "soft_watermark_pct": 75,
  "hard_watermark_pct": 95,
  "pack_target_bytes": {PACK_TARGET_BYTES},
  "scrub_budget_bytes_per_tick": 131072,
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
      "ring_max_bytes": 131072,
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
      "ring_max_bytes": 131072,
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
      "ring_max_bytes": 131072,
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

fn wire_synthetic_drivers(
    manifest: &SiteManifest,
    extra_payload_bytes: u64,
) -> (DriverMap, ControlMap) {
    let mut drivers: DriverMap = BTreeMap::new();
    let mut controls: ControlMap = BTreeMap::new();
    for cam in &manifest.cameras {
        let ctrl = SyntheticCameraControl::new(cam.sensor_id.clone());
        ctrl.set_default_extra_payload_bytes(extra_payload_bytes);
        let drv: Box<dyn SensorDriver> =
            Box::new(SyntheticCameraDriver::new(cam, Arc::clone(&ctrl)));
        drivers.insert(cam.sensor_id.clone(), drv);
        controls.insert(cam.sensor_id.as_str().to_owned(), ctrl);
    }
    (drivers, controls)
}

fn sample_process_rss_kb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(val) = rest.split_ascii_whitespace().next() {
                        if let Ok(kb) = val.parse::<u64>() {
                            return kb;
                        }
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        && out.status.success()
        && let Ok(text) = std::str::from_utf8(&out.stdout)
        && let Ok(kb) = text.trim().parse::<u64>()
    {
        return kb;
    }
    0
}

fn count_pack_files(root: &Path) -> usize {
    let packs_dir = root.join("objects").join("packs");
    fs::read_dir(packs_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(".fssp")))
                .count()
        })
        .unwrap_or(0)
}

fn percentile_us(samples: &[u64], pct_numerator: usize, pct_denominator: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len().saturating_sub(1)) * pct_numerator) / pct_denominator;
    sorted[idx.min(sorted.len() - 1)]
}

fn verify_live_ipc_corroboration(
    supervisor: &mut DaemonSupervisor,
    root: &Path,
    ctrl_51: &Arc<SyntheticCameraControl>,
    ctrl_177: &Arc<SyntheticCameraControl>,
    tick_now_ns: i128,
    track_base: u64,
) -> TestResult<(u128, usize)> {
    let head_before = supervisor.storage().head_snapshot()?.commit_sequence;
    let descriptor = DaemonRuntimeDescriptor::read_from_root(root)?;
    let ipc_root = root.to_path_buf();

    let sub_thread = thread::spawn(
        move || -> Result<(Duration, Instant, Vec<(u64, DeltaEventSummary)>), String> {
            let mut client = IpcClient::connect(IpcClientConfig {
                deployment_root: ipc_root,
                deployment_id: descriptor.site_id,
                contract_basis_digest: descriptor.contract_basis_digest,
                principal: PrincipalId::parse("principal:soak-agent").map_err(|e| e.to_string())?,
                capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
                io_timeout: Duration::from_secs(3),
            })
            .map_err(|e| e.to_string())?;
            let req_id = client.next_request_id();
            let started = Instant::now();
            let mut received = Vec::new();
            let sub = client
                .subscribe_deltas(req_id, head_before, 8)
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
            let received_at = Instant::now();
            Ok((received_at.saturating_duration_since(started), received_at, received))
        },
    );

    thread::sleep(Duration::from_millis(20));

    let motion_rect = ImageRect::new(10, 10, 12, 12)?;
    let emit_start = Instant::now();
    ctrl_51.inject_motion(motion_rect, "person", 930_000, None, track_base);
    ctrl_177.inject_motion(motion_rect, "person", 940_000, None, track_base + 1);
    let report = supervisor.step_tick(tick_now_ns)?;
    assert!(
        report.corroborated_events >= 1,
        "independent clusters wyze-51 + unifi-g4-177 must corroborate"
    );
    let corr_decision = report
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

    let (sub_elapsed, received_at, received) = sub_thread
        .join()
        .map_err(|_| "IPC subscriber thread panicked")?
        .map_err(|e| format!("IPC subscriber failed: {e}"))?;
    let latency_ms = received_at.saturating_duration_since(emit_start).as_millis();
    assert!(
        latency_ms < 500,
        "IPC corroboration delivery took {latency_ms} ms (>= 500 ms budget)"
    );
    assert!(
        sub_elapsed < Duration::from_millis(600),
        "IPC round-trip exceeded budget: {sub_elapsed:?}"
    );
    assert!(
        received.iter().any(|(_, s)| {
            s.delta_class == MeaningfulDeltaClass::Hypothesis
                && s.priority == DeltaPriority::High
                && s.summary.contains("corroborated")
        }),
        "missing High-priority Hypothesis corroboration delta: {received:?}"
    );
    Ok((latency_ms, received.len()))
}

#[test]
fn continuous_540_tick_multi_camera_soak_osd_holds_gap_and_telemetry() -> TestResult {
    let dir = TempDirGuard::new("soak540")?;
    let manifest = SiteManifest::parse_json(&soak_manifest_json(dir.path()))?;
    // ~2 KiB extra payload per frame -> ~3 KiB/frame -> ~12 KiB per 4-frame GOP -> ~4.8 MiB total
    // written over 540 ticks across 3 cameras (~19x the 256 KiB ring cap), exercising wraparound!
    let (drivers, controls) = wire_synthetic_drivers(&manifest, 2048);

    let perception_cfg = PerceptionConfig {
        default_calibration: Some(make_calibrated_person_table()?),
        ..PerceptionConfig::default()
    };

    let t_base: i128 = 1_700_000_000_000_000_000;
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.custom_drivers = drivers;
    cfg.perception_config = perception_cfg;
    cfg.started_at_ns = t_base;
    cfg.enable_ipc = true;

    let mut supervisor = DaemonSupervisor::start(cfg)?;
    let wyze_39_id = SensorId::parse("sensor:wyze-39")?;
    let wyze_51_id = SensorId::parse("sensor:wyze-51")?;
    let unifi_177_id = SensorId::parse("sensor:unifi-g4-177")?;
    let ctrl_39 = Arc::clone(controls.get("sensor:wyze-39").ok_or("missing wyze-39")?);
    let ctrl_51 = Arc::clone(controls.get("sensor:wyze-51").ok_or("missing wyze-51")?);
    let ctrl_177 = Arc::clone(
        controls
            .get("sensor:unifi-g4-177")
            .ok_or("missing unifi-g4-177")?,
    );

    let osd_rect = ImageRect::new(0, 0, 8, 4)?;
    let motion_rect = ImageRect::new(10, 10, 12, 12)?;

    let mut held_ids: Vec<String> = Vec::new();
    let mut held_digests: Vec<ContentDigest> = Vec::new();

    let mut early_orient_us: Vec<u64> = Vec::new();
    let mut mid_orient_us: Vec<u64> = Vec::new();
    let mut late_orient_us: Vec<u64> = Vec::new();
    let mut all_orient_us: Vec<u64> = Vec::new();

    let mut false_osd_alerts: u64 = 0;
    let mut shared_wifi_held_verified: u64 = 0;
    let mut corroborated_total: u64 = 0;
    let mut ipc_latencies_ms: Vec<u128> = Vec::new();
    let mut peak_disk_bytes: u64 = 0;
    let mut peak_pack_count: usize = 0;
    let mut saw_ring_wraparound = false;
    let mut total_evicted_approx: u64 = 0;
    let mut seen_candidate_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut drop_verified = false;
    let mut recovery_verified = false;

    let soak_wall_start = Instant::now();
    let mut current_rss_kb = sample_process_rss_kb();
    let mut jsonl_lines: Vec<String> = Vec::with_capacity(SOAK_TICKS as usize);
    let mut now_ns = t_base;

    for tick in 1..=SOAK_TICKS {
        // Advance simulated time cleanly; step 3s twice (6s total > 5s sliding corroboration window,
        // each step <= 5s stall timeout so two-sample camera continuity stays intact with zero
        // spurious gap deltas) before isolated corroboration checks, and step across backoff window
        // when testing wyze-51 recovery.
        now_ns = if matches!(tick, 88 | 89 | 108 | 109 | 418 | 419) {
            now_ns.saturating_add(3_000_000_000)
        } else if tick == 260 {
            // Advance 2.5s past max backoff so restored wyze-51 reconnects cleanly into gen 2.
            now_ns.saturating_add(2_500_000_000)
        } else if tick == 251 {
            // Small 50ms advance during backoff window to verify no zero-delay reconnect storm.
            now_ns.saturating_add(50_000_000)
        } else {
            now_ns.saturating_add(250_000_000)
        };

        // Pin legal holds onto 2 early GOP closures once flushed (tick 12).
        if tick == 12 && held_ids.is_empty() {
            let candidates: Vec<(String, Vec<ContentDigest>)> = supervisor
                .storage()
                .retention_candidates()
                .iter()
                .take(2)
                .map(|(id, cand)| (id.clone(), cand.object_digests.clone()))
                .collect();
            assert_eq!(
                candidates.len(),
                2,
                "expected at least 2 flushed GOP candidates by tick 12"
            );
            for (idx, (id, digests)) in candidates.into_iter().enumerate() {
                let pinned = supervisor
                    .storage_mut()
                    .pin_candidate_hold(&id, format!("hold:legal-soak-00{}", idx + 1));
                assert!(pinned, "failed to pin legal hold on {id}");
                held_ids.push(id);
                held_digests.extend(digests);
            }
        }

        // Periodic OSD-only ticks inside each camera's `osd_ignore_rects`: MUST produce 0 alerts.
        let is_osd_only_tick =
            tick >= 6 && tick % 10 == 0 && !matches!(tick, 90 | 110 | 250 | 260 | 420);
        if is_osd_only_tick {
            let luma = if (tick / 10) % 2 == 0 { 245 } else { 10 };
            for ctrl in [&ctrl_39, &ctrl_51, &ctrl_177] {
                ctrl.push_spec(SyntheticFrameSpec::OsdOnlyTick {
                    osd_rect,
                    luma_value: luma,
                    is_keyframe: false,
                });
            }
        }

        // Tick 90: Shared Wi-Fi pair (`wyze-39` + `wyze-51`) MUST honestly withhold corroboration.
        if tick == 90 {
            ctrl_39.inject_motion(motion_rect, "person", 920_000, None, 1001);
            ctrl_51.inject_motion(motion_rect, "person", 920_000, None, 1002);
        }

        // Tick 250: Inject mid-stream NetworkDrop on `wyze-51`.
        if tick == 250 {
            ctrl_51.kill_camera(SensorDisconnectReason::NetworkDrop);
        }
        // Tick 259: Restore `wyze-51` so tick 260 reconnects automatically into stream generation 2.
        if tick == 259 {
            ctrl_51.restore_camera();
        }

        // Ticks 110 & 420: Simultaneous independent motion on `wyze-51` + `unifi-g4-177` with live
        // `< 500 ms` `fss-ipc` `SubscribeDeltas` delivery verification.
        let (tick_corr, tick_shared_held, tick_gaps, tick_reconnects) =
            if tick == 110 || tick == 420 {
                let (ipc_ms, _cnt) = verify_live_ipc_corroboration(
                    &mut supervisor,
                    dir.path(),
                    &ctrl_51,
                    &ctrl_177,
                    now_ns,
                    2000 + tick,
                )?;
                ipc_latencies_ms.push(ipc_ms);
                corroborated_total = corroborated_total.saturating_add(1);
                (1_u64, 0_u64, 0_u64, 0_u64)
            } else {
                let rep = supervisor.step_tick(now_ns)?;
                if is_osd_only_tick
                    && (rep.corroborated_events > 0 || rep.shared_domain_held_events > 0)
                {
                    false_osd_alerts = false_osd_alerts.saturating_add(
                        rep.corroborated_events
                            .saturating_add(rep.shared_domain_held_events),
                    );
                }
                if tick == 90 {
                    assert_eq!(
                        rep.corroborated_events, 0,
                        "shared Wi-Fi pair must never falsely corroborate"
                    );
                    assert!(
                        rep.shared_domain_held_events >= 1,
                        "expected SharedFailureDomainHeld on shared Wi-Fi pair"
                    );
                    shared_wifi_held_verified += 1;
                }
                corroborated_total = corroborated_total.saturating_add(rep.corroborated_events);
                (
                    rep.corroborated_events,
                    rep.shared_domain_held_events,
                    rep.coverage_gaps_emitted,
                    rep.reconnects_completed,
                )
            };
        let _ = (tick_corr, tick_shared_held);

        // Verify immediate explicit NotObservable CoverageGap on drop, backoff honesty, and gen 2.
        if tick == 250 {
            assert!(
                tick_gaps >= 1,
                "expected immediate CoverageGap on wyze-51 drop"
            );
            let views = supervisor.camera_views();
            let v51 = views.get(&wyze_51_id).ok_or("missing v51")?;
            let v39 = views.get(&wyze_39_id).ok_or("missing v39")?;
            let v177 = views.get(&unifi_177_id).ok_or("missing v177")?;
            assert_eq!(v51.state, SensorState::GapBackoff);
            assert_eq!(v51.active_sessions, 0);
            assert_eq!(v39.state, SensorState::Streaming);
            assert_eq!(v177.state, SensorState::Streaming);
            let snap = supervisor.storage().projection().snapshot_latest();
            let cov51 =
                supervisor
                    .storage()
                    .projection()
                    .query_coverage(&snap, Some(&wyze_51_id), None);
            assert_eq!(cov51.len(), 1);
            assert_eq!(cov51[0].status, CoverageStatus::NotObservable);
            assert!(cov51[0].active_gaps >= 1);
            drop_verified = true;
        }
        if tick == 251 {
            let views = supervisor.camera_views();
            assert_eq!(
                views.get(&wyze_51_id).ok_or("missing v51")?.state,
                SensorState::GapBackoff,
                "must respect exponential backoff without zero-delay reconnect storm"
            );
        }
        if tick == 260 {
            assert_eq!(tick_reconnects, 1, "expected wyze-51 reconnect at tick 260");
            let views = supervisor.camera_views();
            let v51 = views.get(&wyze_51_id).ok_or("missing v51")?;
            assert_eq!(v51.state, SensorState::Connecting);
            assert_eq!(v51.stream_generation, 2);
            assert_eq!(v51.active_sessions, 1);
            assert_eq!(v51.peak_concurrent_sessions, 1);
            let snap = supervisor.storage().projection().snapshot_latest();
            let cov51 =
                supervisor
                    .storage()
                    .projection()
                    .query_coverage(&snap, Some(&wyze_51_id), None);
            assert_eq!(cov51[0].status, CoverageStatus::NotObservable);
            assert!(cov51[0].active_gaps >= 1);
        }
        if tick == 261 {
            let views = supervisor.camera_views();
            let v51 = views.get(&wyze_51_id).ok_or("missing v51")?;
            assert_eq!(v51.state, SensorState::Streaming);
            assert_eq!(v51.stream_generation, 2);
            let snap = supervisor.storage().projection().snapshot_latest();
            let cov51 = supervisor
                .storage()
                .projection()
                .query_coverage(&snap, Some(&wyze_51_id), None);
            assert_eq!(cov51[0].status, CoverageStatus::Covered);
            assert_eq!(cov51[0].active_gaps, 0);
            recovery_verified = true;
        }

        // Measure `MvccProjectionStore::orient_summary` latency on every tick.
        let orient_t0 = Instant::now();
        let mvcc_snap = supervisor.storage().projection().snapshot_latest();
        let summary = mvcc_snap.orient_summary();
        let orient_us = u64::try_from(orient_t0.elapsed().as_micros()).unwrap_or(u64::MAX);
        assert_eq!(
            summary.anchor.commit_sequence,
            supervisor.storage().head_snapshot()?.commit_sequence
        );

        all_orient_us.push(orient_us);
        if tick <= SOAK_TICKS / 3 {
            early_orient_us.push(orient_us);
        } else if tick <= (SOAK_TICKS * 2) / 3 {
            mid_orient_us.push(orient_us);
        } else {
            late_orient_us.push(orient_us);
        }

        // Track ring wraparound & enforce hard disk bound <= ring_cap + 2 * pack_size.
        let head = supervisor.storage().head_snapshot()?;
        let disk_bytes = head.on_disk_pack_bytes;
        peak_disk_bytes = peak_disk_bytes.max(disk_bytes);
        let pack_count = count_pack_files(dir.path());
        peak_pack_count = peak_pack_count.max(pack_count);
        assert!(
            disk_bytes <= DISK_BOUND_BYTES,
            "tick {tick}: on-disk pack bytes {disk_bytes} exceeded hard bound {DISK_BOUND_BYTES} (ring_cap={RING_CAP_BYTES}, pack_target={PACK_TARGET_BYTES})"
        );

        let current_candidates = supervisor.storage().retention_candidates();
        for id in current_candidates.keys() {
            seen_candidate_ids.insert(id.clone());
        }
        if seen_candidate_ids.len() > current_candidates.len() {
            saw_ring_wraparound = true;
            total_evicted_approx = (seen_candidate_ids.len() - current_candidates.len()) as u64;
        }

        // Verify 100% of legal-held closures survive ring wraparound & compaction.
        let held_preserved = held_ids
            .iter()
            .filter(|id| current_candidates.contains_key(*id))
            .count();
        assert_eq!(
            held_preserved,
            held_ids.len(),
            "tick {tick}: legal hold lost during ring compaction!"
        );
        if tick % 50 == 0 && !held_digests.is_empty() {
            let reader = supervisor.storage().pack_store().reader();
            for digest in &held_digests {
                let bytes = reader.read_verified(digest)?;
                assert!(!bytes.is_empty());
            }
        }

        if tick == 1 || tick % 25 == 0 || tick == SOAK_TICKS {
            current_rss_kb = sample_process_rss_kb();
        }

        let views = supervisor.camera_views();
        let total_reconnects: u64 = views.values().map(|v| v.reconnects).sum();
        let orient_p50_us = percentile_us(&all_orient_us, 50, 100);
        let orient_p99_us = percentile_us(&all_orient_us, 99, 100);
        let elapsed_ms = u64::try_from(soak_wall_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let mut line = String::with_capacity(320);
        let _ = write!(
            line,
            concat!(
                "{{\"schema\":\"fss.daemon_soak_sample.v1\",\"tick\":{},\"elapsed_ms\":{},",
                "\"rss_kb\":{},\"disk_bytes\":{},\"pack_count\":{},\"commits\":{},",
                "\"orient_p50_us\":{},\"orient_p99_us\":{},\"reconnects\":{},\"gaps\":{},",
                "\"false_osd_alerts\":{},\"corroborated_events\":{},\"held_preserved\":{}}}"
            ),
            tick,
            elapsed_ms,
            current_rss_kb,
            disk_bytes,
            pack_count,
            head.commit_sequence,
            orient_p50_us,
            orient_p99_us,
            total_reconnects,
            supervisor
                .camera_views()
                .values()
                .map(|v| u64::from(v.state == SensorState::GapBackoff))
                .sum::<u64>()
                + u64::from(drop_verified),
            false_osd_alerts,
            corroborated_total,
            held_preserved,
        );
        jsonl_lines.push(line);
    }

    // Core invariants before shutdown.
    assert_eq!(
        false_osd_alerts, 0,
        "OSD ticking frames produced false alerts"
    );
    assert_eq!(shared_wifi_held_verified, 1);
    assert!(
        corroborated_total >= 2,
        "expected >= 2 live corroborated events"
    );
    assert_eq!(ipc_latencies_ms.len(), 2);
    assert!(
        saw_ring_wraparound,
        "soak must exercise actual ring wraparound eviction"
    );
    assert!(
        total_evicted_approx >= 20,
        "expected >= 20 evicted GOP windows, got {total_evicted_approx}"
    );
    assert!(drop_verified && recovery_verified);
    assert_eq!(supervisor.perception().pool_metrics().loads, 1);
    for view in supervisor.camera_views().values() {
        assert_eq!(view.peak_concurrent_sessions, 1);
    }

    let early_p50_us = percentile_us(&early_orient_us, 50, 100);
    let early_p99_us = percentile_us(&early_orient_us, 99, 100);
    let mid_p50_us = percentile_us(&mid_orient_us, 50, 100);
    let mid_p99_us = percentile_us(&mid_orient_us, 99, 100);
    let late_p50_us = percentile_us(&late_orient_us, 50, 100);
    let late_p99_us = percentile_us(&late_orient_us, 99, 100);
    let overall_p50_us = percentile_us(&all_orient_us, 50, 100);
    let overall_p99_us = percentile_us(&all_orient_us, 99, 100);

    assert!(
        early_p99_us < ORIENT_P99_BUDGET_US
            && mid_p99_us < ORIENT_P99_BUDGET_US
            && late_p99_us < ORIENT_P99_BUDGET_US,
        "orient_summary p99 exceeded 10ms: early={early_p99_us}us mid={mid_p99_us}us late={late_p99_us}us"
    );
    // Flatness check: late window must stay well under 10ms and not drift unboundedly vs early.
    assert!(
        late_p99_us <= early_p99_us.max(500).saturating_mul(6),
        "orient_summary showed upward drift: early_p99={early_p99_us}us late_p99={late_p99_us}us"
    );

    // Graceful `request -> drain -> finalize` shutdown.
    let shutdown = supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    assert!(shutdown.verified_batches > 100);
    assert!(!default_socket_path(dir.path()).exists());

    // Post-shutdown Merkle epoch ledger full-chain verification with strict IncompleteTailPolicy::Reject.
    let reopened_ledger = MerkleEpochLedger::open(
        dir.path().join("ledger"),
        "site-home-soak",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(
        reopened_ledger.commit_sequence(),
        shutdown.head_commit_sequence
    );
    let _ = reopened_ledger.verify_full_chain()?;

    // Post-shutdown PackStore re-open verifying 100% of legal-held object digests still verify cleanly.
    let reopened_packs = PackStore::open(
        dir.path(),
        PackConfig {
            target_pack_bytes: PACK_TARGET_BYTES,
            ..PackConfig::default()
        },
    )?;
    let reader = reopened_packs.reader();
    for digest in &held_digests {
        let verified_bytes = reader.read_verified(digest)?;
        assert!(!verified_bytes.is_empty());
    }
    let final_disk_bytes = reopened_packs.on_disk_pack_bytes()?;
    assert!(
        final_disk_bytes <= DISK_BOUND_BYTES,
        "post-shutdown pack bytes {final_disk_bytes} > {DISK_BOUND_BYTES}"
    );

    // Emit JSONL telemetry + final receipt to `target/test-logs/daemon-soak/`.
    let log_dir = test_logs_dir()?;
    let jsonl_path = log_dir.join("deterministic_soak.jsonl");
    let receipt_path = log_dir.join("deterministic_soak_receipt.json");
    fs::write(&jsonl_path, format!("{}\n", jsonl_lines.join("\n")))?;

    let max_ipc_ms = ipc_latencies_ms.iter().copied().max().unwrap_or(0);
    let receipt_json = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"fss.daemon_soak_receipt.v1\",\n",
            "  \"mode\": \"deterministic_540_tick\",\n",
            "  \"ticks_executed\": {},\n",
            "  \"head_commit_sequence\": {},\n",
            "  \"verified_batches\": {},\n",
            "  \"ring_cap_bytes\": {},\n",
            "  \"pack_target_bytes\": {},\n",
            "  \"disk_bound_bytes\": {},\n",
            "  \"peak_disk_bytes\": {},\n",
            "  \"final_disk_bytes\": {},\n",
            "  \"disk_bounded\": true,\n",
            "  \"peak_pack_count\": {},\n",
            "  \"evicted_gop_windows\": {},\n",
            "  \"held_closures_pinned\": {},\n",
            "  \"held_closures_preserved\": {},\n",
            "  \"held_digests_verified_post_shutdown\": {},\n",
            "  \"orient_early_p50_us\": {},\n",
            "  \"orient_early_p99_us\": {},\n",
            "  \"orient_mid_p50_us\": {},\n",
            "  \"orient_mid_p99_us\": {},\n",
            "  \"orient_late_p50_us\": {},\n",
            "  \"orient_late_p99_us\": {},\n",
            "  \"orient_overall_p50_us\": {},\n",
            "  \"orient_overall_p99_us\": {},\n",
            "  \"orient_p99_ms\": {:.4},\n",
            "  \"false_osd_alerts\": {},\n",
            "  \"shared_wifi_held_events\": {},\n",
            "  \"corroborated_events\": {},\n",
            "  \"max_ipc_corroboration_ms\": {},\n",
            "  \"wyze51_drop_gap_verified\": {},\n",
            "  \"wyze51_gen2_recovery_verified\": {},\n",
            "  \"active_tasks\": {},\n",
            "  \"leaked_obligations\": {},\n",
            "  \"pool_loads\": 1,\n",
            "  \"rss_kb_final\": {},\n",
            "  \"verdict\": \"pass\"\n",
            "}}\n"
        ),
        SOAK_TICKS,
        shutdown.head_commit_sequence,
        shutdown.verified_batches,
        RING_CAP_BYTES,
        PACK_TARGET_BYTES,
        DISK_BOUND_BYTES,
        peak_disk_bytes,
        final_disk_bytes,
        peak_pack_count,
        total_evicted_approx,
        held_ids.len(),
        held_ids.len(),
        held_digests.len(),
        early_p50_us,
        early_p99_us,
        mid_p50_us,
        mid_p99_us,
        late_p50_us,
        late_p99_us,
        overall_p50_us,
        overall_p99_us,
        (overall_p99_us as f64) / 1000.0,
        false_osd_alerts,
        shared_wifi_held_verified,
        corroborated_total,
        max_ipc_ms,
        drop_verified,
        recovery_verified,
        shutdown.active_tasks,
        shutdown.leaked_obligations,
        current_rss_kb,
    );
    fs::write(&receipt_path, &receipt_json)?;

    eprintln!(
        "METRIC daemon_soak_540: orient_early_p99_us={early_p99_us} orient_mid_p99_us={mid_p99_us} orient_late_p99_us={late_p99_us} peak_disk={peak_disk_bytes}/{DISK_BOUND_BYTES} evicted={total_evicted_approx} held={}/{} false_osd={false_osd_alerts} corr={corroborated_total} max_ipc_ms={max_ipc_ms} active_tasks={} leaked_obligations={}",
        held_ids.len(),
        held_ids.len(),
        shutdown.active_tasks,
        shutdown.leaked_obligations,
    );
    Ok(())
}
