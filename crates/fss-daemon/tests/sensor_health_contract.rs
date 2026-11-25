#![forbid(unsafe_code)]
//! Visual degradation excludes coverage/cognition while preserving exact source custody.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fss_core::{ContentDigest, SensorId};
use fss_daemon::{
    CameraAdapterKind, CameraHealthStatus, DaemonStartConfig, DaemonSupervisor,
    SensorDisconnectReason, SensorDriver, SensorDriverEvent, SensorHealthPolicy, SensorHealthState,
    SiteManifest, SyntheticCameraControl, SyntheticCameraDriver, SyntheticDetectionHint,
    SyntheticFrameSpec,
};
use fss_projection_store::{CoverageStatus, ProjectedCoverageState, ProjectionStore};
use fss_reference::ingest::model_pool::FramePixelInput;
use fss_reference::ingest::osd_mask::ImageRect;
use fss_reference::ingest::sensor_health::HealthFinding;

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;
const START_NS: i128 = 1_700_000_000_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, TestError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fssd-health-{}-{id}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Input {
    spec: SyntheticFrameSpec,
    malformed_decoded_pixels: bool,
    discontinuity: bool,
}

impl From<SyntheticFrameSpec> for Input {
    fn from(spec: SyntheticFrameSpec) -> Self {
        Self {
            spec,
            malformed_decoded_pixels: false,
            discontinuity: false,
        }
    }
}

type Inputs = Arc<Mutex<VecDeque<Input>>>;

struct Driver {
    inner: SyntheticCameraDriver,
    control: Arc<SyntheticCameraControl>,
    inputs: Inputs,
    source_digests: Arc<Mutex<Vec<ContentDigest>>>,
}

impl SensorDriver for Driver {
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason> {
        self.inner.connect(generation)
    }

    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent {
        let input = self
            .inputs
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front());
        let Some(input) = input else {
            return SensorDriverEvent::Idle;
        };
        self.control.push_spec(input.spec);
        let mut event = self.inner.poll_frame(now_ns);
        if let SensorDriverEvent::Frame(frame) = &mut event {
            let frame = Arc::make_mut(frame);
            // Inject a decode defect without changing the real source envelope or its digest.
            if input.malformed_decoded_pixels {
                frame.pixels = FramePixelInput::Luma { pixels: vec![0] };
            }
            frame.discontinuity_before |= input.discontinuity;
            if let Ok(mut digests) = self.source_digests.lock() {
                digests.push(frame.source_digest);
            }
        }
        event
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
        CameraAdapterKind::Synthetic
    }
}

struct Fixture {
    supervisor: DaemonSupervisor,
    inputs: Inputs,
    source_digests: Arc<Mutex<Vec<ContentDigest>>>,
    sensor_id: SensorId,
    now: i128,
    _dir: TempDir,
}

impl Fixture {
    fn new(enabled: bool) -> Result<Self, TestError> {
        let dir = TempDir::new()?;
        let root = dir.0.to_string_lossy();
        let manifest = SiteManifest::parse_json(&format!(
            r#"{{
            "schema":"fss.site_manifest.v1","site_id":"site-health",
            "deployment_root":"{root}","ring_cap_bytes":67108864,
            "pack_target_bytes":65536,"scrub_budget_bytes_per_tick":1048576,
            "cameras":[{{"sensor_id":"sensor:health","adapter":"synthetic",
                "endpoint":"synthetic://health","zone_id":"yard","dimensions":[32,32],
                "failure_domains":["power:health"],"reconnect_min_ms":200,
                "reconnect_max_ms":2000,"stall_timeout_ms":5000,"ring_max_frames":64,
                "ring_max_bytes":262144,"gop_frames":1}}]
        }}"#
        ))?;
        let entry = manifest.cameras.first().ok_or("missing camera")?;
        let sensor_id = entry.sensor_id.clone();
        let control = SyntheticCameraControl::new(sensor_id.clone());
        let inputs = Arc::new(Mutex::new(VecDeque::new()));
        let source_digests = Arc::new(Mutex::new(Vec::new()));
        let driver: Box<dyn SensorDriver> = Box::new(Driver {
            inner: SyntheticCameraDriver::new(entry, Arc::clone(&control)),
            control,
            inputs: Arc::clone(&inputs),
            source_digests: Arc::clone(&source_digests),
        });
        let mut config = DaemonStartConfig::new(manifest);
        config.custom_drivers = BTreeMap::from([(sensor_id.clone(), driver)]);
        config.started_at_ns = START_NS;
        config.enable_ipc = false;
        config.sensor_health_policy = enabled.then_some(SensorHealthPolicy::ConservativeV1);
        Ok(Self {
            supervisor: DaemonSupervisor::start(config)?,
            inputs,
            source_digests,
            sensor_id,
            now: START_NS,
            _dir: dir,
        })
    }

    fn step(&mut self, frames: impl IntoIterator<Item = Input>) -> TestResult {
        self.inputs
            .lock()
            .map_err(|_| "input queue poisoned")?
            .extend(frames);
        self.now += 100_000_000;
        self.supervisor.step_tick(self.now)?;
        Ok(())
    }

    fn coverage(&self) -> Result<ProjectedCoverageState, TestError> {
        let projection = self.supervisor.storage().projection();
        projection
            .query_coverage(
                &projection.snapshot_latest(),
                Some(&self.sensor_id),
                Some("yard"),
            )
            .into_iter()
            .next()
            .ok_or_else(|| "missing coverage".into())
    }

    fn health(&self) -> Result<CameraHealthStatus, TestError> {
        self.supervisor
            .camera_views()
            .remove(&self.sensor_id)
            .and_then(|view| view.sensor_health)
            .ok_or_else(|| "missing health status".into())
    }

    fn acquire(&mut self) -> TestResult {
        self.step((0..8).map(|n| textured(n).into()))?;
        assert_eq!(self.coverage()?.status, CoverageStatus::Covered);
        assert_eq!(self.coverage()?.health_conflicts, 0);
        Ok(())
    }

    fn assert_all_sources_retained(&self) -> TestResult {
        let expected: BTreeSet<_> = self
            .source_digests
            .lock()
            .map_err(|_| "source digest queue poisoned")?
            .iter()
            .copied()
            .collect();
        let packs = self.supervisor.storage().pack_store();
        let roots = packs.list_roots(None, 4096)?;
        assert!(!roots.has_more);
        let mut actual = BTreeSet::new();
        for entry in roots.entries {
            if entry.record.kind == "media-gop-v2" {
                let bytes = packs.read_verified(&entry.record.root_digest)?;
                let chunk = fss_pack::MediaChunkView::parse(&bytes)?;
                for index in 0..chunk.frame_count() {
                    actual.insert(ContentDigest::sha256(chunk.frame_bytes_verified(index)?));
                }
            }
        }
        assert_eq!(
            actual, expected,
            "health screening must preserve every exact source payload"
        );
        Ok(())
    }

    fn finish(self) -> TestResult {
        let report = self.supervisor.shutdown_graceful()?;
        assert_eq!(report.active_tasks, 0);
        assert_eq!(report.leaked_obligations, 0);
        Ok(())
    }
}

fn textured(n: u32) -> SyntheticFrameSpec {
    SyntheticFrameSpec::MotionBurst {
        motion_rect: ImageRect {
            x: (n % 2) * 16,
            y: 0,
            width: 16,
            height: 32,
        },
        luma_value: 180 + (n % 40) as u8,
        extra_payload_bytes: 0,
        is_keyframe: true,
        detections: vec![SyntheticDetectionHint {
            class_label: "person".to_owned(),
            score_ppm: 950_000,
            foot_px: None,
            zone_id: None,
            track_id: u64::from(n) + 1,
        }],
    }
}

fn flat(value: u8) -> SyntheticFrameSpec {
    SyntheticFrameSpec::OsdOnlyTick {
        osd_rect: ImageRect {
            x: 0,
            y: 0,
            width: 32,
            height: 32,
        },
        luma_value: value,
        is_keyframe: true,
    }
}

#[test]
fn frozen_images_with_advancing_source_sequences_hold_coverage_and_preserve_custody() -> TestResult
{
    let mut fixture = Fixture::new(true)?;
    fixture.acquire()?;
    for _ in 0..8 {
        fixture.step([textured(20).into()])?;
    }
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(fixture.coverage()?.health_conflicts, 1);
    assert!(
        fixture
            .health()?
            .findings
            .contains(&HealthFinding::ExactFrameRepetition)
    );
    let views = fixture.supervisor.camera_views();
    assert_eq!(views[&fixture.sensor_id].active_sessions, 1);
    assert_eq!(views[&fixture.sensor_id].frames_ingested, 16);
    fixture.assert_all_sources_retained()?;
    fixture.finish()
}

#[test]
fn extreme_clipping_and_contrast_collapse_hold_until_eight_fresh_clear_frames() -> TestResult {
    for (value, finding) in [
        (0, HealthFinding::PersistentDarkField),
        (255, HealthFinding::PersistentBrightField),
        (128, HealthFinding::ContrastCollapse),
    ] {
        let mut fixture = Fixture::new(true)?;
        fixture.acquire()?;
        fixture.step([textured(8).into()])?;
        assert!(fixture.supervisor.perception().corroborator().window_len() > 0);
        fixture.step((0..3).map(|_| flat(value).into()))?;
        assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
        assert!(fixture.health()?.findings.contains(&finding));
        assert_eq!(
            fixture.supervisor.perception().corroborator().window_len(),
            0,
            "excluded prior tracks must not match future camera observations"
        );
        let decoded_before = fixture.supervisor.camera_views()[&fixture.sensor_id].frames_decoded;
        fixture.step((20..27).map(|n| textured(n).into()))?;
        assert_eq!(fixture.health()?.state, SensorHealthState::Held);
        assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
        fixture.step([textured(27).into()])?;
        assert_eq!(fixture.health()?.state, SensorHealthState::Clear);
        assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
        assert_eq!(fixture.coverage()?.health_conflicts, 0);
        assert_eq!(
            fixture.supervisor.camera_views()[&fixture.sensor_id].frames_decoded,
            decoded_before + 1,
            "only the final recovery frame can enter perception"
        );
        fixture.assert_all_sources_retained()?;
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn source_gap_and_reconnect_require_new_screen_history() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.acquire()?;
    let mut gap: Input = textured(8).into();
    gap.discontinuity = true;
    fixture.step([gap])?;
    assert_eq!(fixture.health()?.consecutive_clear_frames, 1);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    fixture.step((9..16).map(|n| textured(n).into()))?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.step([SyntheticFrameSpec::Disconnect(SensorDisconnectReason::NetworkDrop).into()])?;
    fixture.now += 1_000_000_000;
    fixture.step([])?;
    assert_eq!(
        fixture.supervisor.camera_views()[&fixture.sensor_id].stream_generation,
        2
    );
    fixture.step((30..37).map(|n| textured(n).into()))?;
    assert_eq!(fixture.health()?.consecutive_clear_frames, 7);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    fixture.step([textured(37).into()])?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.assert_all_sources_retained()?;
    fixture.finish()
}

#[test]
fn malformed_decoded_input_fails_closed_without_mutating_encoded_source() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.acquire()?;
    let mut malformed: Input = textured(8).into();
    malformed.malformed_decoded_pixels = true;
    fixture.step([malformed])?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(fixture.health()?.refusal, Some("invalid_image"));
    fixture.assert_all_sources_retained()?;
    fixture.step((20..27).map(|n| textured(n).into()))?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    fixture.step([textured(27).into()])?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.finish()
}

#[test]
fn policy_is_explicit_and_a_warming_screen_never_certifies_coverage() -> TestResult {
    let mut enabled = Fixture::new(true)?;
    enabled.step([textured(0).into(), textured(1).into()])?;
    assert_eq!(enabled.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(enabled.health()?.state, SensorHealthState::Warming);
    enabled.finish()?;
    let mut disabled = Fixture::new(false)?;
    disabled.step([flat(0).into(), flat(0).into()])?;
    assert_eq!(disabled.coverage()?.status, CoverageStatus::Covered);
    assert!(
        disabled.supervisor.camera_views()[&disabled.sensor_id]
            .sensor_health
            .is_none()
    );
    assert!(SensorHealthPolicy::parse("healthy").is_err());
    disabled.finish()
}

#[test]
fn frozen_startup_never_becomes_ready_even_with_high_confidence_detection_hints() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.step((0..8).map(|_| textured(0).into()))?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(fixture.health()?.state, SensorHealthState::Held);
    assert_eq!(
        fixture.supervisor.camera_views()[&fixture.sensor_id].frames_decoded,
        0
    );
    assert_eq!(
        fixture.supervisor.perception().corroborator().window_len(),
        0
    );
    fixture.assert_all_sources_retained()?;
    fixture.finish()
}

#[test]
fn same_poll_clear_screen_then_terminal_loss_cannot_emit_coverage_recovery() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let frames = (0..8)
        .map(|n| textured(n).into())
        .chain([SyntheticFrameSpec::Disconnect(SensorDisconnectReason::NetworkDrop).into()]);
    fixture.step(frames)?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(fixture.health()?.state, SensorHealthState::Warming);
    assert_eq!(
        fixture.supervisor.camera_views()[&fixture.sensor_id].frames_decoded,
        0
    );
    fixture.assert_all_sources_retained()?;
    fixture.finish()
}

#[test]
fn several_health_transitions_in_one_poll_all_retain_their_witnesses() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    fixture.acquire()?;
    let generation_before = fixture.coverage()?.generation;
    let burst = (0..3)
        .map(|_| flat(0).into())
        .chain((20..28).map(|n| textured(n).into()))
        .chain((0..3).map(|_| flat(255).into()));
    fixture.step(burst)?;
    assert_eq!(
        fixture.coverage()?.generation,
        generation_before + 3,
        "dark hold, advisory clear, and bright hold must each have a durable witness"
    );
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert_eq!(fixture.coverage()?.health_conflicts, 1);
    assert!(
        fixture
            .health()?
            .findings
            .contains(&HealthFinding::PersistentBrightField)
    );
    assert_eq!(
        fixture.supervisor.perception().corroborator().window_len(),
        0
    );
    fixture.step([])?;
    fixture.assert_all_sources_retained()?;
    fixture.finish()
}
