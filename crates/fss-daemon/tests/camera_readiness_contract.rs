#![forbid(unsafe_code)]
//! Deterministic acquisition readiness and source continuity contracts.
//! Adapter acceptance, first observation, and retained continuity are separate facts.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fss_core::{CaptureInterval, SensorId, StreamId, TimestampNs};
use fss_daemon::{
    BackoffSchedule, CameraAdapterKind, CameraManifestEntry, CameraRuntimeView, DaemonStartConfig,
    DaemonSupervisor, SensorDisconnectReason, SensorDriver, SensorDriverEvent, SensorState,
    SiteManifest, SyntheticCameraControl, SyntheticCameraDriver, SyntheticFrameSpec,
};
use fss_projection_store::{CoverageStatus, ProjectedCoverageState, ProjectionStore};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

const START_NS: i128 = 1_700_000_000_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, TestError> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = PathBuf::from("/tmp").join(format!("fssd-readiness-{}-{n}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug)]
enum FrameMutation {
    Normal,
    Sequence(u64),
    Generation(u64),
    Sensor(SensorId),
    Stream(StreamId),
    ReceiveTime(i128),
    Discontinuity,
}

#[derive(Clone, Debug)]
enum Input {
    Frame(FrameMutation),
    Disconnect,
}

impl Input {
    fn frame() -> Self {
        Self::Frame(FrameMutation::Normal)
    }
}

type InputQueue = Arc<Mutex<VecDeque<Input>>>;

/// Uses the production synthetic payload generator, but emits only explicitly queued frames.
/// This lets tests distinguish a connected idle session from observed usable footage.
struct ReadinessDriver {
    inner: SyntheticCameraDriver,
    control: Arc<SyntheticCameraControl>,
    inputs: InputQueue,
}

impl SensorDriver for ReadinessDriver {
    fn connect(&mut self, generation: u64) -> Result<(), SensorDisconnectReason> {
        self.inner.connect(generation)
    }

    fn poll_frame(&mut self, now_ns: i128) -> SensorDriverEvent {
        let input = match self.inputs.lock() {
            Ok(mut inputs) => inputs.pop_front(),
            Err(_) => {
                return SensorDriverEvent::Disconnected(SensorDisconnectReason::DriverError(
                    "readiness test input queue poisoned".to_owned(),
                ));
            }
        };
        match input {
            None => SensorDriverEvent::Idle,
            Some(Input::Disconnect) => {
                self.inner.disconnect();
                SensorDriverEvent::Disconnected(SensorDisconnectReason::NetworkDrop)
            }
            Some(Input::Frame(mutation)) => {
                self.control
                    .push_spec(SyntheticFrameSpec::Quiescent { is_keyframe: true });
                let SensorDriverEvent::Frame(mut frame) = self.inner.poll_frame(now_ns) else {
                    return SensorDriverEvent::Disconnected(SensorDisconnectReason::DriverError(
                        "synthetic frame unavailable".to_owned(),
                    ));
                };
                let frame_mut = Arc::make_mut(&mut frame);
                match mutation {
                    FrameMutation::Normal => {}
                    FrameMutation::Sequence(sequence) => frame_mut.sequence = sequence,
                    FrameMutation::Generation(generation) => {
                        frame_mut.stream_generation = generation;
                    }
                    FrameMutation::Sensor(sensor_id) => frame_mut.sensor_id = sensor_id,
                    FrameMutation::Stream(stream_id) => frame_mut.stream_id = stream_id,
                    FrameMutation::ReceiveTime(received_ns) => {
                        frame_mut.host_receive_ns = received_ns;
                    }
                    FrameMutation::Discontinuity => frame_mut.discontinuity_before = true,
                }
                SensorDriverEvent::Frame(frame)
            }
        }
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

    fn update_manifest_entry(&mut self, entry: &CameraManifestEntry) {
        self.inner.update_manifest_entry(entry);
    }
}

struct Fixture {
    supervisor: DaemonSupervisor,
    inputs: InputQueue,
    sensor_id: SensorId,
    _dir: TempDir,
}

impl Fixture {
    fn new(ring_max_frames: usize) -> Result<Self, TestError> {
        Self::with_gop_frames(ring_max_frames, 4)
    }

    fn with_gop_frames(ring_max_frames: usize, gop_frames: usize) -> Result<Self, TestError> {
        let dir = TempDir::new()?;
        let root = dir.0.to_string_lossy();
        let manifest = SiteManifest::parse_json(&format!(
            r#"{{
  "schema": "fss.site_manifest.v1",
  "site_id": "site-readiness",
  "deployment_root": "{root}",
  "ring_cap_bytes": 67108864,
  "pack_target_bytes": 65536,
  "scrub_budget_bytes_per_tick": 1048576,
  "cameras": [{{
    "sensor_id": "sensor:readiness",
    "adapter": "synthetic",
    "endpoint": "synthetic://readiness",
    "zone_id": "yard",
    "dimensions": [32, 32],
    "failure_domains": ["power:readiness"],
    "reconnect_min_ms": 200,
    "reconnect_max_ms": 2000,
    "stall_timeout_ms": 5000,
    "ring_max_frames": {ring_max_frames},
    "ring_max_bytes": 32768,
    "gop_frames": {gop_frames}
  }}]
}}"#
        ))?;
        let entry = manifest.cameras.first().ok_or("missing camera")?;
        let sensor_id = entry.sensor_id.clone();
        let control = SyntheticCameraControl::new(sensor_id.clone());
        let inputs: InputQueue = Arc::new(Mutex::new(VecDeque::new()));
        let driver: Box<dyn SensorDriver> = Box::new(ReadinessDriver {
            inner: SyntheticCameraDriver::new(entry, Arc::clone(&control)),
            control,
            inputs: Arc::clone(&inputs),
        });
        let mut config = DaemonStartConfig::new(manifest);
        config.custom_drivers = BTreeMap::from([(sensor_id.clone(), driver)]);
        config.started_at_ns = START_NS;
        config.enable_ipc = false;
        Ok(Self {
            supervisor: DaemonSupervisor::start(config)?,
            inputs,
            sensor_id,
            _dir: dir,
        })
    }

    fn queue(&self, inputs: impl IntoIterator<Item = Input>) -> TestResult {
        self.inputs
            .lock()
            .map_err(|_| "input queue poisoned")?
            .extend(inputs);
        Ok(())
    }

    fn view(&self) -> Result<CameraRuntimeView, TestError> {
        self.supervisor
            .camera_views()
            .remove(&self.sensor_id)
            .ok_or_else(|| "camera view missing".into())
    }

    fn coverage(&self) -> Result<ProjectedCoverageState, TestError> {
        let snapshot = self.supervisor.storage().projection().snapshot_latest();
        self.supervisor
            .storage()
            .projection()
            .query_coverage(&snapshot, Some(&self.sensor_id), Some("yard"))
            .into_iter()
            .next()
            .ok_or_else(|| "coverage witness missing".into())
    }

    fn finish(self) -> TestResult {
        let report = self.supervisor.shutdown_graceful()?;
        assert_eq!(report.active_tasks, 0);
        assert_eq!(report.leaked_obligations, 0);
        Ok(())
    }
}

#[test]
fn accepted_idle_session_is_not_covered_and_first_frame_watchdog_still_runs() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.view()?.active_sessions, 1);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    assert!(fixture.coverage()?.active_gaps > 0);

    let idle = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(idle.frames_received, 0);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    let timeout = fixture.supervisor.step_tick(START_NS + 5_000_000_001)?;
    assert_eq!(timeout.coverage_gaps_emitted, 1);
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    assert_eq!(fixture.view()?.active_sessions, 0);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    fixture.finish()
}

#[test]
fn readiness_requires_two_retained_samples_and_reconnect_proves_it_again() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    fixture.queue([Input::frame()])?;
    let first = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(first.frames_received, 1);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    fixture.queue([Input::frame()])?;
    let second_at = START_NS + 200_000_000;
    fixture.supervisor.step_tick(second_at)?;
    assert_eq!(fixture.view()?.state, SensorState::Streaming);
    let covered = fixture.coverage()?;
    assert_eq!(covered.status, CoverageStatus::Covered);
    assert_eq!(covered.active_gaps, 0);
    assert_eq!(
        covered.window,
        CaptureInterval::point(TimestampNs(second_at))
    );

    fixture.queue([Input::Disconnect])?;
    fixture.supervisor.step_tick(START_NS + 300_000_000)?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    let reconnect = fixture.supervisor.step_tick(START_NS + 1_000_000_000)?;
    assert_eq!(reconnect.reconnects_completed, 1);
    assert_eq!(reconnect.frames_received, 0);
    assert_eq!(fixture.view()?.stream_generation, 2);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    fixture.queue([Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 1_100_000_000)?;
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    fixture.queue([Input::frame()])?;
    let recovered_at = START_NS + 1_200_000_000;
    fixture.supervisor.step_tick(recovered_at)?;
    let recovered = fixture.coverage()?;
    assert_eq!(fixture.view()?.state, SensorState::Streaming);
    assert_eq!(fixture.view()?.peak_concurrent_sessions, 1);
    assert_eq!(fixture.view()?.total_connections, 2);
    assert_eq!(recovered.status, CoverageStatus::Covered);
    assert_eq!(recovered.active_gaps, 0);
    // The new witness cannot retroactively describe the blind reconnect interval.
    assert_eq!(
        recovered.window,
        CaptureInterval::point(TimestampNs(recovered_at))
    );
    fixture.finish()
}

#[test]
fn frame_received_before_session_acceptance_is_rejected() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    fixture.queue([Input::Frame(FrameMutation::ReceiveTime(START_NS - 1))])?;
    let tick = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(tick.frames_received, 0);
    assert_eq!(fixture.view()?.ring.total_enqueued, 0);
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);
    fixture.finish()
}

#[test]
fn invalid_source_identity_order_or_time_cannot_enter_the_ring() -> TestResult {
    let poll_ns = START_NS + 200_000_000;
    let invalid = [
        (FrameMutation::Generation(99), poll_ns),
        (
            FrameMutation::Sensor(SensorId::parse("sensor:wrong")?),
            poll_ns,
        ),
        (
            FrameMutation::Stream(StreamId::parse("stream:wrong")?),
            poll_ns,
        ),
        (FrameMutation::Sequence(0), poll_ns),
        (FrameMutation::Sequence(1), poll_ns),
        (FrameMutation::ReceiveTime(START_NS), poll_ns),
        (
            FrameMutation::ReceiveTime(START_NS + 150_000_000),
            START_NS + 6_000_000_000,
        ),
        (
            FrameMutation::ReceiveTime(START_NS + 2_000_000_000),
            poll_ns,
        ),
    ];
    for (mutation, now_ns) in invalid {
        let mut fixture = Fixture::new(64)?;
        fixture.queue([Input::frame()])?;
        fixture.supervisor.step_tick(START_NS + 100_000_000)?;
        fixture.queue([Input::Frame(mutation.clone())])?;
        let tick = fixture.supervisor.step_tick(now_ns)?;
        assert_eq!(tick.frames_received, 0, "{mutation:?}");
        assert_eq!(fixture.view()?.ring.total_enqueued, 1, "{mutation:?}");
        assert_eq!(
            fixture.view()?.state,
            SensorState::GapBackoff,
            "{mutation:?}"
        );
        assert_eq!(
            fixture.coverage()?.status,
            CoverageStatus::NotObservable,
            "{mutation:?}"
        );
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn source_discontinuity_and_sequence_gaps_require_new_continuity() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    fixture.queue([Input::frame(), Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);

    fixture.queue([Input::Frame(FrameMutation::Discontinuity)])?;
    let gap = fixture.supervisor.step_tick(START_NS + 200_000_000)?;
    assert_eq!(gap.coverage_gaps_emitted, 1);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    fixture.queue([Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 300_000_000)?;
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);

    fixture.queue([Input::Frame(FrameMutation::Sequence(6))])?;
    let skipped = fixture.supervisor.step_tick(START_NS + 400_000_000)?;
    assert_eq!(skipped.coverage_gaps_emitted, 1);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    fixture.queue([Input::Frame(FrameMutation::Sequence(7))])?;
    fixture.supervisor.step_tick(START_NS + 500_000_000)?;
    assert_eq!(fixture.view()?.state, SensorState::Streaming);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.finish()
}

#[test]
fn same_poll_disconnect_cannot_publish_a_transient_recovery() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    fixture.queue([Input::frame(), Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    fixture.queue([Input::Disconnect])?;
    fixture.supervisor.step_tick(START_NS + 200_000_000)?;
    let lost = fixture.coverage()?;

    fixture.queue([Input::frame(), Input::frame(), Input::Disconnect])?;
    let tick = fixture.supervisor.step_tick(START_NS + 1_000_000_000)?;
    assert_eq!(tick.reconnects_completed, 1);
    assert_eq!(tick.frames_received, 2);
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    let still_lost = fixture.coverage()?;
    assert_eq!(still_lost.status, CoverageStatus::NotObservable);
    // Only connection acceptance and the final loss may commit coverage witnesses.
    // A fleeting Covered witness would be an observable false recovery in ledger history.
    assert_eq!(still_lost.generation, lost.generation + 2);
    fixture.finish()
}

#[test]
fn ring_shedding_resets_readiness_until_two_later_samples_are_retained() -> TestResult {
    let mut fixture = Fixture::new(1)?;
    fixture.queue([Input::frame(), Input::frame()])?;
    let shed = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(shed.frames_shed, 1);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Stale);

    fixture.queue([Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 200_000_000)?;
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_ne!(fixture.coverage()?.status, CoverageStatus::Covered);

    fixture.queue([Input::frame()])?;
    fixture.supervisor.step_tick(START_NS + 300_000_000)?;
    assert_eq!(fixture.view()?.state, SensorState::Streaming);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.finish()
}

#[test]
fn ring_shedding_does_not_erase_source_sequence_or_identity_high_water() -> TestResult {
    let replays = [
        FrameMutation::Sequence(1),
        FrameMutation::Sequence(2),
        FrameMutation::Stream(StreamId::parse("stream:after-shed")?),
    ];
    for replay in replays {
        let mut fixture = Fixture::new(1)?;
        fixture.queue([Input::frame(), Input::frame()])?;
        let shed = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
        assert_eq!(shed.frames_shed, 1);
        assert_eq!(fixture.view()?.ring.total_enqueued, 2);

        fixture.queue([Input::Frame(replay.clone())])?;
        let tick = fixture.supervisor.step_tick(START_NS + 200_000_000)?;
        assert_eq!(tick.frames_received, 0, "{replay:?}");
        assert_eq!(fixture.view()?.ring.total_enqueued, 2, "{replay:?}");
        assert_eq!(fixture.view()?.state, SensorState::GapBackoff, "{replay:?}");
        assert_eq!(
            fixture.coverage()?.status,
            CoverageStatus::NotObservable,
            "{replay:?}"
        );
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn accepted_sessions_without_frames_keep_backoff_until_continuity_recovers() -> TestResult {
    let mut fixture = Fixture::new(64)?;
    let mut expected = BackoffSchedule::new(fixture.sensor_id.as_str(), 200, 2000);
    let first_delay_ns = i128::from(expected.next_delay_ms()) * 1_000_000;
    let second_delay_ns = i128::from(expected.next_delay_ms()) * 1_000_000;
    assert!(second_delay_ns > first_delay_ns);

    let first_timeout = START_NS + 5_000_000_001;
    fixture.supervisor.step_tick(first_timeout)?;
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    let first_reconnect = first_timeout + first_delay_ns;
    let early = fixture.supervisor.step_tick(first_reconnect - 1)?;
    assert_eq!(early.reconnects_completed, 0);
    let connected = fixture.supervisor.step_tick(first_reconnect)?;
    assert_eq!(connected.reconnects_completed, 1);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.view()?.total_connections, 2);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::NotObservable);

    let second_timeout = first_reconnect + 5_000_000_001;
    fixture.supervisor.step_tick(second_timeout)?;
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    let second_reconnect = second_timeout + second_delay_ns;
    let still_waiting = fixture.supervisor.step_tick(second_reconnect - 1)?;
    assert_eq!(
        still_waiting.reconnects_completed, 0,
        "an accepted session without frames must preserve the growing backoff"
    );
    assert_eq!(fixture.view()?.total_connections, 2);
    let connected = fixture.supervisor.step_tick(second_reconnect)?;
    assert_eq!(connected.reconnects_completed, 1);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    assert_eq!(fixture.view()?.total_connections, 3);

    // Only surviving two-frame continuity resets the retry exponent.
    fixture.queue([Input::frame(), Input::frame()])?;
    let healthy_at = second_reconnect + 100_000_000;
    fixture.supervisor.step_tick(healthy_at)?;
    assert_eq!(fixture.view()?.state, SensorState::Streaming);
    assert_eq!(fixture.coverage()?.status, CoverageStatus::Covered);
    fixture.queue([Input::Disconnect])?;
    let disconnected_at = healthy_at + 100_000_000;
    fixture.supervisor.step_tick(disconnected_at)?;
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    let early = fixture
        .supervisor
        .step_tick(disconnected_at + first_delay_ns - 1)?;
    assert_eq!(early.reconnects_completed, 0);
    let reset_retry = fixture
        .supervisor
        .step_tick(disconnected_at + first_delay_ns)?;
    assert_eq!(reset_retry.reconnects_completed, 1);
    assert_eq!(fixture.view()?.total_connections, 4);
    assert_eq!(fixture.view()?.state, SensorState::Connecting);
    fixture.finish()
}

#[test]
fn failed_storage_handoff_keeps_unaccepted_ring_frames_without_duplicate_imports() -> TestResult {
    let mut fixture = Fixture::with_gop_frames(64, 1)?;
    let foreign_bytes = b"independent catalog publication";
    let foreign_digest = fss_core::ContentDigest::sha256(foreign_bytes);
    let packs = Arc::clone(fixture.supervisor.storage().pack_store());
    packs.append_batch(&[fss_pack::PackObjectInput::new(
        fss_pack::PACK_KIND_METADATA,
        0,
        foreign_bytes,
    )])?;
    packs.publish_root(fss_pack::VirtualRootRecord::new(
        "gop:sensor_readiness:1:1",
        foreign_digest,
        "independent-publication",
        1,
        foreign_bytes.len() as u64,
        1,
        TimestampNs(START_NS),
        None,
    )?)?;

    fixture.queue([Input::frame(), Input::frame(), Input::frame()])?;
    assert!(
        fixture
            .supervisor
            .step_tick(START_NS + 100_000_000)
            .is_err()
    );
    let after_failure = fixture.view()?;
    assert_eq!(after_failure.ring.total_enqueued, 3);
    assert_eq!(after_failure.frames_ingested, 1);
    assert_eq!(
        after_failure.ring.current_frames, 2,
        "only the frame accepted into canonical custody may leave the ingest ring"
    );
    let committed = fixture.supervisor.storage().head_snapshot()?;

    // The pending first publication fails before storage accepts the next ring frame.
    assert!(
        fixture
            .supervisor
            .step_tick(START_NS + 200_000_000)
            .is_err()
    );
    assert_eq!(fixture.view()?.frames_ingested, 1);
    assert_eq!(fixture.view()?.ring.current_frames, 2);
    let retried = fixture.supervisor.storage().head_snapshot()?;
    assert_eq!(retried.commit_sequence, committed.commit_sequence);
    assert_eq!(retried.history_root, committed.history_root);
    assert!(fixture.supervisor.shutdown_graceful().is_err());
    Ok(())
}

#[test]
fn graceful_shutdown_drains_retained_frames_beyond_the_tick_ingest_budget() -> TestResult {
    let mut fixture = Fixture::with_gop_frames(64, 4)?;
    fixture.queue((0..12).map(|_| Input::frame()))?;
    let tick = fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(tick.frames_received, 12);
    assert_eq!(fixture.view()?.frames_ingested, 8);
    assert_eq!(fixture.view()?.ring.current_frames, 4);
    let packs = Arc::clone(fixture.supervisor.storage().pack_store());

    let shutdown = fixture.supervisor.shutdown_graceful()?;
    assert_eq!(shutdown.active_tasks, 0);
    assert_eq!(shutdown.leaked_obligations, 0);
    let roots = packs.list_roots(None, 32)?;
    assert!(!roots.has_more);
    let mut retained_frames = 0_u64;
    for entry in roots.entries {
        if entry.record.kind == "media-gop-v2" {
            let bytes = packs.read_verified(&entry.record.root_digest)?;
            let chunk = fss_pack::MediaChunkView::parse(&bytes)?;
            chunk.verify_all_frames()?;
            retained_frames += chunk.frame_count() as u64;
        }
    }
    assert_eq!(
        retained_frames, 12,
        "shutdown must commit the ring remainder before cancelling storage authority"
    );
    Ok(())
}

#[test]
fn reconnect_hands_off_paused_old_generation_frames_before_resetting_the_ring() -> TestResult {
    let mut fixture = Fixture::with_gop_frames(64, 4)?;
    assert!(
        fixture
            .supervisor
            .set_ingest_consumer_paused(&fixture.sensor_id, true)
    );
    fixture.queue((0..12).map(|_| Input::frame()))?;
    fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    assert_eq!(fixture.view()?.frames_ingested, 0);
    fixture.queue([Input::Disconnect])?;
    fixture.supervisor.step_tick(START_NS + 200_000_000)?;
    assert_eq!(fixture.view()?.ring.current_frames, 12);

    let reconnect = fixture.supervisor.step_tick(START_NS + 1_000_000_000)?;
    assert_eq!(reconnect.reconnects_completed, 1);
    assert_eq!(reconnect.frames_committed, 12);
    assert_eq!(fixture.view()?.stream_generation, 2);
    assert_eq!(fixture.view()?.frames_ingested, 12);
    assert_eq!(fixture.view()?.ring.current_frames, 0);
    let packs = fixture.supervisor.storage().pack_store();
    let roots = packs.list_roots(None, 32)?;
    assert!(!roots.has_more);
    let mut retained_frames = 0_u64;
    for entry in roots.entries {
        if entry.record.kind == "media-gop-v2" {
            let bytes = packs.read_verified(&entry.record.root_digest)?;
            let chunk = fss_pack::MediaChunkView::parse(&bytes)?;
            chunk.verify_all_frames()?;
            assert!(chunk.stream_id().ends_with(":g1"));
            retained_frames += chunk.frame_count() as u64;
        }
    }
    assert_eq!(retained_frames, 12);
    fixture.finish()
}

#[test]
fn failed_old_generation_handoff_blocks_reconnect_without_clearing_source() -> TestResult {
    let mut fixture = Fixture::with_gop_frames(64, 4)?;
    assert!(
        fixture
            .supervisor
            .set_ingest_consumer_paused(&fixture.sensor_id, true)
    );
    fixture.queue((0..12).map(|_| Input::frame()))?;
    fixture.supervisor.step_tick(START_NS + 100_000_000)?;
    fixture.queue([Input::Disconnect])?;
    fixture.supervisor.step_tick(START_NS + 200_000_000)?;

    let foreign_bytes = b"reconnect catalog conflict";
    let foreign_digest = fss_core::ContentDigest::sha256(foreign_bytes);
    let packs = Arc::clone(fixture.supervisor.storage().pack_store());
    packs.append_batch(&[fss_pack::PackObjectInput::new(
        fss_pack::PACK_KIND_METADATA,
        0,
        foreign_bytes,
    )])?;
    packs.publish_root(fss_pack::VirtualRootRecord::new(
        "gop:sensor_readiness:1:1",
        foreign_digest,
        "independent-publication",
        1,
        foreign_bytes.len() as u64,
        1,
        TimestampNs(START_NS),
        None,
    )?)?;

    assert!(
        fixture
            .supervisor
            .step_tick(START_NS + 1_000_000_000)
            .is_err()
    );
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    assert_eq!(fixture.view()?.stream_generation, 1);
    assert_eq!(fixture.view()?.total_connections, 1);
    assert_eq!(fixture.view()?.frames_ingested, 4);
    assert_eq!(fixture.view()?.ring.current_frames, 8);
    let committed = fixture.supervisor.storage().head_snapshot()?;

    assert!(
        fixture
            .supervisor
            .step_tick(START_NS + 1_100_000_000)
            .is_err()
    );
    assert_eq!(fixture.view()?.stream_generation, 1);
    assert_eq!(fixture.view()?.total_connections, 1);
    assert_eq!(fixture.view()?.ring.current_frames, 8);
    assert_eq!(
        fixture.supervisor.storage().head_snapshot()?.history_root,
        committed.history_root
    );
    assert!(fixture.supervisor.shutdown_graceful().is_err());
    Ok(())
}

#[test]
fn pinned_capacity_defers_reconnect_without_discarding_the_old_ring() -> TestResult {
    let mut fixture = Fixture::with_gop_frames(64, 4)?;
    assert!(
        fixture
            .supervisor
            .set_ingest_consumer_paused(&fixture.sensor_id, true)
    );
    fixture
        .supervisor
        .storage_mut()
        .register_retention_candidate(fss_pack::RetentionCandidate {
            import_id: "gop:readiness-held-capacity".to_owned(),
            sensor_id: fixture.sensor_id.as_str().to_owned(),
            capture_end_ns: TimestampNs(START_NS),
            byte_size: 67_108_864,
            object_digests: vec![fss_core::ContentDigest::sha256(b"held-capacity")],
            is_derived_proxy: false,
            held_by: vec!["hold:readiness-capacity".to_owned()],
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        })?;
    fixture.queue((0..12).map(|_| Input::frame()))?;
    assert!(
        fixture
            .supervisor
            .step_tick(START_NS + 100_000_000)?
            .quota_pinned
    );
    fixture.queue([Input::Disconnect])?;
    fixture.supervisor.step_tick(START_NS + 200_000_000)?;

    let deferred = fixture.supervisor.step_tick(START_NS + 1_000_000_000)?;
    assert!(deferred.quota_pinned);
    assert_eq!(deferred.reconnects_completed, 0);
    assert_eq!(fixture.view()?.state, SensorState::GapBackoff);
    assert_eq!(fixture.view()?.stream_generation, 1);
    assert_eq!(fixture.view()?.total_connections, 1);
    assert_eq!(fixture.view()?.frames_ingested, 0);
    assert_eq!(fixture.view()?.ring.current_frames, 12);
    assert!(matches!(
        fixture.supervisor.shutdown_graceful(),
        Err(fss_daemon::DaemonError::StorageQuotaPinned { .. })
    ));
    Ok(())
}
