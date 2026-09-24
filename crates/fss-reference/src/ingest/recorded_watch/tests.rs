#![forbid(unsafe_code)]
//! The model-free pipeline runs the real retained decode, foreground, tracker and zone gate on
//! synthetic scenes. Synthetic scenes prove the wiring and authority path, not detection quality.

use super::*;
use crate::ingest::{FileIngestAdapter, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-watch-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-watch".to_owned(),
        operation_id: OperationId::parse("operation:recorded-watch")?,
        principal: "principal:recorded-watch".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:recorded-watch"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

/// Dark background; from frame 3 a bright 16x16 block-aligned square enters at the left edge
/// and moves 8 px right per frame along the top band (when `moving`); otherwise a static scene.
fn scene(moving: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if moving && index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
    }
    Ok(stream)
}

struct Fixture {
    _directory: OwnedDirectory,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    identity: ContentDigest,
}

fn fixture(name: &str, bytes: &[u8]) -> TestResult<Fixture> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("camera.mjpeg");
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-watch", &cx)?;
    let request = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:recorded-watch")?,
        StreamId::parse("stream:recorded-watch")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
    Ok(Fixture {
        _directory: directory,
        cx,
        deployment,
        identity,
    })
}

fn plan(identity: ContentDigest, zone: WatchZone) -> WatchPlan {
    WatchPlan {
        import_identity: identity,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0,
        segment_count: FRAMES,
        zones: vec![zone],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn door() -> WatchZone {
    WatchZone {
        zone_id: "door".to_owned(),
        x: 64,
        y: 0,
        width: 32,
        height: 32,
    }
}

#[test]
fn object_entering_a_zone_yields_one_candidate_published_once() -> TestResult {
    let mut f = fixture("enter", &scene(true)?)?;
    let plan = plan(f.identity, door());
    let limits = WatchLimits::default();
    let before = f.deployment.current_anchor().clone();
    let mut report = WatchReport::analyze(&f.deployment, &plan, &limits, &f.cx)?;
    // Analysis is read-only.
    assert_eq!(*f.deployment.current_anchor(), before);
    assert_eq!(report.frames().len(), FRAMES);
    assert_eq!(report.candidates().len(), 1);
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.zone_id, "door");
    assert_eq!(candidate.status(), WatchStatus::Prepared);
    // The measured centre reaches x = 64 at frame 10; the Kalman-filtered centre the zone gate
    // uses lags the accelerating-from-rest estimate by one frame, so entry is frame 11.
    assert_eq!(candidate.entry_segment, 11);
    assert_eq!(candidate.frame_range(), [3, FRAMES - 1]);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert!(!candidate.event().analyze_corroboration().is_corroborated);
    assert!(candidate.event().evidence.iter().all(|e| !e.supports));
    let proposal = candidate.proposal_digest();

    // Deterministic: a second analysis reproduces the complete report.
    let again = WatchReport::analyze(&f.deployment, &plan, &limits, &f.cx)?;
    assert_eq!(again.to_json(0, None), report.to_json(0, None));

    let published = report.publish(&mut f.deployment, &BTreeSet::from([proposal]), &f.cx)?;
    assert_eq!(published, 1);
    assert_eq!(report.candidates()[0].status(), WatchStatus::Published);
    let after_publish = f.deployment.current_anchor().clone();
    assert!(after_publish.commit_sequence > before.commit_sequence);

    // Rerun with the same approval: recognised, never republished, no authority change.
    let mut rerun = WatchReport::analyze(&f.deployment, &plan, &limits, &f.cx)?;
    assert_eq!(
        rerun.candidates()[0].status(),
        WatchStatus::AlreadyPublished
    );
    assert_eq!(rerun.candidates()[0].proposal_digest(), proposal);
    let republished = rerun.publish(&mut f.deployment, &BTreeSet::from([proposal]), &f.cx)?;
    assert_eq!(republished, 0);
    assert_eq!(*f.deployment.current_anchor(), after_publish);
    Ok(())
}

#[test]
fn unknown_approval_is_refused_before_any_write() -> TestResult {
    let mut f = fixture("stale", &scene(true)?)?;
    let plan = plan(f.identity, door());
    let before = f.deployment.current_anchor().clone();
    let mut report = WatchReport::analyze(&f.deployment, &plan, &WatchLimits::default(), &f.cx)?;
    let bogus = ContentDigest::sha256(b"not a proposal");
    let refused = report.publish(&mut f.deployment, &BTreeSet::from([bogus]), &f.cx);
    match refused {
        Err(error @ WatchError::StaleApproval(_)) => {
            assert_eq!(error.stable_id(), "ERR-WATCH-APPROVAL-STALE-001");
        }
        other => return Err(format!("expected stale approval, got {other:?}").into()),
    }
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn motion_outside_zones_and_static_scenes_yield_no_candidate() -> TestResult {
    let yard = WatchZone {
        zone_id: "yard".to_owned(),
        x: 0,
        y: 36,
        width: 96,
        height: 12,
    };
    let moving = fixture("outside", &scene(true)?)?;
    let report = WatchReport::analyze(
        &moving.deployment,
        &plan(moving.identity, yard),
        &WatchLimits::default(),
        &moving.cx,
    )?;
    assert!(report.candidates().is_empty());
    // The object was detected and tracked; it simply never entered the zone.
    assert!(report.frames().iter().any(|f| !f.boxes.is_empty()));

    let quiet = fixture("static", &scene(false)?)?;
    let report = WatchReport::analyze(
        &quiet.deployment,
        &plan(quiet.identity, door()),
        &WatchLimits::default(),
        &quiet.cx,
    )?;
    assert!(report.candidates().is_empty());
    assert!(report.frames().iter().all(|f| f.boxes.is_empty()));
    Ok(())
}

#[test]
fn invalid_plans_are_typed_refusals() -> TestResult {
    let f = fixture("plan", &scene(false)?)?;
    let mut too_long = plan(f.identity, door());
    too_long.segment_count = MAX_WATCH_FRAMES + 1;
    let mut bad_zone = plan(f.identity, door());
    bad_zone.zones[0].zone_id = "no spaces".to_owned();
    let mut no_zone = plan(f.identity, door());
    no_zone.zones.clear();
    for invalid in [too_long, bad_zone, no_zone] {
        let refused = WatchReport::analyze(&f.deployment, &invalid, &WatchLimits::default(), &f.cx);
        assert!(matches!(refused, Err(WatchError::InvalidPlan(_))));
    }
    let mut beyond = plan(f.identity, door());
    beyond.first_segment = 1;
    let refused = WatchReport::analyze(&f.deployment, &beyond, &WatchLimits::default(), &f.cx);
    assert!(
        matches!(&refused, Err(WatchError::Decode(error)) if matches!(**error, RecordedDecodeError::Unavailable)),
        "{refused:?}"
    );
    Ok(())
}
