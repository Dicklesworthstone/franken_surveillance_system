#![forbid(unsafe_code)]
//! Real retained source -> native JPEG -> foreground -> tracker -> streaming dwell -> event.

use super::*;
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId, TimestampNs};
use super::super::recorded_decode::ComponentInterpretation;
use super::super::recorded_watch::{WatchDetectorConfig, WatchReport, WatchTrackerConfig};
use std::fs;
use std::path::Path;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-dwell-test";
const FRAMES: usize = 300;
const WIDTH: u32 = 48;
const HEIGHT: u32 = 32;
const PERIOD: u64 = 100_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-long-dwell-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("directory capacity".into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-dwell".into(), operation_id: OperationId::parse("operation:long-dwell")?,
        principal: principal.into(), capabilities: vec!["ADP-REPLAY-001".into()], deadline: None,
        priority: 10, budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
fn scene(moving: bool, miss: Option<usize>, corrupt: Option<usize>, gap: bool) -> Test<Vec<u8>> {
    let config = JpegConfig { quality: 90, subsampling: Subsampling::Grayscale,
        restart_interval: 0, custom_markers: Vec::new() };
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if moving && index >= 3 && miss != Some(index) {
            for y in 8..24 { for x in 8..24 { pixels[y * WIDTH as usize + x] = 220; } }
        }
        let mut frame = encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?;
        if corrupt == Some(index) {
            // An independently delimited JPEG with unsupported progressive coding. Source
            // framing remains complete, so this tests decode refusal, not missing bytes.
            let sof = frame.windows(2).position(|w| w == [0xff, 0xc0]).ok_or("SOF0 absent")?;
            frame[sof + 1] = 0xc2;
        }
        if gap && index == 150 { bytes.extend_from_slice(b"omitted-source-bytes"); }
        bytes.extend(frame);
    }
    Ok(bytes)
}
struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    input_bytes: u64,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], known_time: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let path = directory.0.join("source.mjpeg");
        fs::write(&path, bytes)?;
        let cx = context(&root, "principal:long-dwell-test")?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let mut request = FileIngestRequest::new(&path, SensorId::parse("sensor:long-dwell")?, StreamId::parse("stream:long-dwell")?)
            .with_limits(limits).with_receive_time(TimestampNs(1_000_000_000_000));
        if known_time { request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?); }
        let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        // Every analysis and cold retry below must work after the original input disappears.
        fs::remove_file(path)?;
        let plan = WatchPlan {
            import_identity: receipt.import_identity, interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0, segment_count: FRAMES,
            zones: vec![WatchZone { zone_id: "porch".into(), x: 0, y: 0, width: WIDTH, height: HEIGHT }],
            detector: WatchDetectorConfig::default(), tracker: WatchTrackerConfig::default(),
        };
        Ok(Self { deployment, cx, plan, input_bytes: bytes.len() as u64, _directory: directory })
    }
    fn analyze(&self, rule: DwellPolicy) -> Test<LongDwellReport> {
        Ok(LongDwellReport::analyze(&self.deployment, &self.plan, rule, WatchOptions::default(), &LongDwellLimits::default(), &self.cx)?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (self.deployment.current_anchor().clone(), self.deployment.effects().last_root(), self.deployment.publisher().spool().digests().count())
    }
}
fn rule() -> DwellPolicy {
    DwellPolicy { minimum_duration_ns: 200 * PERIOD, maximum_sample_gap_ns: PERIOD, minimum_observations: 3 }
}

#[test]
fn a_real_three_hundred_frame_episode_crosses_the_old_window_limit() -> Test {
    let f = Fixture::new("long", &scene(true, None, None, false)?, true)?;
    let before = f.snapshot();
    assert!(matches!(WatchReport::analyze(&f.deployment, &f.plan, &WatchLimits::default(), &f.cx), Err(WatchError::InvalidPlan(_))));
    let report = f.analyze(rule())?;
    assert_eq!(f.snapshot(), before);
    assert_eq!(report.frames_decoded(), FRAMES);
    assert_eq!(report.candidates().len(), 1);
    let span = report.candidates()[0].span();
    assert_eq!(span.first.position, 5);
    assert_eq!(span.trigger.position, 205);
    assert_eq!(span.last.position, FRAMES - 1);
    assert_eq!(span.observations, FRAMES - 5);
    assert_eq!(report.source_chunk_bytes_read(), f.input_bytes);
    assert_eq!(report.analysis_digest(), f.analyze(rule())?.analysis_digest());
    Ok(())
}

#[test]
fn publication_is_source_closed_and_exact_cold_retry_does_not_duplicate() -> Test {
    let mut f = Fixture::new("publish", &scene(true, None, None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approvals = report.candidates().iter().map(LongDwellCandidate::proposal_digest).collect();
    assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 1);
    let event = report.candidates()[0].event();
    let (read, _) = f.deployment.current_event_authority(&event.event_id)?;
    assert_eq!(read.revision_digest(), event.revision_digest());
    assert_eq!(read.state, EventState::Indeterminate);
    assert_eq!(read.kind, EventKind::Unclassified);
    assert!(read.evidence.iter().all(|item| !item.supports));
    assert_eq!(f.deployment.effects().operations().count(), 0);
    assert_eq!(f.deployment.publisher().spool().read(report.analysis_digest())?, report.analysis);
    let after = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let mut retry = LongDwellReport::analyze(&reopened, &f.plan, rule(), WatchOptions::default(), &LongDwellLimits::default(), &f.cx)?;
    assert_eq!(retry.analysis_digest(), report.analysis_digest());
    assert_eq!(retry.candidates()[0].status(), WatchStatus::AlreadyPublished);
    assert_eq!(retry.publish(&mut reopened, &approvals, &f.cx)?, 0);
    assert_eq!(*reopened.current_anchor(), after.0);
    Ok(())
}

#[test]
fn an_actual_miss_splits_dwell_even_when_the_tracker_retains_the_id() -> Test {
    let f = Fixture::new("miss", &scene(true, Some(150), None, false)?, true)?;
    let report = f.analyze(DwellPolicy { minimum_duration_ns: 10 * PERIOD, ..rule() })?;
    assert_eq!(report.candidates().len(), 2);
    assert_eq!(report.candidates()[0].span().last.position, 149);
    assert_eq!(report.candidates()[1].span().first.position, 151);
    assert!(f.analyze(rule())?.candidates().is_empty());
    Ok(())
}

#[test]
fn every_aggregate_budget_refuses_the_whole_analysis_without_writes() -> Test {
    let f = Fixture::new("limits", &scene(true, None, None, false)?, true)?;
    let before = f.snapshot();
    let defaults = LongDwellLimits::default();
    for limits in [
        LongDwellLimits { maximum_source_chunk_bytes: 1, ..defaults },
        LongDwellLimits { maximum_pixel_samples: u64::from(WIDTH * HEIGHT) * 20, ..defaults },
        LongDwellLimits { maximum_assignment_work: 1, ..defaults },
        LongDwellLimits { maximum_trace_bytes: 100, ..defaults },
    ] {
        assert!(matches!(LongDwellReport::analyze(&f.deployment, &f.plan, rule(), WatchOptions::default(), &limits, &f.cx), Err(WatchError::Limit)));
        assert_eq!(f.snapshot(), before);
    }
    Ok(())
}

#[test]
fn unknown_capture_time_is_refused_before_codec_work() -> Test {
    let f = Fixture::new("time", &scene(true, None, None, false)?, false)?;
    let mut limits = LongDwellLimits::default();
    limits.decode.jpeg_work_units = 0;
    assert!(matches!(LongDwellReport::analyze(&f.deployment, &f.plan, rule(), WatchOptions::default(), &limits, &f.cx), Err(WatchError::InvalidPlan("long dwell requires explicit capture-time hints"))));
    Ok(())
}

#[test]
fn privacy_change_invalidates_a_preview_and_masked_motion_creates_no_episode() -> Test {
    let mut f = Fixture::new("mask", &scene(true, None, None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let policy = PrivacyMaskPolicy::new(SensorId::parse("sensor:long-dwell")?, [WIDTH, HEIGHT], &[[0, 0, WIDTH, HEIGHT]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let after_mask = f.snapshot();
    assert!(matches!(report.publish(&mut f.deployment, &approvals, &f.cx), Err(WatchError::InvalidPlan(_))));
    assert_eq!(f.snapshot(), after_mask);
    let masked = f.analyze(rule())?;
    assert!(masked.candidates().is_empty());
    assert_eq!(masked.masked_zones, 1);
    assert_ne!(masked.analysis_digest(), report.analysis_digest());
    Ok(())
}

#[test]
fn wrong_rule_and_actor_cannot_reuse_a_valid_approval() -> Test {
    let mut f = Fixture::new("approval", &scene(true, None, None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approval = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let mut changed = f.analyze(DwellPolicy { minimum_duration_ns: 201 * PERIOD, ..rule() })?;
    let before = f.snapshot();
    assert!(matches!(changed.publish(&mut f.deployment, &approval, &f.cx), Err(WatchError::StaleApproval(_))));
    let other = context(f.deployment.root(), "principal:another-actor")?;
    assert!(matches!(report.publish(&mut f.deployment, &approval, &other), Err(WatchError::Conflict)));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn retained_source_cursor_matches_independent_segment_assembly() -> Test {
    let f = Fixture::new("cursor", &scene(true, None, None, false)?, true)?;
    let limits = RetainedReadLimits::default();
    let retained = RetainedFileImport::open(&f.deployment, f.plan.import_identity, limits, &f.cx)?;
    let mut cursor = ChunkCursor::new(f.input_bytes);
    for segment in 0..FRAMES {
        assert_eq!(cursor.segment(&f.deployment, &retained, segment, limits, &f.cx)?,
            retained.read_segment(&f.deployment, segment, limits, &f.cx)?);
    }
    assert_eq!(cursor.bytes_read(), f.input_bytes);
    assert!(matches!(cursor.segment(&f.deployment, &retained, 0, limits, &f.cx), Err(WatchError::Conflict)));
    Ok(())
}

#[test]
fn tolerated_decode_refusal_resets_foreground_and_temporal_state() -> Test {
    let f = Fixture::new("decode", &scene(true, None, Some(150), false)?, true)?;
    assert!(f.analyze(rule()).is_err());
    let report = LongDwellReport::analyze(&f.deployment, &f.plan, rule(), WatchOptions { tolerate_decode_refusals: true }, &LongDwellLimits::default(), &f.cx)?;
    assert_eq!(report.frames_decoded(), FRAMES - 1);
    assert_eq!(report.refusals.len(), 1);
    assert_eq!(report.refusals[0].first_segment, 150);
    assert!(report.restarts > 0);
    assert!(report.candidates().is_empty());
    Ok(())
}

#[test]
fn omitted_bytes_never_become_trustworthy_index_derived_elapsed_time() -> Test {
    let f = Fixture::new("gap", &scene(true, None, None, true)?, true)?;
    assert!(f.analyze(rule()).is_err());
    let report = LongDwellReport::analyze(&f.deployment, &f.plan, rule(), WatchOptions { tolerate_decode_refusals: true }, &LongDwellLimits::default(), &f.cx)?;
    assert!(report.candidates().is_empty());
    assert_eq!(report.unreliable, report.decoded);
    assert!(report.to_json(0, None)?.contains("\"absence_certifiable\":false"));
    Ok(())
}

#[test]
fn cancellation_after_provenance_is_resumable_without_a_false_event() -> Test {
    let mut f = Fixture::new("cancel", &scene(true, None, None, false)?, true)?;
    let mut report = f.analyze(rule())?;
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let event_id = report.candidates()[0].event().event_id.clone();
    f.cx.set_cancel_at_checkpoint("long_dwell:commit");
    assert!(report.publish(&mut f.deployment, &approvals, &f.cx).is_err());
    assert!(f.cx.is_drain_completed());
    assert!(!f.deployment.ledger().current().objects.keys().any(|id| id.as_str() == format!("object:event:{event_id}")));
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let cx = context(&root, "principal:long-dwell-test")?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let mut retry = LongDwellReport::analyze(&reopened, &f.plan, rule(), WatchOptions::default(), &LongDwellLimits::default(), &cx)?;
    assert_eq!(retry.analysis_digest(), report.analysis_digest());
    assert_eq!(retry.publish(&mut reopened, &approvals, &cx)?, 1);
    Ok(())
}

#[test]
fn analysis_cancellation_and_static_zero_candidates_never_create_authority() -> Test {
    let f = Fixture::new("static", &scene(false, None, None, false)?, true)?;
    let before = f.snapshot();
    assert!(f.analyze(rule())?.candidates().is_empty());
    f.cx.set_cancel_at_checkpoint("long_dwell:decoded");
    assert!(f.analyze(rule()).is_err());
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}
