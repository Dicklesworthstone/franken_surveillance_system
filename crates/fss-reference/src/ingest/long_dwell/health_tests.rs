#![forbid(unsafe_code)]
//! Actual retained MJPEG, native decoding, privacy, screening and guarded publication.

use super::*;
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
use crate::ingest::sensor_health::HealthFinding;
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId, TimestampNs};
use std::fs;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-dwell-health";
const FRAMES: usize = 300;
const WIDTH: u32 = 48;
const HEIGHT: u32 = 32;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-dwell-health-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Scene {
    Frozen,
    Changing,
    MaskedChange,
}
fn source(scene: Scene, corrupt: bool, gap: bool) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let background = if matches!(scene, Scene::Changing) {
            40 + (index % 2) as u8 * 8
        } else {
            40
        };
        let mut pixels = vec![background; (WIDTH * HEIGHT) as usize];
        if index >= 3 {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        if matches!(scene, Scene::MaskedChange) {
            for y in 0..8 {
                for x in 40..48 {
                    pixels[y * WIDTH as usize + x] = 100 + (index % 2) as u8 * 80;
                }
            }
        }
        let mut frame = encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?;
        if corrupt && index == 150 {
            let sof = frame
                .windows(2)
                .position(|w| w == [0xff, 0xc0])
                .ok_or("SOF0 missing")?;
            frame[sof + 1] = 0xc2;
        }
        if gap && index == 150 {
            bytes.extend_from_slice(b"omitted-source-bytes");
        }
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
    fn new(label: &str, scene: Scene, corrupt: bool, gap: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let path = directory.0.join("camera.mjpeg");
        let bytes = source(scene, corrupt, gap)?;
        fs::write(&path, &bytes)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:dwell-health".into(),
            operation_id: OperationId::parse("operation:dwell-health")?,
            principal: "principal:dwell-health".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(128 * 1024 * 1024)
                .storage_operations(65_536)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let receipt = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &path,
                SensorId::parse("sensor:dwell-health")?,
                StreamId::parse("stream:dwell-health")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(path)?;
        let plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 32,
                height: 32,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            input_bytes: bytes.len() as u64,
            _directory: directory,
        })
    }
    fn scan(
        &self,
        screened: bool,
        tolerant: bool,
        limits: &LongDwellLimits,
    ) -> Test<LongDwellReport> {
        let options = WatchOptions {
            tolerate_decode_refusals: tolerant,
        };
        let analyze = if screened {
            LongDwellReport::analyze_screened
        } else {
            LongDwellReport::analyze
        };
        Ok(analyze(
            &self.deployment,
            &self.plan,
            rule(),
            options,
            limits,
            &self.cx,
        )?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
    fn mask(&mut self) -> Test {
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse("sensor:dwell-health")?,
            [WIDTH, HEIGHT],
            &[[40, 0, 8, 8]],
        )?;
        let approval = preview_mask(&self.deployment, &policy)?.approval;
        declare_mask(&mut self.deployment, &policy, approval, &self.cx)?;
        Ok(())
    }
}
fn rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 20_000_000_000,
        maximum_sample_gap_ns: 100_000_000,
        minimum_observations: 3,
    }
}
fn approvals(report: &LongDwellReport) -> BTreeSet<ContentDigest> {
    report
        .candidates()
        .iter()
        .map(LongDwellCandidate::proposal_digest)
        .collect()
}

#[test]
fn frozen_frames_keep_the_candidate_but_cannot_publish_a_screened_event() -> Test {
    let mut f = Fixture::new("freeze", Scene::Frozen, false, false)?;
    let before = f.snapshot();
    let plain = f.scan(false, false, &LongDwellLimits::default())?;
    let mut screened = f.scan(true, false, &LongDwellLimits::default())?;
    assert_eq!(plain.candidates().len(), 1);
    assert_eq!(screened.candidates().len(), 1);
    assert_eq!(
        plain.candidates()[0].span(),
        screened.candidates()[0].span()
    );
    let health = screened.health_summary().ok_or("screen absent")?;
    assert!(health.complete());
    assert_eq!(health.status(), "suspected_degradation");
    assert!(
        health
            .findings()
            .iter()
            .any(|r| r.finding == HealthFinding::ExactFrameRepetition)
    );
    assert!(
        screened
            .to_json(0, Some("fss-event watch"))?
            .contains("\"publish_command\":null")
    );
    let approved = approvals(&screened);
    assert!(
        matches!(screened.publish(&mut f.deployment, &approved, &f.cx),
        Err(WatchError::InvalidPlan(reason)) if reason == HEALTH_PUBLICATION_BLOCKED)
    );
    assert_eq!(f.snapshot(), before);
    assert_eq!(f.deployment.effects().operations().count(), 0);
    Ok(())
}

#[test]
fn screening_is_single_decode_and_approval_isolated_without_quality_promotion() -> Test {
    let mut f = Fixture::new("single-pass", Scene::Changing, false, false)?;
    let plain = f.scan(false, false, &LongDwellLimits::default())?;
    let mut screened = f.scan(true, false, &LongDwellLimits::default())?;
    let before = f.snapshot();
    let health = screened.health_summary().ok_or("screen absent")?;
    assert_eq!(health.status(), "no_findings");
    assert!(health.complete());
    assert_eq!(health.frames_screened(), FRAMES);
    assert_eq!(
        health.samples_screened(),
        FRAMES as u64 * u64::from(WIDTH * HEIGHT)
    );
    assert_eq!(screened.source_chunk_bytes_read(), f.input_bytes);
    assert_eq!(
        screened.source_chunk_bytes_read(),
        plain.source_chunk_bytes_read()
    );
    assert_eq!(screened.jpeg_work, plain.jpeg_work);
    assert_eq!(screened.candidates().len(), 1);
    assert_ne!(screened.analysis_digest(), plain.analysis_digest());
    assert!(!plain.to_json(0, None)?.contains("sensor_health"));
    assert!(
        screened
            .to_json(0, None)?
            .contains("\"healthy_proved\":false")
    );
    assert!(
        screened
            .analysis
            .windows(health_policy_bytes().len())
            .any(|v| v == health_policy_bytes())
    );
    let measurement_domain = b"fss.sensor_health.observation.v1";
    assert_eq!(
        screened
            .analysis
            .windows(measurement_domain.len())
            .filter(|v| *v == measurement_domain)
            .count(),
        FRAMES
    );
    assert!(matches!(
        screened.publish(&mut f.deployment, &approvals(&plain), &f.cx),
        Err(WatchError::StaleApproval(_))
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn a_no_findings_publication_retains_measurements_and_survives_cold_retry() -> Test {
    let mut f = Fixture::new("cold", Scene::Changing, false, false)?;
    let mut report = f.scan(true, false, &LongDwellLimits::default())?;
    let approved = approvals(&report);
    assert!(!approved.is_empty());
    assert_eq!(report.publish(&mut f.deployment, &approved, &f.cx)?, 1);
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(report.analysis_digest())?,
        report.analysis
    );
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(health_policy_digest())?,
        health_policy_bytes()
    );
    assert_eq!(
        report.candidates()[0].event().state,
        EventState::Indeterminate
    );
    assert!(
        report.candidates()[0]
            .event()
            .evidence
            .iter()
            .all(|e| !e.supports)
    );
    let after = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let mut retry = LongDwellReport::analyze_screened(
        &reopened,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &f.cx,
    )?;
    assert_eq!(retry.analysis_digest(), report.analysis_digest());
    assert_eq!(retry.health_summary(), report.health_summary());
    assert_eq!(retry.publish(&mut reopened, &approved, &f.cx)?, 0);
    assert_eq!(*reopened.current_anchor(), after.0);
    assert_eq!(reopened.effects().last_root(), after.1);
    Ok(())
}

#[test]
fn a_tolerated_decode_gap_cannot_be_reported_as_a_complete_screen() -> Test {
    let mut f = Fixture::new("decode-gap", Scene::Changing, true, false)?;
    let before = f.snapshot();
    let mut report = f.scan(true, true, &LongDwellLimits::default())?;
    let health = report.health_summary().ok_or("screen absent")?;
    assert!(!health.complete());
    assert_eq!(health.frames_screened(), FRAMES - 1);
    assert_eq!(
        health.samples_screened(),
        (FRAMES as u64 - 1) * u64::from(WIDTH * HEIGHT)
    );
    assert!(report.publication_blocked());
    assert_eq!(report.refusals[0].first_segment, 150);
    assert!(
        matches!(report.publish(&mut f.deployment, &BTreeSet::new(), &f.cx),
        Err(WatchError::InvalidPlan(reason)) if reason == HEALTH_PUBLICATION_BLOCKED)
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn hidden_pixel_changes_cannot_clear_frozen_visible_pixels() -> Test {
    let mut f = Fixture::new("masked", Scene::MaskedChange, false, false)?;
    let unmasked = f.scan(true, false, &LongDwellLimits::default())?;
    assert!(
        !unmasked
            .health_summary()
            .ok_or("screen absent")?
            .findings()
            .iter()
            .any(|r| r.finding == HealthFinding::ExactFrameRepetition)
    );
    f.mask()?;
    let before = f.snapshot();
    let mut masked = f.scan(true, false, &LongDwellLimits::default())?;
    assert!(
        masked
            .health_summary()
            .ok_or("screen absent")?
            .findings()
            .iter()
            .any(|r| r.finding == HealthFinding::ExactFrameRepetition)
    );
    assert_ne!(unmasked.analysis_digest(), masked.analysis_digest());
    let approved = approvals(&masked);
    assert!(masked.publish(&mut f.deployment, &approved, &f.cx).is_err());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn a_new_privacy_generation_invalidates_an_unsent_screened_proposal() -> Test {
    let mut f = Fixture::new("mask-change", Scene::Changing, false, false)?;
    let mut report = f.scan(true, false, &LongDwellLimits::default())?;
    assert!(!report.publication_blocked());
    let approved = approvals(&report);
    f.mask()?;
    let before = f.snapshot();
    assert!(matches!(
        report.publish(&mut f.deployment, &approved, &f.cx),
        Err(WatchError::InvalidPlan(_))
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn row_cancellation_and_health_trace_exhaustion_do_not_publish() -> Test {
    let f = Fixture::new("trace-limit", Scene::Changing, false, false)?;
    let plain = f.scan(false, false, &LongDwellLimits::default())?;
    let limits = LongDwellLimits {
        maximum_trace_bytes: plain.analysis.len(),
        ..LongDwellLimits::default()
    };
    let before = f.snapshot();
    LongDwellReport::analyze(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &limits,
        &f.cx,
    )?;
    assert!(matches!(
        LongDwellReport::analyze_screened(
            &f.deployment,
            &f.plan,
            rule(),
            WatchOptions::default(),
            &limits,
            &f.cx
        ),
        Err(WatchError::Limit)
    ));
    assert_eq!(f.snapshot(), before);
    f.cx.set_cancel_at_checkpoint_occurrence("sensor_health:row", 40);
    assert!(
        matches!(LongDwellReport::analyze_screened(&f.deployment, &f.plan, rule(), WatchOptions::default(), &LongDwellLimits::default(), &f.cx),
        Err(WatchError::Decode(e)) if matches!(*e, RecordedDecodeError::Cancelled))
    );
    assert_eq!(f.snapshot(), before);
    assert!(f.cx.is_drain_completed());
    Ok(())
}

#[test]
fn omitted_source_time_cannot_turn_a_no_findings_scan_into_admission() -> Test {
    let f = Fixture::new("source-gap", Scene::Changing, false, true)?;
    let before = f.snapshot();
    let report = f.scan(true, true, &LongDwellLimits::default())?;
    assert!(!report.health_summary().ok_or("screen absent")?.complete());
    assert!(report.publication_blocked());
    assert_eq!(report.unreliable, FRAMES);
    assert_eq!(f.snapshot(), before);
    Ok(())
}
