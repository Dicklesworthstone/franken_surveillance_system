#![forbid(unsafe_code)]
//! Cached native results must remain source-current at the actual fusion entry point.
//! Synthetic footage establishes bounded composition, not detector accuracy or calibration.

use super::{EventFusionError, EventFusionProfile, EventFusionReport, Test, pin, spec};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, LedgerAnchor, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome};
use fss_reference::ingest::long_dwell::{LongDwellDetector, LongDwellLimits, LongDwellReport};
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

const SITE: &str = "site:dwell-fusion-contract";
const PRINCIPAL: &str = "principal:dwell-fusion-contract";
const FRAMES: usize = 170;
const DETECTOR_PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const DETECTOR_PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-dwell-fusion-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:dwell-fusion-contract".into(),
        operation_id: OperationId::parse("operation:dwell-fusion-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn jpeg(square: bool) -> Test<Vec<u8>> {
    let mut pixels = vec![40; 48 * 32];
    if square {
        for y in 8..24 {
            for x in 8..24 {
                pixels[y * 48 + x] = 220;
            }
        }
    }
    Ok(encode_jpeg(
        48,
        32,
        &pixels,
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, active: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let input = directory.0.join("source.mjpeg");
        let quiet = jpeg(false)?;
        let occupied = jpeg(true)?;
        let mut bytes = Vec::new();
        for frame in 0..FRAMES {
            bytes.extend_from_slice(if active && frame >= 150 {
                &occupied
            } else {
                &quiet
            });
        }
        fs::write(&input, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:long-dwell-fixture")?,
            StreamId::parse("stream:dwell-fusion-contract")?,
        )
        .with_limits(limits)
        .with_receive_time(TimestampNs(1_000_000_000_000))
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::remove_file(&input)?;
        let plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 48,
                height: 32,
            }],
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            _directory: directory,
        })
    }

    fn package(&self, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
        Ok(RgbDetectorPackage::load(
            DETECTOR_PACKAGE,
            ContentDigest::parse(DETECTOR_PACKAGE_DIGEST)?,
            1 << 36,
            &self.cx,
            scalar,
        )?)
    }

    fn analyze(&self, detector: &LongDwellDetector<'_>, screened: bool) -> Test<LongDwellReport> {
        Ok(LongDwellReport::analyze_with_detector(
            &self.deployment,
            &self.plan,
            DwellPolicy {
                minimum_duration_ns: 200_000_000,
                maximum_sample_gap_ns: 100_000_000,
                minimum_observations: 3,
            },
            WatchOptions::default(),
            &LongDwellLimits::default(),
            detector,
            screened,
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
}

fn profile_for(report: &LongDwellReport) -> Test<EventFusionProfile> {
    let mut request = spec()?;
    request.plan_digest = report.analysis_digest();
    request.cascade_digest = report.detector_recipe().ok_or("trained recipe")?.digest();
    request.calibrations[0].sensor = report.sensor_id().as_str().to_owned();
    Ok(EventFusionProfile::for_long_dwell(
        request,
        report.analysis_root(),
    )?)
}

#[test]
fn cached_native_episode_advice_keeps_proposals_and_work_but_refuses_scope_or_authority_changes()
-> Test {
    let mut f = Fixture::new("late-episode", true)?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let detector = LongDwellDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig {
            max_inferences: 1,
            frames_per_track: 3,
            ..CascadeConfig::default()
        },
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    let native = f.analyze(&detector, false)?;
    assert_eq!(native.candidates().len(), 1);
    let candidate = &native.candidates()[0];
    assert!(candidate.span().first.position >= 150);
    assert_eq!(candidate.class_evidence().len(), 3);
    assert_eq!(
        candidate
            .class_evidence()
            .iter()
            .filter(|e| matches!(&e.outcome, EvidenceOutcome::BudgetExhausted))
            .count(),
        2
    );
    let native_json = native.to_json(f.deployment.current_anchor().commit_sequence, None)?;
    let profile = profile_for(&native)?;
    let advice = EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &f.cx)?;
    let result = &advice.candidates()[0];
    assert_eq!(result.candidate, candidate.identity());
    assert_eq!(result.native_proposal, candidate.proposal_digest());
    assert_eq!(result.native_provenance, candidate.provenance_root());
    assert_eq!(result.scores.len(), candidate.class_evidence().len());
    assert_eq!(
        result
            .scores
            .iter()
            .filter_map(|link| link.source_record)
            .collect::<BTreeSet<_>>(),
        candidate
            .class_evidence()
            .iter()
            .map(|e| e.digest)
            .collect::<BTreeSet<_>>()
    );
    for skipped in candidate
        .class_evidence()
        .iter()
        .filter(|e| matches!(&e.outcome, EvidenceOutcome::BudgetExhausted))
    {
        let link = result
            .scores
            .iter()
            .find(|link| link.source_record == Some(skipped.digest))
            .ok_or("retained skipped observation")?;
        assert!(
            link.score_bits.is_none() && link.score_ppm.is_none() && link.calibration.is_none()
        );
    }
    assert_eq!(
        EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &f.cx,)?.digest(),
        advice.digest()
    );
    let json = advice.to_json()?;
    assert!(json.contains("fss.event_class_fusion_report.v4"));
    assert!(json.contains("\"continuous_occupancy_certified\":false"));
    assert!(json.contains("\"coverage_witness_supplied\":false"));
    assert!(json.contains("\"maximum_candidates\":32"));
    assert_eq!(
        native.to_json(f.deployment.current_anchor().commit_sequence, None)?,
        native_json
    );
    assert_eq!(f.snapshot(), before);

    for slot in 0..4 {
        let mut request = profile.spec().clone();
        let mut root = native.analysis_root();
        match slot {
            0 => request.plan_digest = f.plan.digest(),
            1 => request.cascade_digest = pin("different recipe"),
            2 => root = pin("different complete source"),
            _ => request.calibrations[0].sensor = "sensor:foreign".into(),
        }
        let wrong = EventFusionProfile::for_long_dwell(request, root)?;
        assert!(matches!(
            EventFusionReport::long_dwell(&native, &package, &wrong, &f.deployment, &f.cx),
            Err(EventFusionError::Scope)
        ));
    }
    let watch = EventFusionProfile::for_long_watch(profile.spec().clone(), native.analysis_root())?;
    assert!(matches!(
        EventFusionReport::long_dwell(&native, &package, &watch, &f.deployment, &f.cx),
        Err(EventFusionError::Scope)
    ));
    let cancellation = context(f.deployment.root())?;
    cancellation.set_cancel_at_checkpoint("long_dwell:derived_source_checked");
    assert!(matches!(
        EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &cancellation),
        Err(EventFusionError::Cancelled)
    ));
    assert!(cancellation.is_drain_completed());
    assert_eq!(f.snapshot(), before);

    // A mask outside the observed episode still advances the exact authority basis. The
    // unchanged cached native proposal cannot silently adopt that new source authorization.
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-dwell-fixture")?,
        [48, 32],
        &[[40, 0, 4, 4]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let changed = f.snapshot();
    assert!(matches!(
        EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &f.cx),
        Err(EventFusionError::StaleBasis)
    ));
    assert_eq!(f.snapshot(), changed);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn empty_episode_advice_still_requires_source_custody_and_requested_health_clearance() -> Test {
    let f = Fixture::new("empty-source", false)?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let detector = LongDwellDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    let native = f.analyze(&detector, false)?;
    assert!(native.candidates().is_empty());
    assert!(
        native
            .detector_cascade()
            .ok_or("retained cascade")?
            .inferred_segments()
            .is_empty()
    );
    let profile = profile_for(&native)?;
    let advice = EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &f.cx)?;
    assert!(advice.candidates().is_empty());
    let json = advice.to_json()?;
    assert!(json.contains("\"complete_candidate_analysis\":true"));
    assert!(json.contains("\"class_absence_certified\":false"));
    assert!(json.contains("\"continuous_occupancy_certified\":false"));
    assert!(json.contains("\"effect_authority\":false"));
    assert_eq!(f.snapshot(), before);

    let screened = f.analyze(&detector, true)?;
    assert!(screened.publication_blocked());
    let screened_profile = profile_for(&screened)?;
    assert!(matches!(
        EventFusionReport::long_dwell(&screened, &package, &screened_profile, &f.deployment, &f.cx),
        Err(EventFusionError::Evidence)
    ));
    assert_eq!(f.snapshot(), before);

    let retained = RetainedFileImport::open(
        &f.deployment,
        f.plan.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let source = retained.manifest().ordered_chunks[0];
    let path = f.deployment.publisher().spool().object_path(source);
    fs::remove_file(&path)?;
    let missing = f.snapshot();
    assert!(matches!(
        EventFusionReport::long_dwell(&native, &package, &profile, &f.deployment, &f.cx),
        Err(EventFusionError::Evidence)
    ));
    assert!(
        !path.exists(),
        "derived advice cannot repair missing custody"
    );
    assert_eq!(f.snapshot(), missing);
    scalar.drain_and_finalize();
    Ok(())
}
