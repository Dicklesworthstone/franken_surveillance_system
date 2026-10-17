#![forbid(unsafe_code)]
//! Native ground projection beyond former windows, discontinuities and publication prerequisites.
//! Synthetic recordings prove the executable composition, not detection quality or calibration.

use super::{EventFusionError, EventFusionProfile, EventFusionReport, SensorCalibration, spec};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, LedgerAnchor, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::detector_cascade::CascadeConfig;
use fss_reference::ingest::long_watch::LongWatchDetector;
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_corroboration::streaming::{
    LongCorroborationLimits, LongCorroborationReport,
};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationDependencies, CorroborationGates, CorroborationOptions,
    CorroborationPlan, GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-corroboration-contract";
const PRINCIPAL: &str = "principal:long-corroboration-contract";
const IDENTITY: [f64; 9] = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
const DETECTOR_PACKAGE: &[u8] =
    include_bytes!("../../../../../../models/yolox-nano/yolox_nano.fmpk");
const DETECTOR_PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-paired-fusion-{label}-{}-{attempt}",
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
        trace_id: "trace:long-corroboration-contract".into(),
        operation_id: OperationId::parse("operation:long-corroboration-contract")?,
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

fn jpeg(x: Option<usize>) -> Test<Vec<u8>> {
    let mut pixels = vec![40_u8; 48 * 32];
    if let Some(x) = x {
        for y in 8..24 {
            for column in x..x + 16 {
                pixels[y * 48 + column] = 220;
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
fn scene(frames: usize, moving: bool, decode_gap: bool, source_gap: bool) -> Test<Vec<u8>> {
    let quiet = jpeg(None)?;
    let squares = (0..=24).map(|x| jpeg(Some(x))).collect::<Test<Vec<_>>>()?;
    let mut unsupported = quiet.clone();
    let sof = unsupported
        .windows(2)
        .position(|w| w == [0xff, 0xc0])
        .ok_or("SOF0")?;
    unsupported[sof + 1] = 0xc2;
    let mut result = Vec::new();
    for position in 0..frames {
        if source_gap && position == 20 {
            result.extend_from_slice(b"unaccounted-source-gap");
        }
        if decode_gap && position == 20 {
            result.extend_from_slice(&unsupported);
        } else if position < 3 || ((decode_gap || source_gap) && (20..24).contains(&position)) {
            result.extend_from_slice(&quiet);
        } else {
            let x = if moving {
                4 + position.saturating_sub(128).min(20)
            } else {
                8
            };
            result.extend_from_slice(&squares[x]);
        }
    }
    Ok(result)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: CorroborationPlan,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut imports = Vec::new();
        for name in ["east", "west"] {
            let input = directory.0.join(format!("{name}.{extension}"));
            fs::write(&input, bytes)?;
            let mut limits = FileIngestLimits::standard();
            limits.max_segments = 1024;
            limits.chunk_bytes = 4096;
            let request = FileIngestRequest::new(
                &input,
                SensorId::parse(format!("sensor:long-corroboration-{name}"))?,
                StreamId::parse(format!("stream:long-corroboration-{name}"))?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
            imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
            fs::remove_file(input)?;
        }
        let plan = CorroborationPlan {
            cameras: [
                CorroborationCamera {
                    name: "east".into(),
                    import_identity: imports[0],
                    homography: GroundHomography { matrix: IDENTITY },
                },
                CorroborationCamera {
                    name: "west".into(),
                    import_identity: imports[1],
                    homography: GroundHomography { matrix: IDENTITY },
                },
            ],
            interpretation: if extension == "mjpeg" {
                ComponentInterpretation::Grayscale
            } else {
                ComponentInterpretation::YCbCr
            },
            zones: vec![GroundZone {
                zone_id: "door".into(),
                x: 8.0,
                y: 16.0,
                width: 16.0,
                height: 16.0,
            }],
            gates: CorroborationGates {
                time_gate_ns: 200_000_000,
                distance_gate: 4.0,
            },
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
    fn analyze(&self, tolerant: bool) -> Test<LongCorroborationReport> {
        Ok(LongCorroborationReport::analyze(
            &self.deployment,
            &self.plan,
            CorroborationOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongCorroborationLimits::default(),
            &CorroborationDependencies::default(),
            &self.cx,
        )?)
    }
    fn trained_package(&self, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
        Ok(RgbDetectorPackage::load(
            DETECTOR_PACKAGE,
            ContentDigest::parse(DETECTOR_PACKAGE_DIGEST)?,
            1 << 36,
            &self.cx,
            scalar,
        )?)
    }
    fn annotate(
        &self,
        detector: &LongWatchDetector<'_>,
        tolerant: bool,
    ) -> Test<LongCorroborationReport> {
        Ok(LongCorroborationReport::analyze_with_detector(
            &self.deployment,
            &self.plan,
            CorroborationOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongCorroborationLimits::default(),
            &CorroborationDependencies::default(),
            false,
            detector,
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
    fn mask(&mut self, camera: &str, rectangle: [u32; 4]) -> Test {
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse(format!("sensor:long-corroboration-{camera}"))?,
            [48, 32],
            &[rectangle],
        )?;
        let approval = preview_mask(&self.deployment, &policy)?.approval;
        declare_mask(&mut self.deployment, &policy, approval, &self.cx)?;
        Ok(())
    }
}

fn profile_for(report: &LongCorroborationReport) -> Test<EventFusionProfile> {
    let mut spec = spec()?;
    spec.plan_digest = report.analysis_digest();
    spec.cascade_digest = report.detector_recipe().ok_or("trained recipe")?.digest();
    let cameras: Vec<_> = report.source_cameras().collect();
    assert_eq!(cameras.len(), 2);
    let template = spec.calibrations[0].calibration.clone();
    spec.calibrations = cameras
        .iter()
        .map(|(camera, _)| SensorCalibration {
            sensor: camera.sensor_id.clone(),
            calibration: template.clone(),
            failure_domains: BTreeSet::new(),
        })
        .collect();
    Ok(EventFusionProfile::for_long_corroboration(
        spec,
        [cameras[0].1, cameras[1].1],
    )?)
}

#[test]
fn paired_native_advice_covers_late_entries_and_refuses_wrong_scope_without_mutating_authority()
-> Test {
    let mut f = Fixture::new("late", &scene(170, true, false, false)?, "mjpeg")?;
    f.plan.zones[0].x = 28.0;
    let scalar = ScalarExecCx::new();
    let package = f.trained_package(&scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig {
            max_inferences: 1,
            frames_per_track: 2,
            ..CascadeConfig::default()
        },
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    let native = f.annotate(&detector, false)?;
    assert_eq!(native.candidates().len(), 1);
    assert!(
        native
            .samples()
            .iter()
            .all(|sample| sample.entry_position > 128)
    );
    let profile = profile_for(&native)?;
    let advice =
        EventFusionReport::long_corroborate(&native, &package, &profile, &f.deployment, &f.cx)?;
    assert_eq!(advice.candidates().len(), 1);
    let result = &advice.candidates()[0];
    assert_eq!(result.candidate, native.candidates()[0].identity());
    assert_eq!(
        result.native_proposal,
        native.candidates()[0].proposal_digest()
    );
    assert_eq!(
        result.native_provenance,
        native.candidates()[0].provenance_root()
    );
    assert_eq!(result.scores.len(), 4);
    let west = result
        .scores
        .iter()
        .filter(|link| link.sensor.ends_with("west"))
        .collect::<Vec<_>>();
    assert_eq!(west.len(), 2);
    assert!(
        west.iter()
            .all(|link| link.source_record.is_some() && link.score_bits.is_none())
    );
    assert_eq!(native.inference_selections_admitted(), 1);
    assert_eq!(f.snapshot(), before);
    let json = advice.to_json()?;
    assert!(json.contains("fss.event_class_fusion_report.v3"));
    assert!(json.contains("\"class_absence_certified\":false"));
    assert!(json.contains("\"effect_authority\":false"));
    assert_eq!(
        EventFusionReport::long_corroborate(&native, &package, &profile, &f.deployment, &f.cx)?
            .digest(),
        advice.digest()
    );
    for index in 0..5 {
        let mut request = profile.spec().clone();
        let mut roots = profile.long_corroboration_analysis_roots().ok_or("roots")?;
        match index {
            0 => request.plan_digest = native.plan_digest(),
            1 => request.cascade_digest = ContentDigest::sha256(b"wrong recipe"),
            2 => roots.swap(0, 1),
            3 => roots[1] = ContentDigest::sha256(b"other full source"),
            _ => request.calibrations[1].sensor = "sensor:foreign".into(),
        }
        let wrong = EventFusionProfile::for_long_corroboration(request, roots)?;
        assert!(matches!(
            EventFusionReport::long_corroborate(&native, &package, &wrong, &f.deployment, &f.cx),
            Err(EventFusionError::Scope)
        ));
    }
    let single = EventFusionProfile::for_long_watch(
        profile.spec().clone(),
        profile.long_corroboration_analysis_roots().ok_or("roots")?[0],
    )?;
    assert!(matches!(
        EventFusionReport::long_corroborate(&native, &package, &single, &f.deployment, &f.cx),
        Err(EventFusionError::Scope)
    ));
    assert_eq!(f.snapshot(), before);
    f.mask("west", [40, 0, 4, 4])?;
    let changed = f.snapshot();
    assert!(matches!(
        EventFusionReport::long_corroborate(&native, &package, &profile, &f.deployment, &f.cx),
        Err(EventFusionError::StaleBasis)
    ));
    assert_eq!(f.snapshot(), changed);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn source_revalidation_includes_camera_two_even_with_no_candidates() -> Test {
    let mut f = Fixture::new("empty-custody", &scene(12, false, false, false)?, "mjpeg")?;
    f.plan.zones[0].x = 1000.0;
    let native = f.analyze(false)?;
    assert!(native.candidates().is_empty());
    let before = f.snapshot();
    native.revalidate_derived_sources(&f.deployment, &f.cx)?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.plan.cameras[1].import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let object = format!(
        "object:capsule:{}",
        retained.manifest().segment_spans[1].capsule_id
    );
    let digest = f
        .deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.object_id.as_str() == object)
        .ok_or("west capsule")?
        .payload_digest;
    let path = f.deployment.publisher().spool().object_path(digest);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("nonempty capsule")? ^= 1;
    fs::write(path, bytes)?;
    assert!(
        native
            .revalidate_derived_sources(&f.deployment, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn zero_candidate_advice_is_still_source_checked_and_cancelled_not_successfully_empty() -> Test {
    let mut f = Fixture::new("empty-advice", &scene(12, false, false, false)?, "mjpeg")?;
    f.plan.zones[0].x = 1000.0;
    let scalar = ScalarExecCx::new();
    let package = f.trained_package(&scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let native = f.annotate(&detector, false)?;
    let profile = profile_for(&native)?;
    let before = f.snapshot();
    let advice =
        EventFusionReport::long_corroborate(&native, &package, &profile, &f.deployment, &f.cx)?;
    assert!(advice.candidates().is_empty());
    assert_eq!(native.inference_selections_admitted(), 0);
    f.cx.set_cancel_at_checkpoint("long_corroboration:derived_sources_checked");
    assert!(matches!(
        EventFusionReport::long_corroborate(&native, &package, &profile, &f.deployment, &f.cx),
        Err(EventFusionError::Cancelled)
    ));
    assert_eq!(f.snapshot(), before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn requested_whole_scan_health_findings_fence_derived_advice() -> Test {
    let f = Fixture::new("health-fence", &scene(40, false, false, false)?, "mjpeg")?;
    let before = f.snapshot();
    let native = LongCorroborationReport::analyze_screened(
        &f.deployment,
        &f.plan,
        CorroborationOptions::default(),
        &LongCorroborationLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?;
    assert!(native.publication_blocked());
    assert!(
        native
            .revalidate_derived_sources(&f.deployment, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}
