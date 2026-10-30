#![forbid(unsafe_code)]
//! Real retained JPEG/native-package execution, source withdrawals and cold zone reconstruction.
//! The tiny model is numeric test data; the separate YOLOX case checks real clipped proposals.
#[path = "package_zones_contract/health.rs"]
mod health;
mod package_zone_support;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{PackageTrackingConfig, retain_package_detection};
use fss_reference::ingest::package_zones::*;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use package_zone_support::{Test, footage, jpeg, package};
use std::fs;
use std::path::{Path, PathBuf};

const SITE: &str = "site:package-zones-native";
const PRINCIPAL: &str = "principal:package-zones-native";
const SENSOR: &str = "sensor:package-zones-native";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-zones-{label}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-zones-native".into(),
        operation_id: OperationId::parse("operation:package-zones-native")?,
        principal: principal.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
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
struct Fixture {
    _directory: Directory,
    root: PathBuf,
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    import: ContentDigest,
    detection: ContentDigest,
}
fn fixture(label: &str, media: &[u8], bytes: &[u8], hint: bool) -> Test<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let source = directory.0.join("source.mjpeg");
    fs::write(&source, media)?;
    let cx = context(&root, PRINCIPAL)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut request = FileIngestRequest::new(
        &source,
        SensorId::parse(SENSOR)?,
        StreamId::parse("stream:package-zones")?,
    )
    .with_receive_time(TimestampNs(10_000_000_000));
    if hint {
        request = request.with_capture_hint(CaptureHint::new(
            TimestampNs(1_000_000_000),
            1_000_000,
            10.0,
        )?);
    }
    let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
    fs::remove_file(source)?;
    let retained = RetainedFileImport::open(
        &deployment,
        imported.import_identity,
        RetainedReadLimits::default(),
        &cx,
    )?;
    let scalar = ScalarExecCx::new();
    let model =
        RgbDetectorPackage::load(bytes, ContentDigest::sha256(bytes), 1 << 40, &cx, &scalar)?;
    let detection = run_package_detection(
        &deployment,
        &model,
        &PackageDetectRequest {
            import_identity: imported.import_identity,
            first_segment: 0,
            segment_count: retained.manifest().segment_spans.len(),
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(),
        &cx,
        &scalar,
    )?;
    retain_package_detection(&mut deployment, &model, &detection, &cx)?;
    Ok(Fixture {
        _directory: directory,
        root,
        deployment,
        cx,
        import: imported.import_identity,
        detection: detection.digest,
    })
}
fn tracking() -> PackageTrackingConfig {
    PackageTrackingConfig {
        confirmation_hits: 2,
        maximum_missed_frames: 1,
        minimum_iou_ppm: 0,
    }
}
fn config() -> PackageZoneConfig {
    PackageZoneConfig {
        maximum_sample_gap_ns: 110_000_000,
        dwell: Some(PackageZoneDwell {
            minimum_duration_ns: 180_000_000,
            minimum_observations: 3,
        }),
        zones: vec![PackageZone {
            id: "yard".into(),
            x: 14,
            y: 0,
            width: 14,
            height: 16,
            margin: 0,
        }],
    }
}
fn analyze(f: &Fixture) -> Test<PackageZoneReport> {
    Ok(PackageZoneReport::analyze(
        &f.deployment,
        f.detection,
        "numeric-a",
        tracking(),
        config(),
        &f.cx,
    )?)
}

#[test]
fn native_class_selected_entries_and_dwell_retain_and_rebuild_without_model_or_source_files() -> Test
{
    let mut f = fixture("cold", &footage(), &package()?, true)?;
    let before = f.deployment.current_anchor().clone();
    let mut report = analyze(&f)?;
    assert_eq!(f.deployment.current_anchor(), &before);
    assert_eq!(report.analysis().class_index(), 0);
    assert_eq!(report.frames().len(), 14);
    assert_eq!(report.analysis().tracks().len(), 1);
    assert_eq!(report.cells().len(), 14);
    assert!(!report.cells()[0].sample_confirmed);
    assert!(report.cells()[1].sample_confirmed);
    assert_eq!(report.cells()[10].relation, PackageZoneRelation::Unobserved);
    assert_eq!(report.cells()[10].detection_row, None);
    assert!(
        report.analysis().retained().record().frames[10]
            .detections
            .iter()
            .any(|d| d.class_index == 1)
    );
    let entries: Vec<_> = report
        .events()
        .iter()
        .filter(|e| e.kind == PackageZoneEventKind::EnteredBetweenObservations)
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].from_frame, Some(1));
    let dwells: Vec<_> = report
        .events()
        .iter()
        .filter(|e| e.kind == PackageZoneEventKind::SampledDwell)
        .collect();
    assert_eq!(dwells.len(), 2);
    assert!(dwells[0].through_frame < 10 && dwells[1].from_frame.is_some_and(|n| n > 10));
    assert!(
        !report
            .events()
            .iter()
            .any(|e| e.kind == PackageZoneEventKind::LeftBetweenObservations)
    );
    for cell in report.cells().iter().filter(|c| c.detection_row.is_some()) {
        let frame = &report.analysis().retained().record().frames[cell.frame];
        let row = frame
            .detections
            .iter()
            .find(|d| Some(d.row) == cell.detection_row && d.class_index == 0)
            .ok_or("assigned row")?;
        assert_eq!(cell.bounds, Some(row.bounds));
    }
    report.admit_retention_json()?;
    let approved = report.approval_digest();
    assert!(!report.retain(&mut f.deployment, approved, &f.cx)?);
    let bytes = report.encoded().to_vec();
    let digest = report.digest();
    let anchor = report.retention_anchor().cloned().ok_or("retention")?;
    let head = f.deployment.current_anchor().clone();
    assert!(report.retain(&mut f.deployment, approved, &f.cx)?);
    assert_eq!(f.deployment.current_anchor(), &head);
    let Fixture {
        _directory,
        root,
        deployment,
        cx,
        ..
    } = f;
    drop(deployment);
    cx.drain_and_finalize();
    let cx = context(&root, PRINCIPAL)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut cold = PackageZoneReport::open(&deployment, digest, &cx)?;
    assert_eq!(cold.encoded(), bytes);
    assert_eq!(cold.retention_anchor(), Some(&anchor));
    assert_eq!(cold.events(), report.events());
    assert!(cold.retain(&mut deployment, approved, &cx)?);
    assert_eq!(deployment.current_anchor(), &head);
    let json = cold.to_json(PackageZoneOperation::ReadVerified)?;
    assert!(json.contains("\"source_health_assessed\":false"));
    assert!(json.contains("\"capture_time_label\":\"operator_assumption\""));
    assert!(!_directory.0.join("source.mjpeg").exists());
    Ok(())
}

#[test]
fn cancellation_after_root_has_no_cognition_authority_and_exact_restart_completes_once() -> Test {
    let mut f = fixture("cancel", &footage(), &package()?, true)?;
    let mut report = analyze(&f)?;
    let cancelled = context(&f.root, PRINCIPAL)?;
    cancelled.set_cancel_at_checkpoint(STAGE_PACKAGE_ZONES_COMMIT);
    let approval = report.approval_digest();
    assert!(matches!(
        report.retain(&mut f.deployment, approval, &cancelled),
        Err(PackageZoneError::Cancelled)
    ));
    assert!(matches!(
        PackageZoneReport::open(&f.deployment, report.digest(), &f.cx),
        Err(PackageZoneError::Unavailable)
    ));
    let Fixture {
        _directory,
        root,
        deployment,
        cx,
        ..
    } = f;
    drop(deployment);
    cx.drain_and_finalize();
    cancelled.drain_and_finalize();
    let cx = context(&root, PRINCIPAL)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    assert!(!report.retain(&mut deployment, approval, &cx)?);
    let head = deployment.current_anchor().clone();
    assert!(report.retain(&mut deployment, approval, &cx)?);
    assert_eq!(deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn wrong_class_approval_principal_corrupt_proof_and_current_privacy_refuse_without_repair() -> Test
{
    let mut f = fixture("withdrawals", &footage(), &package()?, true)?;
    let mut report = analyze(&f)?;
    let head = f.deployment.current_anchor().clone();
    assert!(
        PackageZoneReport::analyze(
            &f.deployment,
            f.detection,
            "foreign-label",
            tracking(),
            config(),
            &f.cx
        )
        .is_err()
    );
    assert!(matches!(
        report.retain(&mut f.deployment, ContentDigest::sha256(b"wrong"), &f.cx),
        Err(PackageZoneError::StaleApproval)
    ));
    let other = context(&f.root, "principal:other-zone-reviewer")?;
    let approval = report.approval_digest();
    assert!(report.retain(&mut f.deployment, approval, &other).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);
    report.retain(&mut f.deployment, approval, &f.cx)?;
    let source = RetainedFileImport::open(
        &f.deployment,
        f.import,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    for digest in [
        report.digest(),
        report.provenance_root(),
        report.analysis().digest(),
        report.frames()[0].capsule_digest,
        source.manifest().ordered_chunks[0],
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut damaged = bytes.clone();
        *damaged.last_mut().ok_or("empty object")? ^= 1;
        fs::write(&path, &damaged)?;
        assert!(
            PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err(),
            "{digest}"
        );
        assert!(
            report.retain(&mut f.deployment, approval, &f.cx).is_err(),
            "{digest}"
        );
        assert_eq!(fs::read(&path)?, damaged);
        assert_eq!(f.deployment.current_anchor(), &head);
        fs::write(path, bytes)?;
    }
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approved = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approved, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    assert!(PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err());
    assert!(report.retain(&mut f.deployment, approval, &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn original_source_deletion_withdraws_fresh_and_cold_zone_derivations() -> Test {
    let mut f = fixture("deletion", &footage(), &package()?, true)?;
    let mut report = analyze(&f)?;
    let approval = report.approval_digest();
    report.retain(&mut f.deployment, approval, &f.cx)?;
    let plan = plan_deletion(&f.deployment, f.import, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.deployment,
        digest,
        approval_digest(digest, SITE, PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert!(analyze(&f).is_err());
    assert!(PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err());
    assert!(report.retain(&mut f.deployment, approval, &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn source_gaps_reset_tracks_and_unknown_or_omitted_time_cannot_establish_dwell() -> Test {
    let bytes = package()?;
    let unknown = fixture("unknown", &footage(), &bytes, false)?;
    assert!(matches!(
        PackageZoneReport::analyze(
            &unknown.deployment,
            unknown.detection,
            "numeric-a",
            tracking(),
            config(),
            &unknown.cx
        ),
        Err(PackageZoneError::Invalid(_))
    ));
    let mut spatial = config();
    spatial.dwell = None;
    let report = PackageZoneReport::analyze(
        &unknown.deployment,
        unknown.detection,
        "numeric-a",
        tracking(),
        spatial,
        &unknown.cx,
    )?;
    assert!(report.frames().iter().all(|f| !f.time_reliable));
    assert!(!report.events().iter().any(|e| matches!(
        e.kind,
        PackageZoneEventKind::EnteredBetweenObservations | PackageZoneEventKind::SampledDwell
    )));
    let mut media: Vec<_> = [240, 240, 240].into_iter().flat_map(jpeg).collect();
    media.extend_from_slice(b"SOURCE-GAP-NOT-A-FRAME");
    media.extend([240, 240, 240].into_iter().flat_map(jpeg));
    let gap = fixture("gap", &media, &bytes, true)?;
    let report = analyze(&gap)?;
    assert_eq!(report.analysis().tracks().len(), 2);
    assert!(report.frames()[3].source_boundary);
    assert!(report.frames().iter().all(|f| !f.time_reliable));
    assert!(
        !report
            .events()
            .iter()
            .any(|e| e.kind == PackageZoneEventKind::SampledDwell)
    );
    assert_ne!(
        report.analysis().tracks()[0].identity,
        report.analysis().tracks()[1].identity
    );
    Ok(())
}

#[test]
fn real_yolox_clipped_proposals_never_become_strict_inside_or_dwell() -> Test {
    const JPEG: &[u8] =
        include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
    const MODEL: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
    let f = fixture("yolox-partial", JPEG, MODEL, true)?;
    let mut config = config();
    config.zones[0] = PackageZone {
        id: "whole-image".into(),
        x: 0,
        y: 0,
        width: 64,
        height: 48,
        margin: 0,
    };
    let report = PackageZoneReport::analyze(
        &f.deployment,
        f.detection,
        "tie",
        PackageTrackingConfig {
            confirmation_hits: 1,
            ..tracking()
        },
        config,
        &f.cx,
    )?;
    assert_eq!(report.cells().len(), 3);
    assert!(report.cells().iter().all(|c| matches!(
        c.relation,
        PackageZoneRelation::Partial | PackageZoneRelation::Boundary
    )));
    assert!(report.events().is_empty());
    Ok(())
}
