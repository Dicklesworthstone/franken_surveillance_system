#![forbid(unsafe_code)]
//! Actual retained numeric FMPK/JPEG observations joined to independently retained native health.

use super::*;
use fss_reference::ingest::historical_health::HistoricalHealthRecord;
use fss_reference::ingest::historical_health::exposure::{
    HealthExposureLimits, HealthExposureState,
};
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;

fn clear_media() -> Vec<u8> {
    [128, 144, 160, 176, 192, 208, 224]
        .into_iter()
        .flat_map(jpeg)
        .collect()
}
fn whole_image() -> PackageZoneConfig {
    PackageZoneConfig {
        zones: vec![PackageZone {
            id: "image".into(),
            x: 0,
            y: 0,
            width: 32,
            height: 16,
            margin: 0,
        }],
        ..config()
    }
}
fn screened(f: &Fixture, config: PackageZoneConfig) -> Test<PackageZoneReport> {
    Ok(PackageZoneReport::analyze_screened(
        &f.deployment,
        f.detection,
        "numeric-a",
        tracking(),
        config,
        HealthExposureLimits::default(),
        &f.cx,
    )?)
}
fn diagnostic(
    f: &mut Fixture,
    first: usize,
    count: usize,
    refused: bool,
) -> Test<HistoricalHealthRecord> {
    let plan = WatchPlan {
        import_identity: f.import,
        interpretation: ComponentInterpretation::YCbCr,
        first_segment: first,
        segment_count: count,
        zones: vec![WatchZone {
            zone_id: "screen".into(),
            x: 0,
            y: 0,
            width: 32,
            height: 16,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    let mut limits = LongDwellLimits::default();
    if refused {
        limits.decode.jpeg_limits.maximum_dimension = 16;
    }
    let report = LongDwellReport::analyze_screened(
        &f.deployment,
        &plan,
        DwellPolicy {
            minimum_duration_ns: 180_000_000,
            maximum_sample_gap_ns: 110_000_000,
            minimum_observations: 3,
        },
        WatchOptions {
            tolerate_decode_refusals: refused,
        },
        &limits,
        &f.cx,
    )?;
    let proposal = report
        .health_diagnostic()
        .ok_or("native diagnostic missing")?;
    let record = proposal.record().clone();
    proposal.retain(&mut f.deployment, proposal.approval_digest(), &f.cx)?;
    Ok(record)
}

#[test]
fn missing_screen_withholds_support_without_erasing_assignments_or_changing_legacy_bytes() -> Test {
    let mut f = fixture("health-unknown", &clear_media(), &package()?, true)?;
    let legacy = analyze(&f)?;
    let legacy_bytes = legacy.encoded().to_vec();
    let head = f.deployment.current_anchor().clone();
    let mut report = screened(&f, config())?;
    assert!(report.requires_health_screening());
    assert_eq!(report.cells(), legacy.cells());
    assert_eq!(report.frames(), legacy.frames());
    assert!(report.events().is_empty());
    assert_ne!(report.digest(), legacy.digest());
    assert_eq!(f.deployment.current_anchor(), &head);
    for (frame, exposure) in report
        .health_exposures()
        .ok_or("missing exposure")?
        .iter()
        .enumerate()
    {
        assert_eq!(exposure.state(), HealthExposureState::NoMatchingDiagnostic);
        assert!(exposure.findings().is_empty());
        assert_eq!(report.health_support_allowed(frame), Some(false));
    }
    let approval = report.approval_digest();
    report.retain(&mut f.deployment, approval, &f.cx)?;
    let cold = PackageZoneReport::open(&f.deployment, report.digest(), &f.cx)?;
    assert_eq!(cold.encoded(), report.encoded());
    assert_eq!(cold.retention_anchor(), report.retention_anchor());
    assert_eq!(analyze(&f)?.encoded(), legacy_bytes);
    assert!(
        cold.to_json(PackageZoneOperation::ReadVerified)?
            .contains("\"source_health_assessed\":true")
    );
    assert!(
        legacy
            .to_json(PackageZoneOperation::Analyzed)?
            .contains("\"source_health_assessed\":false")
    );
    Ok(())
}

#[test]
fn complete_screen_preserves_native_events_and_single_catalog_work_across_zone_product() -> Test {
    let mut f = fixture("health-clear", &clear_media(), &package()?, true)?;
    let legacy = analyze(&f)?;
    let health_record = diagnostic(&mut f, 0, 7, false)?;
    assert_eq!(health_record.status(), "no_findings");
    let mut report = screened(&f, config())?;
    assert_eq!(report.cells(), legacy.cells());
    assert_eq!(report.events(), legacy.events());
    assert!(
        report
            .events()
            .iter()
            .any(|event| event.kind == PackageZoneEventKind::SampledDwell)
    );
    for exposure in report.health_exposures().ok_or("missing exposure")? {
        assert_eq!(
            exposure.state(),
            HealthExposureState::ScreenedWithoutFindings
        );
        assert_eq!(exposure.pins().len(), 1);
        assert_eq!(exposure.pins()[0].record_digest, health_record.digest());
    }
    let usage = report.health_usage().ok_or("missing usage")?;
    assert_eq!(usage.records_loaded, 1);
    assert_eq!(usage.assessment_work, 7);
    let mut two_zones = config();
    let mut second = two_zones.zones[0].clone();
    second.id = "yard-second".into();
    two_zones.zones.push(second);
    let doubled = screened(&f, two_zones)?;
    assert_eq!(doubled.cells().len(), report.cells().len() * 2);
    assert_eq!(doubled.health_usage(), report.health_usage());
    report.admit_retention_json()?;
    let approval = report.approval_digest();
    let io_before_retain = f.deployment.publisher().spool().read_budget_usage();
    assert!(!report.retain(&mut f.deployment, approval, &f.cx)?);
    assert_eq!(
        report
            .health_usage()
            .ok_or("missing usage")?
            .assessment_work,
        21
    );
    let io_after_retain = f.deployment.publisher().spool().read_budget_usage();
    assert!(io_after_retain.used_bytes > 0 && io_after_retain.used_read_attempts > 0);
    let json = report.to_json(PackageZoneOperation::Retained)?;
    assert!(json.contains(&format!(
        "\"retention_indexed_read_bytes_reserved\":{}",
        io_after_retain.used_bytes - io_before_retain.used_bytes
    )));
    assert!(json.contains(&format!(
        "\"retention_indexed_read_attempts\":{}",
        io_after_retain.used_read_attempts - io_before_retain.used_read_attempts
    )));
    let head = f.deployment.current_anchor().clone();
    assert!(report.retain(&mut f.deployment, approval, &f.cx)?);
    assert_eq!(
        report
            .health_usage()
            .ok_or("missing usage")?
            .assessment_work,
        28
    );
    assert!(
        f.deployment
            .publisher()
            .spool()
            .read_budget_usage()
            .used_bytes
            > io_after_retain.used_bytes
    );
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
    let cold_cx = context(&root, PRINCIPAL)?;
    let cold_deployment = ReferenceDeployment::open(&root, SITE, &cold_cx)?;
    let cold = PackageZoneReport::open(&cold_deployment, report.digest(), &cold_cx)?;
    assert_eq!(cold.encoded(), report.encoded());
    assert_eq!(cold.retention_anchor(), report.retention_anchor());
    assert_eq!(cold.events(), report.events());
    assert_eq!(
        cold.health_usage().ok_or("missing usage")?.assessment_work,
        7
    );
    assert_eq!(cold_deployment.current_anchor(), &head);
    drop(cold_deployment);
    cold_cx.drain_and_finalize();
    drop(_directory);
    Ok(())
}

#[test]
fn unscreened_gap_and_incomplete_native_scan_interrupt_dwell_but_never_imply_departure() -> Test {
    let mut f = fixture("health-gap", &clear_media(), &package()?, true)?;
    assert_eq!(diagnostic(&mut f, 0, 3, false)?.status(), "no_findings");
    assert_eq!(diagnostic(&mut f, 4, 3, false)?.status(), "no_findings");
    let report = screened(&f, whole_image())?;
    assert_eq!(report.health_support_allowed(3), Some(false));
    assert_eq!(report.cells()[3].relation, PackageZoneRelation::Inside);
    assert!(report.events().iter().any(|event| event.kind
        == PackageZoneEventKind::ObservationInterrupted
        && event.at_frame == 3));
    assert!(
        !report
            .events()
            .iter()
            .any(|event| event.kind == PackageZoneEventKind::LeftBetweenObservations)
    );
    let dwells = report
        .events()
        .iter()
        .filter(|event| event.kind == PackageZoneEventKind::SampledDwell)
        .collect::<Vec<_>>();
    assert_eq!(dwells.len(), 1);
    assert_eq!(dwells[0].from_frame, Some(4));
    assert_eq!(dwells[0].through_frame, 6);
    assert_eq!(diagnostic(&mut f, 0, 7, true)?.status(), "incomplete");
    let incomplete = screened(&f, whole_image())?;
    assert!(incomplete.events().is_empty());
    assert!(
        incomplete
            .health_exposures()
            .ok_or("missing exposure")?
            .iter()
            .all(|exposure| exposure.state() == HealthExposureState::ScreeningIncomplete)
    );
    assert!(
        incomplete
            .cells()
            .iter()
            .all(|cell| cell.relation == PackageZoneRelation::Inside)
    );
    Ok(())
}

#[test]
fn later_native_freeze_finding_invalidates_retained_support_without_rewriting_legacy_or_source()
-> Test {
    let media = (0..10).flat_map(|_| jpeg(208)).collect::<Vec<_>>();
    let mut f = fixture("health-late-freeze", &media, &package()?, true)?;
    let legacy = PackageZoneReport::analyze(
        &f.deployment,
        f.detection,
        "numeric-a",
        tracking(),
        whole_image(),
        &f.cx,
    )?;
    for (first, count) in [(0, 4), (4, 3), (7, 3)] {
        assert_eq!(
            diagnostic(&mut f, first, count, false)?.status(),
            "no_findings"
        );
    }
    let mut report = screened(&f, whole_image())?;
    assert!(
        report
            .events()
            .iter()
            .any(|event| event.kind == PackageZoneEventKind::SampledDwell)
    );
    let approval = report.approval_digest();
    report.retain(&mut f.deployment, approval, &f.cx)?;
    let bytes = report.encoded().to_vec();
    assert_eq!(
        diagnostic(&mut f, 0, 10, false)?.status(),
        "suspected_degradation"
    );
    let head = f.deployment.current_anchor().clone();
    assert!(PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err());
    assert!(report.retain(&mut f.deployment, approval, &f.cx).is_err());
    assert_eq!(
        f.deployment.publisher().spool().read(report.digest())?,
        bytes
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    let fresh = screened(&f, whole_image())?;
    assert_eq!(fresh.cells(), legacy.cells());
    assert!(fresh.events().is_empty());
    assert!(
        fresh
            .health_exposures()
            .ok_or("missing exposure")?
            .iter()
            .all(|exposure| exposure.state() == HealthExposureState::Findings)
    );
    assert_eq!(
        PackageZoneReport::analyze(
            &f.deployment,
            f.detection,
            "numeric-a",
            tracking(),
            whole_image(),
            &f.cx
        )?
        .encoded(),
        legacy.encoded()
    );
    Ok(())
}

#[test]
fn screened_proof_corruption_limits_privacy_and_source_deletion_refuse_without_repair() -> Test {
    let mut f = fixture("health-custody", &clear_media(), &package()?, true)?;
    let health_record = diagnostic(&mut f, 0, 7, false)?;
    let mut report = screened(&f, config())?;
    let approval = report.approval_digest();
    report.retain(&mut f.deployment, approval, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    let limits = HealthExposureLimits {
        maximum_assessment_work: 6,
        ..HealthExposureLimits::default()
    };
    assert!(
        PackageZoneReport::analyze_screened(
            &f.deployment,
            f.detection,
            "numeric-a",
            tracking(),
            config(),
            limits,
            &f.cx
        )
        .is_err()
    );
    assert!(
        PackageZoneReport::open_with_health_limits(&f.deployment, report.digest(), limits, &f.cx)
            .is_err()
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    for digest in [health_record.digest(), health_record.trace_digest()] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut damaged = bytes.clone();
        *damaged.last_mut().ok_or("empty diagnostic object")? ^= 1;
        fs::write(&path, &damaged)?;
        assert!(PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err());
        assert!(screened(&f, config()).is_err());
        assert_eq!(fs::read(&path)?, damaged);
        assert_eq!(f.deployment.current_anchor(), &head);
        fs::write(path, bytes)?;
    }
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
    assert!(screened(&f, config()).is_err());
    assert!(PackageZoneReport::open(&f.deployment, report.digest(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);

    let mut masked = fixture("health-privacy", &clear_media(), &package()?, true)?;
    diagnostic(&mut masked, 0, 7, false)?;
    let mut report = screened(&masked, config())?;
    let approval = report.approval_digest();
    report.retain(&mut masked.deployment, approval, &masked.cx)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approved = preview_mask(&masked.deployment, &policy)?.approval;
    declare_mask(&mut masked.deployment, &policy, approved, &masked.cx)?;
    let head = masked.deployment.current_anchor().clone();
    assert!(PackageZoneReport::open(&masked.deployment, report.digest(), &masked.cx).is_err());
    assert_eq!(masked.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn retention_revalidations_share_allowance_and_a_fresh_operation_recovers_only_the_same_root()
-> Test {
    let mut f = fixture("health-retention-budget", &clear_media(), &package()?, true)?;
    diagnostic(&mut f, 0, 7, false)?;
    let limits = HealthExposureLimits {
        maximum_assessment_work: 14,
        ..HealthExposureLimits::default()
    };
    let mut report = PackageZoneReport::analyze_screened(
        &f.deployment,
        f.detection,
        "numeric-a",
        tracking(),
        config(),
        limits,
        &f.cx,
    )?;
    let bytes = report.encoded().to_vec();
    let approval = report.approval_digest();
    assert!(report.retain(&mut f.deployment, approval, &f.cx).is_err());
    assert_eq!(
        report
            .health_usage()
            .ok_or("missing usage")?
            .assessment_work,
        14
    );
    assert!(report.retention_anchor().is_none());
    assert!(matches!(
        PackageZoneReport::open(&f.deployment, report.digest(), &f.cx),
        Err(PackageZoneError::Unavailable)
    ));
    let head = f.deployment.current_anchor().clone();
    let spent = f.deployment.publisher().spool().read_budget_usage();
    assert!(spent.used_bytes > 0 && spent.used_read_attempts > 0);
    assert!(report.retain(&mut f.deployment, approval, &f.cx).is_err());
    assert_eq!(
        report
            .health_usage()
            .ok_or("missing usage")?
            .assessment_work,
        14
    );
    assert_eq!(f.deployment.current_anchor(), &head);
    let mut fresh = screened(&f, config())?;
    assert_eq!(fresh.encoded(), bytes);
    assert_eq!(fresh.approval_digest(), approval);
    assert!(!fresh.retain(&mut f.deployment, approval, &f.cx)?);
    let cold = PackageZoneReport::open(&f.deployment, fresh.digest(), &f.cx)?;
    assert_eq!(cold.encoded(), bytes);
    assert_eq!(cold.retention_anchor(), fresh.retention_anchor());
    Ok(())
}
