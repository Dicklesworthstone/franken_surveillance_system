#![forbid(unsafe_code)]
//! QSR projection through real retained JPEG, model, tracker, health, privacy and deletion owners.

use super::*;
use fss_reference::ingest::qsr_observations::{
    QsrConfig, QsrError, QsrObservationReport, QsrPresence, QsrZoneBinding, QsrZoneRole,
};

fn qsr_config() -> QsrConfig {
    QsrConfig {
        zone_roles: vec![QsrZoneBinding {
            zone: "image".into(),
            role: QsrZoneRole::Queue,
        }],
        lane_stages: Vec::new(),
    }
}
fn retain_screened(f: &mut Fixture) -> Test<ContentDigest> {
    let mut zones = screened(f, whole_image())?;
    let approval = zones.approval_digest();
    zones.retain(&mut f.deployment, approval, &f.cx)?;
    Ok(zones.digest())
}

#[test]
fn qsr_native_counts_and_dwell_cold_reopen_without_new_authority_or_inference() -> Test {
    let mut f = fixture("qsr-native", &clear_media(), &package()?, true)?;
    diagnostic(&mut f, 0, 7, false)?;
    let zones = retain_screened(&mut f)?;
    let head = f.deployment.current_anchor().clone();
    let report = QsrObservationReport::open(&f.deployment, zones, qsr_config(), &f.cx)?;
    assert_eq!(report.source().digest(), zones);
    assert_eq!(report.observations().zones[0].sampled_frames, 7);
    assert_eq!(report.observations().zones[0].supported_frames, 7);
    assert_eq!(report.observations().zones[0].unknown_frames, 0);
    assert_eq!(
        report.observations().samples[0].presence,
        QsrPresence::NotObserved
    );
    assert_eq!(report.observations().samples[0].tentative_tracks, 1);
    assert!(
        report.observations().samples[1..]
            .iter()
            .all(|sample| sample.confirmed_tracks.len() == 1)
    );
    assert_eq!(report.observations().dwell.len(), 1);
    let dwell = &report.observations().dwell[0];
    assert_eq!(
        (dwell.from_frame, dwell.through_frame, dwell.observations),
        (Some(1), 6, 6)
    );
    assert_eq!(
        (dwell.minimum_duration_ns, dwell.maximum_duration_ns),
        (Some(498_000_000), Some(502_000_000))
    );
    let bytes = report.encoded().to_vec();
    let json = report.to_json()?;
    assert!(json.contains("\"schema\":\"fss.qsr_observation_report.v1\""));
    assert!(json.contains("\"capture_time_label\":\"operator_assumption\""));
    assert!(json.contains("\"absence_certified\":false"));
    assert!(json.contains("\"service_or_wait_duration_established\":false"));
    assert_eq!(f.deployment.current_anchor(), &head);
    let mut alternative = qsr_config();
    alternative.zone_roles[0].role = QsrZoneRole::Register;
    let annotated = QsrObservationReport::open(&f.deployment, zones, alternative, &f.cx)?;
    assert_ne!(annotated.digest(), report.digest());
    assert_eq!(annotated.observations(), report.observations());
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
    let cold = QsrObservationReport::open(&cold_deployment, zones, qsr_config(), &cold_cx)?;
    assert_eq!(cold.encoded(), bytes);
    assert_eq!(cold.to_json()?, json);
    assert_eq!(cold_deployment.current_anchor(), &head);
    drop(cold_deployment);
    cold_cx.drain_and_finalize();
    drop(_directory);
    Ok(())
}

#[test]
fn qsr_unknown_screen_is_null_count_and_legacy_or_unknown_annotation_refuses() -> Test {
    let mut f = fixture("qsr-unknown", &clear_media(), &package()?, true)?;
    let zones = retain_screened(&mut f)?;
    let head = f.deployment.current_anchor().clone();
    let report = QsrObservationReport::open(&f.deployment, zones, qsr_config(), &f.cx)?;
    assert_eq!(report.observations().zones[0].maximum_observed_count, None);
    assert_eq!(report.observations().zones[0].unknown_frames, 7);
    assert!(
        report
            .observations()
            .samples
            .iter()
            .all(|sample| sample.presence == QsrPresence::Unknown
                && sample.confirmed_tracks.is_empty())
    );
    assert!(report.observations().dwell.is_empty());
    assert!(report.to_json()?.contains("\"confirmed_track_count\":null"));
    let mut invalid = qsr_config();
    invalid.zone_roles[0].zone = "not-in-source".into();
    assert!(matches!(
        QsrObservationReport::open(&f.deployment, zones, invalid, &f.cx),
        Err(QsrError::Invalid(_))
    ));
    assert_eq!(f.deployment.current_anchor(), &head);
    let mut legacy = analyze(&f)?;
    legacy.retain(&mut f.deployment, legacy.approval_digest(), &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    assert!(matches!(
        QsrObservationReport::open(&f.deployment, legacy.digest(), QsrConfig::default(), &f.cx),
        Err(QsrError::Invalid(_))
    ));
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn qsr_rechecks_diagnostic_custody_current_privacy_and_source_deletion_without_repair() -> Test {
    let mut f = fixture("qsr-source-checks", &clear_media(), &package()?, true)?;
    let diagnostic = diagnostic(&mut f, 0, 7, false)?;
    let zones = retain_screened(&mut f)?;
    let head = f.deployment.current_anchor().clone();
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(diagnostic.trace_digest());
    let original = fs::read(&path)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("diagnostic bytes")? ^= 1;
    fs::write(&path, &corrupt)?;
    assert!(QsrObservationReport::open(&f.deployment, zones, qsr_config(), &f.cx).is_err());
    assert_eq!(fs::read(&path)?, corrupt);
    assert_eq!(f.deployment.current_anchor(), &head);
    fs::write(path, original)?;
    let plan = plan_deletion(&f.deployment, f.import, &f.cx)?;
    assert!(plan.blockers.is_empty());
    let digest = plan.digest()?;
    commit_deletion(
        &mut f.deployment,
        digest,
        approval_digest(digest, SITE, PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    let head = f.deployment.current_anchor().clone();
    assert!(QsrObservationReport::open(&f.deployment, zones, qsr_config(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);

    let mut masked = fixture("qsr-current-privacy", &clear_media(), &package()?, true)?;
    super::diagnostic(&mut masked, 0, 7, false)?;
    let zones = retain_screened(&mut masked)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approval = preview_mask(&masked.deployment, &policy)?.approval;
    declare_mask(&mut masked.deployment, &policy, approval, &masked.cx)?;
    let head = masked.deployment.current_anchor().clone();
    assert!(
        QsrObservationReport::open(&masked.deployment, zones, qsr_config(), &masked.cx).is_err()
    );
    assert_eq!(masked.deployment.current_anchor(), &head);
    Ok(())
}
