#![forbid(unsafe_code)]
//! Native retained JPEG/model execution -> complete sampled occupancy and current withdrawal.

use super::*;
use fss_reference::ingest::historical_health::exposure::HealthExposureLimits;
use fss_reference::ingest::package_zones::occupancy::{
    OccupancyHealth, OccupancyState, PackageOccupancyReport, STAGE_OCCUPANCY_REVALIDATE,
};

#[test]
fn retained_native_assignments_project_complete_counts_and_cold_read_without_new_custody() -> Test {
    let mut f = fixture("occupancy-cold", &footage(), &package()?, true)?;
    let mut zones = analyze(&f)?;
    assert!(PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx).is_err());
    zones.retain(&mut f.deployment, zones.approval_digest(), &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    let occupancy = PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx)?;
    assert_eq!(occupancy.source_report(), zones.digest());
    assert_eq!(
        occupancy.samples().len(),
        zones.frames().len() * zones.config().zones.len()
    );
    for row in occupancy.samples() {
        let expected = zones
            .cells()
            .iter()
            .filter(|cell| {
                cell.frame == row.frame
                    && cell.zone == row.zone
                    && cell.sample_confirmed
                    && cell.relation == PackageZoneRelation::Inside
            })
            .count();
        assert_eq!(row.observed_count, Some(expected));
        assert_eq!(row.supporting_tracks.len(), expected);
        assert_eq!(row.health, OccupancyHealth::Unassessed);
    }
    assert_eq!(occupancy.samples()[0].excluded.tentative, 1);
    assert_eq!(occupancy.samples()[10].excluded.unobserved, 1);
    assert_eq!(
        occupancy.samples()[10].state,
        OccupancyState::NoPositiveObservation
    );
    assert!(occupancy.to_json().contains("\"coverage_witness\":null"));
    assert!(occupancy.to_json().contains("\"absence_certified\":false"));
    assert_eq!(f.deployment.current_anchor(), &head);
    let expected = occupancy.to_json().to_owned();
    let digest = zones.digest();
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
    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(
        PackageOccupancyReport::open(&deployment, digest, &cx)?.to_json(),
        expected
    );
    assert_eq!(deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn screened_unknown_source_keeps_complete_rows_and_withholds_counts_including_empty_tracks() -> Test
{
    let mut f = fixture("occupancy-health", &footage(), &package()?, true)?;
    let mut zones = PackageZoneReport::analyze_screened(
        &f.deployment,
        f.detection,
        "numeric-a",
        tracking(),
        config(),
        HealthExposureLimits::default(),
        &f.cx,
    )?;
    zones.retain(&mut f.deployment, zones.approval_digest(), &f.cx)?;
    let occupancy = PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx)?;
    assert_eq!(occupancy.samples().len(), 14);
    assert!(
        occupancy
            .samples()
            .iter()
            .all(|r| r.observed_count.is_none()
                && r.state == OccupancyState::HealthExcluded
                && r.supporting_tracks.is_empty())
    );
    assert!(occupancy.samples().iter().any(|r| r.excluded.health != 0));

    let media = [0, 0, 0].into_iter().flat_map(jpeg).collect::<Vec<_>>();
    let mut empty = fixture("occupancy-empty", &media, &package()?, true)?;
    let mut zones = analyze(&empty)?;
    assert!(zones.analysis().tracks().is_empty());
    zones.retain(&mut empty.deployment, zones.approval_digest(), &empty.cx)?;
    let occupancy = PackageOccupancyReport::open(&empty.deployment, zones.digest(), &empty.cx)?;
    assert_eq!(occupancy.samples().len(), 3);
    assert!(
        occupancy.samples().iter().all(
            |r| r.observed_count == Some(0) && r.state == OccupancyState::NoPositiveObservation
        )
    );
    Ok(())
}

#[test]
fn cancellation_at_final_revalidation_and_changed_source_proof_return_no_projection() -> Test {
    let mut f = fixture("occupancy-refusal", &footage(), &package()?, true)?;
    let mut zones = analyze(&f)?;
    zones.retain(&mut f.deployment, zones.approval_digest(), &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    let cancelled = context(&f.root, PRINCIPAL)?;
    cancelled.set_cancel_at_checkpoint(STAGE_OCCUPANCY_REVALIDATE);
    assert!(matches!(
        PackageOccupancyReport::open(&f.deployment, zones.digest(), &cancelled),
        Err(PackageZoneError::Cancelled)
    ));
    cancelled.drain_and_finalize();
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(zones.frames()[0].capsule_digest);
    let bytes = fs::read(&path)?;
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().ok_or("empty capsule")? ^= 1;
    fs::write(&path, &corrupt)?;
    assert!(PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx).is_err());
    assert_eq!(fs::read(&path)?, corrupt);
    assert_eq!(f.deployment.current_anchor(), &head);
    fs::write(&path, &bytes)?;
    assert!(PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx).is_ok());
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    assert!(PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn deletion_of_original_source_withdraws_occupancy_without_repair() -> Test {
    let mut f = fixture("occupancy-deletion", &footage(), &package()?, true)?;
    let mut zones = analyze(&f)?;
    zones.retain(&mut f.deployment, zones.approval_digest(), &f.cx)?;
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
    assert!(PackageOccupancyReport::open(&f.deployment, zones.digest(), &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}
