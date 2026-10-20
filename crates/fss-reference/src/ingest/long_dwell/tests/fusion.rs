#![forbid(unsafe_code)]
//! Native custody/authority admission for downstream sampled-dwell class advice.

use super::*;

#[test]
fn immutable_episode_accessors_preserve_exact_native_roots_and_rule_identity() -> Test {
    let f = Fixture::new("derived-roots", &scene(true, None, None, false)?, true)?;
    let before = f.snapshot();
    let report = f.analyze(rule())?;
    let candidate = report.candidates().first().ok_or("native episode")?;
    assert_eq!(
        candidate.identity(),
        ContentDigest::sha256(&candidate.record)
    );
    assert_eq!(candidate.provenance_root(), candidate.manifest.root());
    assert_eq!(report.analysis_root(), report.replay_analysis_root());
    assert_eq!(report.sensor_id().as_str(), "sensor:long-dwell");
    report.revalidate_derived_source(&f.deployment, &f.cx)?;
    let different = f.analyze(DwellPolicy {
        minimum_duration_ns: rule().minimum_duration_ns + PERIOD,
        ..rule()
    })?;
    assert_ne!(different.analysis_digest(), report.analysis_digest());
    assert_ne!(different.analysis_root(), report.analysis_root());
    assert_ne!(different.candidates()[0].identity(), candidate.identity());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn empty_dwell_scan_still_revalidates_original_owner_privacy_and_anchor() -> Test {
    let mut f = Fixture::new(
        "derived-empty-authority",
        &scene(false, None, None, false)?,
        true,
    )?;
    let report = f.analyze(rule())?;
    assert!(report.candidates().is_empty());
    report.revalidate_derived_source(&f.deployment, &f.cx)?;
    let other = context(f.deployment.root(), "principal:other")?;
    assert!(matches!(
        report.revalidate_derived_source(&f.deployment, &other),
        Err(WatchError::Conflict)
    ));
    other.drain_and_finalize();
    let mask = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-dwell")?,
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    let changed = f.snapshot();
    assert!(matches!(
        report.revalidate_derived_source(&f.deployment, &f.cx),
        Err(WatchError::Conflict)
    ));
    assert_eq!(f.snapshot(), changed);
    Ok(())
}

#[test]
fn damaged_quiet_source_capsule_cannot_support_fresh_empty_dwell_advice() -> Test {
    let f = Fixture::new(
        "derived-empty-custody",
        &scene(false, None, None, false)?,
        true,
    )?;
    let report = f.analyze(rule())?;
    assert!(report.candidates().is_empty());
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.plan.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let capsule = format!(
        "object:capsule:{}",
        retained.manifest().segment_spans[1].capsule_id
    );
    let digest = f
        .deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.object_id.as_str() == capsule)
        .ok_or("quiet capsule")?
        .payload_digest;
    let path = f.deployment.publisher().spool().object_path(digest);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("nonempty capsule")? ^= 1;
    fs::write(path, bytes)?;
    let before = f.snapshot();
    assert!(
        report
            .revalidate_derived_source(&f.deployment, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn requested_health_gate_and_cancelled_delivery_refuse_derived_dwell_use() -> Test {
    let f = Fixture::new("derived-health", &scene(true, None, None, false)?, true)?;
    let screened = LongDwellReport::analyze_screened(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &f.cx,
    )?;
    assert!(screened.publication_blocked());
    let before = f.snapshot();
    assert!(matches!(
        screened.revalidate_derived_source(&f.deployment, &f.cx),
        Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED))
    ));
    let plain = f.analyze(rule())?;
    f.cx.set_cancel_at_checkpoint("long_dwell:derived_source_checked");
    assert!(
        plain
            .revalidate_derived_source(&f.deployment, &f.cx)
            .is_err()
    );
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}
